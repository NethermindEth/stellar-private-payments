//! Caller-supplied circuit fingerprints and optional GitHub-release download.

use std::collections::BTreeMap;

use anyhow::Context;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::Error;

#[derive(Debug, Clone, Deserialize)]
pub struct CircuitMeta {
    pub repository: String,
    pub commit: String,
    pub circom: String,
    pub circomlib: String,
    #[serde(rename = "circom-witness-rs")]
    pub circom_witness_rs: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CircuitHashes {
    pub setup: String,
    pub r1cs: String,
    #[serde(rename = "graph.bin")]
    pub graph: String,
    #[serde(rename = "proving_key.bin")]
    pub proving_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CircuitLockfile {
    pub version: String,
    pub meta: CircuitMeta,
    #[serde(flatten)]
    pub circuits: BTreeMap<String, CircuitHashes>,
}

impl CircuitLockfile {
    pub const ARTIFACT_KINDS: [&'static str; 3] = ["r1cs", "graph.bin", "proving_key.bin"];

    pub fn release_url(&self) -> String {
        format!(
            "https://github.com/{}/releases/download/circuits-v{}/circuits.tar.gz",
            self.meta.repository, self.version
        )
    }

    pub fn artifact_file_name(stem: &str, kind: &str) -> String {
        match kind {
            "r1cs" => format!("{stem}.r1cs"),
            "graph.bin" => format!("{stem}.graph.bin"),
            "proving_key.bin" => format!("{stem}_proving_key.bin"),
            _ => format!("{stem}.{kind}"),
        }
    }

    pub fn verify_artifact(&self, stem: &str, kind: &str, bytes: &[u8]) -> Result<(), Error> {
        let hashes = self.entry(stem)?;
        let want = Self::expected_hash_hex(hashes, kind)?;
        let got = Self::sha256_hex(bytes);
        if got != want {
            return Err(Error::Other(anyhow::anyhow!(
                "hash mismatch {stem}/{kind}: want {want} got {got}"
            )));
        }
        Ok(())
    }

    pub fn artifact_sha256(&self, stem: &str, kind: &str) -> Result<[u8; 32], Error> {
        let hashes = self.entry(stem)?;
        let hex = Self::expected_hash_hex(hashes, kind)?;
        let bytes =
            hex::decode(hex).with_context(|| format!("invalid hash hex for {stem}/{kind}"))?;
        if bytes.len() != 32 {
            return Err(Error::Other(anyhow::anyhow!(
                "expected 32-byte hash for {stem}/{kind}, got {} hex chars",
                hex.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn entry(&self, stem: &str) -> Result<&CircuitHashes, Error> {
        self.circuits.get(stem).ok_or_else(|| {
            Error::Other(anyhow::anyhow!(
                "stem {stem} is not in supplied circuits.json"
            ))
        })
    }

    fn expected_hash_hex<'a>(hashes: &'a CircuitHashes, kind: &str) -> Result<&'a str, Error> {
        match kind {
            "r1cs" => Ok(hashes.r1cs.as_str()),
            "graph.bin" => Ok(hashes.graph.as_str()),
            "proving_key.bin" => Ok(hashes.proving_key.as_str()),
            other => Err(Error::Other(anyhow::anyhow!(
                "unknown artifact kind: {other}"
            ))),
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }
}

pub fn circuit_lock(json: &str) -> Result<CircuitLockfile, Error> {
    let lock: CircuitLockfile =
        serde_json::from_str(json).context("parse supplied circuits.json")?;
    if lock.version.is_empty() || lock.circuits.is_empty() {
        return Err(anyhow::anyhow!("circuit lock must have a version and circuit entries").into());
    }
    for stem in lock.circuits.keys() {
        if stem.is_empty() || !stem.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
            return Err(anyhow::anyhow!("invalid circuit stem: {stem}").into());
        }
        for kind in CircuitLockfile::ARTIFACT_KINDS {
            lock.artifact_sha256(stem, kind)?;
        }
    }
    Ok(lock)
}

#[cfg(not(target_arch = "wasm32"))]
mod store {
    use std::{
        collections::HashSet,
        fs,
        io::Cursor,
        path::{Component, Path, PathBuf},
    };

    use anyhow::Context;
    use flate2::read::GzDecoder;
    use tar::Archive;

    use super::{CircuitLockfile, Error};
    use crate::types::{
        CircuitStem, KEY_OWNERSHIP_CIRCUIT, ProverArtifacts, SELECTIVE_DISCLOSURE_1_CIRCUIT,
        SELECTIVE_DISCLOSURE_2_CIRCUIT, SELECTIVE_DISCLOSURE_3_CIRCUIT,
        SELECTIVE_DISCLOSURE_4_CIRCUIT,
    };

    const DISCLOSURE_STEMS: [&str; 4] = [
        SELECTIVE_DISCLOSURE_1_CIRCUIT,
        SELECTIVE_DISCLOSURE_2_CIRCUIT,
        SELECTIVE_DISCLOSURE_3_CIRCUIT,
        SELECTIVE_DISCLOSURE_4_CIRCUIT,
    ];

    pub struct CircuitStore {
        dir: PathBuf,
        lock: CircuitLockfile,
    }

    impl CircuitStore {
        pub fn open(dir: impl Into<PathBuf>, lock: CircuitLockfile) -> Self {
            Self {
                dir: dir.into(),
                lock,
            }
        }

        pub fn dir(&self) -> &Path {
            &self.dir
        }

        pub async fn ensure(&self) -> Result<(), Error> {
            self.ensure_from(&self.lock.release_url()).await
        }

        async fn ensure_from(&self, url: &str) -> Result<(), Error> {
            let lock = &self.lock;
            fs::create_dir_all(&self.dir).context("create circuits dir")?;
            if self.ready(lock) {
                return Ok(());
            }

            let bytes = reqwest::Client::new()
                .get(url)
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .with_context(|| format!("download {url}"))?
                .bytes()
                .await
                .with_context(|| format!("download {url}"))?;

            unpack_tar_gz(&bytes, &self.dir, &allowed_names(lock))?;
            if self.ready(lock) {
                Ok(())
            } else {
                Err(Error::Other(anyhow::anyhow!(
                    "downloaded circuit artifacts do not match supplied circuits.json"
                )))
            }
        }

        pub fn ensure_blocking(&self) -> Result<(), Error> {
            crate::blocking::runtime::block_on(self.ensure())
        }

        pub fn artifacts(&self, stem: &str) -> Result<ProverArtifacts, Error> {
            let lock = &self.lock;
            let _ = lock.entry(stem)?;
            read_artifacts(&self.dir, stem, lock)
        }

        pub fn transact_artifacts(&self) -> Result<Vec<(CircuitStem, ProverArtifacts)>, Error> {
            CircuitStem::all_transact_stems()
                .into_iter()
                .map(|stem| {
                    self.artifacts(&stem.to_string())
                        .map(|artifacts| (stem, artifacts))
                })
                .collect()
        }

        pub fn disclosure_artifacts(&self) -> Result<Vec<(&'static str, ProverArtifacts)>, Error> {
            DISCLOSURE_STEMS
                .iter()
                .copied()
                .map(|stem| self.artifacts(stem).map(|artifacts| (stem, artifacts)))
                .collect()
        }

        pub fn key_ownership_artifacts(&self) -> Result<ProverArtifacts, Error> {
            self.artifacts(KEY_OWNERSHIP_CIRCUIT)
        }

        fn ready(&self, lock: &CircuitLockfile) -> bool {
            lock.circuits
                .iter()
                .all(|(stem, _)| files_ok(&self.dir, stem, lock))
        }
    }

    fn files_ok(dir: &Path, stem: &str, lock: &CircuitLockfile) -> bool {
        CircuitLockfile::ARTIFACT_KINDS.iter().all(|&kind| {
            let path = dir.join(CircuitLockfile::artifact_file_name(stem, kind));
            let Ok(bytes) = fs::read(&path) else {
                return false;
            };
            lock.verify_artifact(stem, kind, &bytes).is_ok()
        })
    }

    fn read_artifacts(
        dir: &Path,
        stem: &str,
        lock: &CircuitLockfile,
    ) -> Result<ProverArtifacts, Error> {
        let read = |kind: &str| -> Result<Vec<u8>, Error> {
            let path = dir.join(CircuitLockfile::artifact_file_name(stem, kind));
            let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            lock.verify_artifact(stem, kind, &bytes)
                .with_context(|| path.display().to_string())?;
            Ok(bytes)
        };
        Ok(ProverArtifacts {
            proving_key: read("proving_key.bin")?,
            circuit_graph: read("graph.bin")?,
            circuit_r1cs: read("r1cs")?,
        })
    }

    fn allowed_names(lock: &CircuitLockfile) -> HashSet<String> {
        let mut names = HashSet::from(["circuits.json".to_string()]);
        for stem in lock.circuits.keys() {
            for kind in CircuitLockfile::ARTIFACT_KINDS {
                names.insert(CircuitLockfile::artifact_file_name(stem, kind));
            }
        }
        names
    }

    fn tar_basename(path: &Path) -> Option<&str> {
        let mut name = None;
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(s) if name.is_none() => name = s.to_str(),
                _ => return None,
            }
        }
        name
    }

    fn unpack_tar_gz(bytes: &[u8], dest: &Path, allowed: &HashSet<String>) -> Result<(), Error> {
        let mut archive = Archive::new(GzDecoder::new(Cursor::new(bytes)));
        let entries = archive.entries().context("read circuits.tar.gz")?;
        for entry in entries {
            let mut entry = entry.context("circuits.tar.gz")?;
            let name = {
                let path = entry.path().context("circuits.tar.gz")?;
                tar_basename(&path).map(str::to_owned)
            };
            let Some(name) = name else {
                continue;
            };
            if !allowed.contains(&name) {
                continue;
            }
            entry
                .unpack(dest.join(&name))
                .with_context(|| format!("extract {name}"))?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use std::io::Write;

        use flate2::{Compression, write::GzEncoder};
        use sha2::{Digest, Sha256};
        use tar::{Builder, EntryType, Header};
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        use super::*;
        use crate::circuits::circuit_lock;

        const STEM: &str = "test_circuit";
        const R1CS_FILE: &str = "test_circuit.r1cs";
        const GRAPH_FILE: &str = "test_circuit.graph.bin";
        const KEY_FILE: &str = "test_circuit_proving_key.bin";
        const R1CS: &[u8] = b"r1cs payload";
        const GRAPH: &[u8] = b"graph payload";
        const KEY: &[u8] = b"proving key payload";
        const VICTIM: &[u8] = b"victim, must stay as it is";

        /// A temp tree with the extraction target in `dest/` and a sibling
        /// `outside/` that nothing in the archive may touch.
        struct Fixture(PathBuf);

        impl Fixture {
            fn new() -> Self {
                let mut suffix = [0; 8];
                getrandom::getrandom(&mut suffix).expect("random suffix");
                let root =
                    std::env::temp_dir().join(format!("spp-circuits-{}", hex::encode(suffix)));
                fs::create_dir_all(root.join("dest")).expect("create dest");
                fs::create_dir_all(root.join("outside")).expect("create outside");
                Self(root)
            }

            fn dest(&self) -> PathBuf {
                self.0.join("dest")
            }

            fn outside(&self) -> PathBuf {
                self.0.join("outside")
            }

            fn victim(&self) -> PathBuf {
                let victim = self.outside().join("victim");
                fs::write(&victim, VICTIM).expect("write victim");
                victim
            }

            fn dest_listing(&self) -> Vec<String> {
                let mut names: Vec<String> = fs::read_dir(self.dest())
                    .expect("read dest")
                    .map(|e| {
                        e.expect("dest entry")
                            .file_name()
                            .to_string_lossy()
                            .into_owned()
                    })
                    .collect();
                names.sort();
                names
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn lock_json() -> serde_json::Value {
            let hash = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
            serde_json::json!({
                "version": "9.9",
                "meta": {
                    "repository": "owner/repo",
                    "commit": "commit",
                    "circom": "circom",
                    "circomlib": "circomlib",
                    "circom-witness-rs": "witness",
                },
                (STEM): {
                    "setup": "local",
                    "r1cs": hash(R1CS),
                    "graph.bin": hash(GRAPH),
                    "proving_key.bin": hash(KEY),
                },
            })
        }

        fn lock() -> CircuitLockfile {
            circuit_lock(&lock_json().to_string()).expect("test circuit lock")
        }

        fn allowed() -> HashSet<String> {
            allowed_names(&lock())
        }

        fn append(
            builder: &mut Builder<Vec<u8>>,
            name: &str,
            kind: EntryType,
            link: Option<&str>,
            data: &[u8],
        ) {
            let mut header = Header::new_gnu();
            // `Header::set_path` refuses `..` and absolute names, so fill the
            // raw name field the way a hostile archive would.
            header
                .as_old_mut()
                .name
                .get_mut(..name.len())
                .expect("name fits the 100-byte tar field")
                .copy_from_slice(name.as_bytes());
            header.set_entry_type(kind);
            if let Some(link) = link {
                header.set_link_name(link).expect("link name");
            }
            header.set_size(u64::try_from(data.len()).expect("entry size"));
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, data).expect("append entry");
        }

        fn file(builder: &mut Builder<Vec<u8>>, name: &str, data: &[u8]) {
            append(builder, name, EntryType::Regular, None, data);
        }

        fn link(builder: &mut Builder<Vec<u8>>, kind: EntryType, name: &str, target: &Path) {
            let target = target.to_str().expect("utf-8 path");
            append(builder, name, kind, Some(target), b"");
        }

        fn gzip(bytes: &[u8]) -> Vec<u8> {
            let mut gz = GzEncoder::new(Vec::new(), Compression::default());
            gz.write_all(bytes).expect("gzip");
            gz.finish().expect("finish gzip")
        }

        fn tar_gz(build: impl FnOnce(&mut Builder<Vec<u8>>)) -> Vec<u8> {
            let mut builder = Builder::new(Vec::new());
            build(&mut builder);
            gzip(&builder.into_inner().expect("finish tar"))
        }

        /// The archive `circuit-bundle.yml` produces with
        /// `tar -C "$PACK" -czf ... .`.
        fn release_archive() -> Vec<u8> {
            tar_gz(|b| {
                append(b, "./", EntryType::Directory, None, b"");
                file(b, &format!("./{R1CS_FILE}"), R1CS);
                file(b, &format!("./{GRAPH_FILE}"), GRAPH);
                file(b, &format!("./{KEY_FILE}"), KEY);
                file(b, "./circuits.json", b"{}");
            })
        }

        async fn serve_archive(status: u16, body: Vec<u8>, requests: u64) -> MockServer {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/circuits.tar.gz"))
                .respond_with(ResponseTemplate::new(status).set_body_bytes(body))
                .expect(requests)
                .mount(&server)
                .await;
            server
        }

        fn archive_url(server: &MockServer) -> String {
            format!("{}/circuits.tar.gz", server.uri())
        }

        fn write_artifacts(dir: &Path) {
            for (name, bytes) in [(R1CS_FILE, R1CS), (GRAPH_FILE, GRAPH), (KEY_FILE, KEY)] {
                fs::write(dir.join(name), bytes).expect("write artifact");
            }
        }

        #[test]
        fn allowed_names_lists_circuits_json_and_every_artifact_of_every_stem() {
            let mut json = lock_json();
            json["second"] = json[STEM].clone();
            let lock = circuit_lock(&json.to_string()).expect("two-stem lock");
            let expected: HashSet<String> = [
                "circuits.json",
                R1CS_FILE,
                GRAPH_FILE,
                KEY_FILE,
                "second.r1cs",
                "second.graph.bin",
                "second_proving_key.bin",
            ]
            .map(String::from)
            .into();
            assert_eq!(allowed_names(&lock), expected);
        }

        #[test]
        fn tar_basename_accepts_only_a_single_name_with_an_optional_dot_prefix() {
            for (entry, want) in [
                ("x", Some("x")),
                ("./x", Some("x")),
                ("a/b/x", None),
                ("a/x", None),
                ("./a/x", None),
                ("../x", None),
                ("a/../x", None),
                ("/abs/x", None),
                ("/x", None),
                ("./", None),
                ("", None),
            ] {
                assert_eq!(tar_basename(Path::new(entry)), want, "entry {entry:?}");
            }
        }

        #[cfg(unix)]
        #[test]
        fn tar_basename_rejects_a_name_that_is_not_utf8() {
            use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

            assert_eq!(
                tar_basename(Path::new(OsStr::from_bytes(b"\xff\xfe"))),
                None
            );
        }

        #[test]
        fn unpack_extracts_the_allowed_files_of_the_release_archive() {
            let fx = Fixture::new();
            unpack_tar_gz(&release_archive(), &fx.dest(), &allowed()).expect("unpack");
            assert_eq!(
                fx.dest_listing(),
                ["circuits.json", GRAPH_FILE, R1CS_FILE, KEY_FILE]
            );
            assert_eq!(fs::read(fx.dest().join(R1CS_FILE)).expect("r1cs"), R1CS);
            assert_eq!(fs::read(fx.dest().join(GRAPH_FILE)).expect("graph"), GRAPH);
            assert_eq!(fs::read(fx.dest().join(KEY_FILE)).expect("key"), KEY);
        }

        #[test]
        fn unpack_extracts_an_allowed_file_stored_at_the_archive_root() {
            let fx = Fixture::new();
            let archive = tar_gz(|b| file(b, R1CS_FILE, R1CS));
            unpack_tar_gz(&archive, &fx.dest(), &allowed()).expect("unpack");
            assert_eq!(fs::read(fx.dest().join(R1CS_FILE)).expect("r1cs"), R1CS);
        }

        #[test]
        fn unpack_skips_an_allowed_name_stored_below_a_directory() {
            let fx = Fixture::new();
            let archive = tar_gz(|b| file(b, &format!("circuits/{R1CS_FILE}"), R1CS));
            unpack_tar_gz(&archive, &fx.dest(), &allowed()).expect("unpack");
            assert_eq!(fx.dest_listing(), Vec::<String>::new());
        }

        #[test]
        fn unpack_skips_a_name_that_climbs_out_of_the_target_dir() {
            let fx = Fixture::new();
            let archive = tar_gz(|b| {
                file(b, &format!("../{R1CS_FILE}"), R1CS);
                file(b, &format!("a/../{GRAPH_FILE}"), GRAPH);
            });
            unpack_tar_gz(&archive, &fx.dest(), &allowed()).expect("unpack");
            assert_eq!(fx.dest_listing(), Vec::<String>::new());
            assert!(!fx.0.join(R1CS_FILE).exists());
            assert!(!fx.0.join(GRAPH_FILE).exists());
        }

        #[test]
        fn unpack_skips_an_absolute_name() {
            let fx = Fixture::new();
            let absolute = fx.outside().join(R1CS_FILE);
            let archive = tar_gz(|b| file(b, absolute.to_str().expect("utf-8 path"), R1CS));
            unpack_tar_gz(&archive, &fx.dest(), &allowed()).expect("unpack");
            assert!(!absolute.exists());
            assert_eq!(fx.dest_listing(), Vec::<String>::new());
        }

        #[test]
        fn unpack_skips_names_the_lock_does_not_list() {
            let fx = Fixture::new();
            let archive = tar_gz(|b| {
                file(b, "extra.bin", b"extra");
                file(b, "other_circuit.r1cs", b"other");
                file(b, R1CS_FILE, R1CS);
            });
            unpack_tar_gz(&archive, &fx.dest(), &allowed()).expect("unpack");
            assert_eq!(fx.dest_listing(), [R1CS_FILE]);
        }

        #[test]
        fn unpack_keeps_the_last_entry_when_a_name_appears_twice() {
            let fx = Fixture::new();
            let archive = tar_gz(|b| {
                file(b, R1CS_FILE, b"first");
                file(b, R1CS_FILE, R1CS);
            });
            unpack_tar_gz(&archive, &fx.dest(), &allowed()).expect("unpack");
            assert_eq!(fs::read(fx.dest().join(R1CS_FILE)).expect("r1cs"), R1CS);
        }

        #[cfg(unix)]
        #[test]
        fn unpack_does_not_write_through_a_symlink_named_like_an_artifact() {
            let fx = Fixture::new();
            let victim = fx.victim();
            let archive = tar_gz(|b| {
                link(b, EntryType::Symlink, R1CS_FILE, &victim);
                file(b, R1CS_FILE, R1CS);
            });
            unpack_tar_gz(&archive, &fx.dest(), &allowed()).expect("unpack");
            assert_eq!(fs::read(&victim).expect("victim"), VICTIM);
            assert_eq!(fs::read(fx.dest().join(R1CS_FILE)).expect("r1cs"), R1CS);
        }

        #[cfg(unix)]
        #[test]
        fn unpack_does_not_write_through_a_hard_link_named_like_an_artifact() {
            let fx = Fixture::new();
            let victim = fx.victim();
            let archive = tar_gz(|b| {
                link(b, EntryType::Link, R1CS_FILE, &victim);
                file(b, R1CS_FILE, R1CS);
            });
            unpack_tar_gz(&archive, &fx.dest(), &allowed()).expect("unpack");
            assert_eq!(fs::read(&victim).expect("victim"), VICTIM);
            assert_eq!(fs::read(fx.dest().join(R1CS_FILE)).expect("r1cs"), R1CS);
        }

        #[cfg(unix)]
        #[test]
        fn unpack_leaves_the_target_of_a_symlink_entry_unchanged() {
            let fx = Fixture::new();
            let victim = fx.victim();
            let archive = tar_gz(|b| link(b, EntryType::Symlink, R1CS_FILE, &victim));
            let _ = unpack_tar_gz(&archive, &fx.dest(), &allowed());
            assert_eq!(fs::read(&victim).expect("victim"), VICTIM);
            assert_eq!(fx.outside().read_dir().expect("outside").count(), 1);
        }

        #[cfg(unix)]
        #[test]
        fn unpack_leaves_the_target_of_a_hard_link_entry_unchanged() {
            let fx = Fixture::new();
            let victim = fx.victim();
            let archive = tar_gz(|b| link(b, EntryType::Link, R1CS_FILE, &victim));
            let _ = unpack_tar_gz(&archive, &fx.dest(), &allowed());
            assert_eq!(fs::read(&victim).expect("victim"), VICTIM);
            assert_eq!(fx.outside().read_dir().expect("outside").count(), 1);
        }

        #[test]
        fn unpack_rejects_a_truncated_gzip_stream() {
            let fx = Fixture::new();
            let archive = release_archive();
            let truncated = archive.get(..archive.len() / 2).expect("half the archive");
            unpack_tar_gz(truncated, &fx.dest(), &allowed()).expect_err("truncated");
        }

        #[test]
        fn unpack_rejects_bytes_that_are_not_gzip() {
            let fx = Fixture::new();
            let err = unpack_tar_gz(b"definitely not gzip", &fx.dest(), &allowed())
                .expect_err("not gzip");
            assert!(err.to_string().contains("circuits.tar.gz"), "{err}");
            assert_eq!(fx.dest_listing(), Vec::<String>::new());
        }

        #[test]
        fn unpack_rejects_a_gzip_payload_that_is_not_a_tar_archive() {
            let fx = Fixture::new();
            let err = unpack_tar_gz(&gzip(&[b'A'; 2048]), &fx.dest(), &allowed())
                .expect_err("not a tar archive");
            assert!(err.to_string().contains("circuits.tar.gz"), "{err}");
            assert_eq!(fx.dest_listing(), Vec::<String>::new());
        }

        #[tokio::test]
        async fn ensure_downloads_and_unpacks_the_release_archive() {
            let fx = Fixture::new();
            let server = serve_archive(200, release_archive(), 1).await;
            let store = CircuitStore::open(fx.dest(), lock());

            store
                .ensure_from(&archive_url(&server))
                .await
                .expect("ensure");

            let artifacts = store.artifacts(STEM).expect("artifacts");
            assert_eq!(artifacts.circuit_r1cs, R1CS);
            assert_eq!(artifacts.circuit_graph, GRAPH);
            assert_eq!(artifacts.proving_key, KEY);
        }

        #[tokio::test]
        async fn ensure_does_not_download_when_the_artifacts_are_already_present() {
            let fx = Fixture::new();
            write_artifacts(&fx.dest());
            let server = serve_archive(200, release_archive(), 0).await;
            let store = CircuitStore::open(fx.dest(), lock());

            store
                .ensure_from(&archive_url(&server))
                .await
                .expect("ensure");
        }

        #[tokio::test]
        async fn ensure_succeeds_offline_when_the_artifacts_are_already_present() {
            let fx = Fixture::new();
            write_artifacts(&fx.dest());
            let store = CircuitStore::open(fx.dest(), lock());

            store.ensure().await.expect("ensure");
        }

        #[tokio::test]
        async fn ensure_replaces_an_artifact_whose_hash_does_not_match() {
            let fx = Fixture::new();
            write_artifacts(&fx.dest());
            fs::write(fx.dest().join(GRAPH_FILE), b"corrupted").expect("corrupt graph");
            let server = serve_archive(200, release_archive(), 1).await;
            let store = CircuitStore::open(fx.dest(), lock());

            store
                .ensure_from(&archive_url(&server))
                .await
                .expect("ensure");

            assert_eq!(fs::read(fx.dest().join(GRAPH_FILE)).expect("graph"), GRAPH);
        }

        #[tokio::test]
        async fn ensure_rejects_an_archive_whose_files_do_not_match_circuits_json() {
            let fx = Fixture::new();
            let tampered = tar_gz(|b| {
                file(b, R1CS_FILE, R1CS);
                file(b, GRAPH_FILE, b"tampered graph");
                file(b, KEY_FILE, KEY);
            });
            let server = serve_archive(200, tampered, 1).await;
            let store = CircuitStore::open(fx.dest(), lock());

            let err = store
                .ensure_from(&archive_url(&server))
                .await
                .expect_err("tampered archive");

            assert_eq!(
                err.to_string(),
                "downloaded circuit artifacts do not match supplied circuits.json"
            );
        }

        #[tokio::test]
        async fn ensure_rejects_an_archive_that_lacks_an_artifact() {
            let fx = Fixture::new();
            let incomplete = tar_gz(|b| {
                file(b, R1CS_FILE, R1CS);
                file(b, GRAPH_FILE, GRAPH);
            });
            let server = serve_archive(200, incomplete, 1).await;
            let store = CircuitStore::open(fx.dest(), lock());

            let err = store
                .ensure_from(&archive_url(&server))
                .await
                .expect_err("incomplete archive");

            assert_eq!(
                err.to_string(),
                "downloaded circuit artifacts do not match supplied circuits.json"
            );
        }

        #[tokio::test]
        async fn ensure_reports_a_missing_release_as_a_download_error() {
            let fx = Fixture::new();
            let server = serve_archive(404, Vec::new(), 1).await;
            let url = archive_url(&server);
            let store = CircuitStore::open(fx.dest(), lock());

            let err = store.ensure_from(&url).await.expect_err("404");

            assert!(
                err.to_string().starts_with(&format!("download {url}")),
                "{err}"
            );
            assert_eq!(fx.dest_listing(), Vec::<String>::new());
        }

        #[tokio::test]
        async fn ensure_reports_a_connection_failure_as_a_download_error() {
            let fx = Fixture::new();
            // Nothing can listen on port 0, so the connection fails without
            // reserving a port that a parallel test's server could take.
            let url = "http://127.0.0.1:0/circuits.tar.gz";
            let store = CircuitStore::open(fx.dest(), lock());

            let err = store
                .ensure_from(url)
                .await
                .expect_err("connection failure");

            assert!(
                err.to_string().starts_with(&format!("download {url}")),
                "{err}"
            );
        }

        #[tokio::test]
        async fn ensure_recovers_after_a_truncated_download() {
            let fx = Fixture::new();
            let archive = release_archive();
            let truncated = archive.get(..archive.len() / 2).expect("half the archive");
            let broken = serve_archive(200, truncated.to_vec(), 1).await;
            let good = serve_archive(200, archive.clone(), 1).await;
            let store = CircuitStore::open(fx.dest(), lock());

            store
                .ensure_from(&archive_url(&broken))
                .await
                .expect_err("truncated download");
            store.ensure_from(&archive_url(&good)).await.expect("retry");

            assert_eq!(store.artifacts(STEM).expect("artifacts").circuit_r1cs, R1CS);
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use store::CircuitStore;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        CircuitStem, KEY_OWNERSHIP_CIRCUIT, SELECTIVE_DISCLOSURE_1_CIRCUIT,
        SELECTIVE_DISCLOSURE_2_CIRCUIT, SELECTIVE_DISCLOSURE_3_CIRCUIT,
        SELECTIVE_DISCLOSURE_4_CIRCUIT,
    };

    const DISCLOSURE_STEMS: [&str; 4] = [
        SELECTIVE_DISCLOSURE_1_CIRCUIT,
        SELECTIVE_DISCLOSURE_2_CIRCUIT,
        SELECTIVE_DISCLOSURE_3_CIRCUIT,
        SELECTIVE_DISCLOSURE_4_CIRCUIT,
    ];

    #[test]
    fn lockfile_covers_transact_disclosure_and_key_ownership() {
        let lock = circuit_lock(include_str!("../circuits.json")).expect("parse test lock");
        assert!(!lock.version.is_empty());
        for stem in CircuitStem::all_transact_stems() {
            let stem_str = stem.to_string();
            assert!(lock.circuits.contains_key(&stem_str), "missing {stem_str}");
        }
        for stem in DISCLOSURE_STEMS {
            assert!(lock.circuits.contains_key(stem), "missing {stem}");
        }
        assert!(lock.circuits.contains_key(KEY_OWNERSHIP_CIRCUIT));
    }
    #[test]
    fn one_sdk_accepts_distinct_runtime_locks_without_weakening_hash_checks() {
        let source = include_str!("../circuits.json");
        let mut json: serde_json::Value = serde_json::from_str(source).expect("test circuit JSON");
        let stem = "policy_tx_2_2";
        for payload in [b"deployment A".as_slice(), b"deployment B".as_slice()] {
            let hash = hex::encode(Sha256::digest(payload));
            for kind in CircuitLockfile::ARTIFACT_KINDS {
                json[stem][kind] = hash.clone().into();
            }
            let lock = circuit_lock(&json.to_string()).expect("runtime circuit lock");
            for kind in CircuitLockfile::ARTIFACT_KINDS {
                assert!(lock.verify_artifact(stem, kind, payload).is_ok());
                assert!(
                    lock.verify_artifact(stem, kind, b"other deployment")
                        .is_err()
                );
            }
        }
        json["../escape"] = json[stem].clone();
        assert!(circuit_lock(&json.to_string()).is_err());
    }

    fn lock_json() -> serde_json::Value {
        serde_json::from_str(include_str!("../circuits.json")).expect("test circuit JSON")
    }

    fn lock_from(json: &serde_json::Value) -> CircuitLockfile {
        circuit_lock(&json.to_string()).expect("circuit lock")
    }

    #[test]
    fn release_url_names_the_circuits_release_of_the_locked_version() {
        let mut json = lock_json();
        json["version"] = "1.2.3".into();
        json["meta"]["repository"] = "owner/repo".into();
        assert_eq!(
            lock_from(&json).release_url(),
            "https://github.com/owner/repo/releases/download/circuits-v1.2.3/circuits.tar.gz"
        );
    }

    #[test]
    fn artifact_file_name_follows_the_release_layout_for_each_kind() {
        assert_eq!(
            CircuitLockfile::artifact_file_name("stem", "r1cs"),
            "stem.r1cs"
        );
        assert_eq!(
            CircuitLockfile::artifact_file_name("stem", "graph.bin"),
            "stem.graph.bin"
        );
        assert_eq!(
            CircuitLockfile::artifact_file_name("stem", "proving_key.bin"),
            "stem_proving_key.bin"
        );
        assert_eq!(
            CircuitLockfile::artifact_file_name("stem", "other"),
            "stem.other"
        );
    }

    #[test]
    fn verify_artifact_rejects_a_stem_that_is_not_in_the_lock() {
        let err = lock_from(&lock_json())
            .verify_artifact("not_a_circuit", "r1cs", b"payload")
            .expect_err("unknown stem");
        assert_eq!(
            err.to_string(),
            "stem not_a_circuit is not in supplied circuits.json"
        );
    }

    #[test]
    fn verify_artifact_rejects_an_unknown_artifact_kind() {
        let err = lock_from(&lock_json())
            .verify_artifact("policy_tx_2_2", "zkey", b"payload")
            .expect_err("unknown kind");
        assert_eq!(err.to_string(), "unknown artifact kind: zkey");
    }

    #[test]
    fn verify_artifact_rejects_bytes_that_do_not_hash_to_the_locked_value() {
        let json = lock_json();
        let want = json["policy_tx_2_2"]["r1cs"].as_str().expect("locked hash");
        let got = hex::encode(Sha256::digest(b"tampered"));
        let err = lock_from(&json)
            .verify_artifact("policy_tx_2_2", "r1cs", b"tampered")
            .expect_err("hash mismatch");
        assert_eq!(
            err.to_string(),
            format!("hash mismatch policy_tx_2_2/r1cs: want {want} got {got}")
        );
    }

    #[test]
    fn circuit_lock_rejects_a_hash_that_is_not_hex() {
        let mut json = lock_json();
        json["policy_tx_2_2"]["graph.bin"] = "not hex".into();
        let err = circuit_lock(&json.to_string()).expect_err("malformed hex");
        assert!(
            err.to_string()
                .starts_with("invalid hash hex for policy_tx_2_2/graph.bin"),
            "{err}"
        );
    }

    #[test]
    fn circuit_lock_rejects_a_hash_that_is_not_32_bytes() {
        let mut json = lock_json();
        json["policy_tx_2_2"]["proving_key.bin"] = "abcd".into();
        let err = circuit_lock(&json.to_string()).expect_err("short hash");
        assert_eq!(
            err.to_string(),
            "expected 32-byte hash for policy_tx_2_2/proving_key.bin, got 4 hex chars"
        );
    }

    #[test]
    fn circuit_lock_rejects_an_empty_version() {
        let mut json = lock_json();
        json["version"] = "".into();
        let err = circuit_lock(&json.to_string()).expect_err("empty version");
        assert_eq!(
            err.to_string(),
            "circuit lock must have a version and circuit entries"
        );
    }

    #[test]
    fn circuit_lock_rejects_a_lock_without_circuit_entries() {
        let json = serde_json::json!({ "version": "0.7", "meta": lock_json()["meta"] });
        let err = circuit_lock(&json.to_string()).expect_err("no circuits");
        assert_eq!(
            err.to_string(),
            "circuit lock must have a version and circuit entries"
        );
    }
}
