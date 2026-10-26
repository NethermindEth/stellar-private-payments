//! Which CI run built a contract's code, from its Wasm's meta, the manifest,
//! and GitHub's artifact attestations.
//!
//! The status reads what an attestation's payload claims and checks no
//! signature, so it names the run that built the code and never says the code
//! is safe.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};

use anyhow::{Context as _, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::stellar_cli::ContractCode;

/// The repository whose builds are not flagged.
const HOME_REPO: &str = "NethermindEth/stellar-private-payments";
const WORKFLOW: &str = ".github/workflows/contracts-release.yml";
const WORKFLOW_REF: &str = "refs/heads/main";
const SLSA_PROVENANCE: &str = "https://slsa.dev/provenance/v1";
/// Seconds a cached lookup stays fresh: 24 hours for a match, 10 minutes for a
/// miss.
const MATCH_TTL: u64 = 86_400;
const MISS_TTL: u64 = 600;
/// How long a GitHub request may take, so a stalled one reads as `unknown`
/// instead of holding the command.
pub const GITHUB_TIMEOUT: Duration = Duration::from_secs(10);

/// What a contract's code must be to match the manifest.
pub struct Expected<'a> {
    /// The Wasm hash the manifest records.
    pub recorded: Option<&'a str>,
    /// The package the contract's role is built from.
    pub package: &'a str,
    /// A verifier's key name; `None` for other contracts.
    pub key: Option<&'a str>,
    /// The network the release's verifiers were built for; `None` accepts any.
    pub network: Option<&'a str>,
}

/// What a contract runs, as read.
#[derive(Clone, Copy)]
pub enum Code<'a> {
    /// The read failed.
    Unread,
    /// The executable is not a Wasm, such as a Stellar asset contract's.
    NoWasm,
    /// The Wasm's hash and meta.
    Wasm(&'a ContractCode),
}

impl<'a> Code<'a> {
    fn wasm(self) -> Option<&'a ContractCode> {
        match self {
            Self::Wasm(code) => Some(code),
            Self::Unread | Self::NoWasm => None,
        }
    }
}

/// The CI run an attestation names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Build {
    pub repo: String,
    pub commit: String,
    pub run_url: String,
}

/// A contract's code status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "code_status", rename_all = "snake_case")]
pub enum CodeStatus {
    /// The release workflow on `main` of the Wasm's `source_repo` attested this
    /// hash.
    Attested {
        #[serde(flatten)]
        build: Build,
        /// Whether `build.repo` is not the home repository.
        other_repo: bool,
    },
    /// GitHub has no matching attestation, but the hash is the manifest's.
    MatchesManifest,
    /// The hash is not the manifest's, or the meta does not fit the contract's
    /// role.
    Differs,
    /// None of the above.
    Unknown { reason: UnknownReason },
}

/// Why a contract's code status is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    /// The contract's code could not be read.
    CodeUnread,
    /// The contract's executable is not a Wasm.
    NoCode,
    /// GitHub did not answer with a list of attestations.
    GithubUnchecked,
    /// No matching attestation, or no valid `source_repo` to ask about, and the
    /// manifest records no hash.
    NotRecorded,
}

impl std::fmt::Display for CodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Attested { build, other_repo } => {
                let commit = build.commit.get(..7).unwrap_or(&build.commit);
                write!(f, "built by {}", build.repo)?;
                if *other_repo {
                    f.write_str(", which is not the project's official repository,")?;
                }
                write!(f, " from source version {commit} → {}", build.run_url)
            }
            Self::MatchesManifest => f.write_str(
                "matches the deployment configuration; GitHub has no build record for it",
            ),
            Self::Differs => f.write_str(
                "not the code the deployment configuration records, or built for another kind of \
                 contract; run the check in \"Check a deployment's code\" in the operator manual \
                 to see which",
            ),
            Self::Unknown { reason } => f.write_str(match reason {
                UnknownReason::CodeUnread => {
                    "unknown: could not read the contract's code; run the command again"
                }
                UnknownReason::NoCode => {
                    "unknown: this address is a token, not one of the project's contracts; check \
                     that the deployment configuration names the right address"
                }
                UnknownReason::GithubUnchecked => {
                    "unknown: no usable answer from GitHub; try again later"
                }
                UnknownReason::NotRecorded => {
                    "unknown: GitHub has no build record for it, and the deployment configuration \
                     names no contracts release to compare with"
                }
            }),
        }
    }
}

/// GitHub's answer for one Wasm hash, as cached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Lookup {
    Attested(Build),
    Missing,
}

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    checked_at: u64,
    lookup: Lookup,
}

/// Decides each row's code status, asking GitHub, through the cache in
/// `cache_dir`, once for each distinct repository and hash, in parallel.
///
/// A row whose code differs, or whose Wasm has no valid `source_repo`, sends no
/// request. `now` is Unix time in seconds.
pub fn statuses(
    rows: &[(&Expected<'_>, Code<'_>)],
    cache_dir: &Path,
    now: u64,
    fetch: impl Fn(&str) -> Result<(u16, String)> + Sync,
) -> Vec<CodeStatus> {
    let asks: BTreeSet<(&str, &str)> = rows
        .iter()
        .filter_map(|&(want, code)| code.wasm().filter(|code| !differs(want, code)))
        .filter_map(|code| Some((source_repo(&code.meta)?, code.hash.as_str())))
        .collect();
    let fetch = &fetch;
    let answers: BTreeMap<_, _> = std::thread::scope(|scope| {
        let asks: Vec<_> = asks
            .into_iter()
            .map(|(repo, hash)| {
                let answer = scope.spawn(move || lookup(cache_dir, repo, hash, now, fetch));
                ((repo, hash), answer)
            })
            .collect();
        asks.into_iter()
            .map(|(ask, answer)| (ask, answer.join().ok().flatten()))
            .collect()
    });
    rows.iter()
        .map(|&(want, code)| {
            let lookup = code.wasm().and_then(|code| match source_repo(&code.meta) {
                Some(repo) => answers.get(&(repo, code.hash.as_str())).cloned().flatten(),
                None => Some(Lookup::Missing),
            });
            code_status(want, code, lookup.as_ref())
        })
        .collect()
}

/// Builds the client every GitHub request shares, giving up on a request after
/// `timeout`.
///
/// # Errors
///
/// Returns an error when reqwest cannot set up its TLS backend.
pub fn client(timeout: Duration) -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .user_agent(concat!("spp/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .build()?)
}

/// Sends a GET request to `url` and returns the status code and body.
///
/// # Errors
///
/// Returns an error when the request or reading the body fails.
pub fn fetch(client: &reqwest::blocking::Client, url: &str) -> Result<(u16, String)> {
    let reply = client.get(url).send()?;
    Ok((reply.status().as_u16(), reply.text()?))
}

/// Returns the first of `differs`, `attested`, and `matches_manifest` that
/// applies, else `unknown`.
fn code_status(want: &Expected<'_>, code: Code<'_>, lookup: Option<&Lookup>) -> CodeStatus {
    let code = match code {
        Code::Wasm(code) => code,
        Code::Unread => {
            return CodeStatus::Unknown {
                reason: UnknownReason::CodeUnread,
            };
        }
        Code::NoWasm => {
            return CodeStatus::Unknown {
                reason: UnknownReason::NoCode,
            };
        }
    };
    if differs(want, code) {
        return CodeStatus::Differs;
    }
    match lookup {
        Some(Lookup::Attested(build)) => CodeStatus::Attested {
            build: build.clone(),
            other_repo: build.repo != HOME_REPO,
        },
        Some(Lookup::Missing) if want.recorded.is_some() => CodeStatus::MatchesManifest,
        Some(Lookup::Missing) => CodeStatus::Unknown {
            reason: UnknownReason::NotRecorded,
        },
        None => CodeStatus::Unknown {
            reason: UnknownReason::GithubUnchecked,
        },
    }
}

/// Reports whether the code is not the manifest's or does not fit the row's
/// role.
fn differs(want: &Expected<'_>, code: &ContractCode) -> bool {
    want.recorded.is_some_and(|hash| hash != code.hash) || !fits_role(want, &code.meta)
}

/// Reports whether the meta's `bldopt` entries, when it has any, hold exactly
/// one package, the role's, and for a verifier exactly one feature, its key's.
fn fits_role(want: &Expected<'_>, meta: &[(String, String)]) -> bool {
    let opts: Vec<&str> = meta
        .iter()
        .filter(|(key, _)| key == "bldopt")
        .map(|(_, val)| val.as_str())
        .collect();
    let packages: Vec<&str> = opts
        .iter()
        .filter_map(|opt| opt.strip_prefix("--package="))
        .collect();
    let features: Vec<&str> = opts
        .iter()
        .filter_map(|opt| opt.strip_prefix("--features="))
        .collect();
    opts.is_empty()
        || (packages == [want.package]
            && want.key.is_none_or(|key| {
                matches!(features.as_slice(), [feature] if names_key(feature, key, want.network))
            }))
}

/// Reports whether `feature` embeds `key` for `network`, or for any network
/// without a dash when it is `None`.
fn names_key(feature: &str, key: &str, network: Option<&str>) -> bool {
    // The verifier's build.rs rule: `vk-<network>-<key>`, lowercased, `_` as
    // `-`, "" as `none`.
    let dashed = |name: &str| name.to_lowercase().replace('_', "-");
    let key = dashed(if key.is_empty() { "none" } else { key });
    match network {
        Some(network) => feature == format!("vk-{}-{key}", dashed(network)),
        // The first dash ends the network, so `vk-testnet-a-gvk-v` never names `gvk_V`.
        None => feature
            .strip_prefix("vk-")
            .and_then(|rest| rest.split_once('-'))
            .is_some_and(|(net, rest)| !net.is_empty() && rest == key),
    }
}

/// Returns the `owner/name` of the meta's first `source_repo`, when it is a
/// valid GitHub repository.
fn source_repo(meta: &[(String, String)]) -> Option<&str> {
    let repo = meta
        .iter()
        .find(|(key, _)| key == "source_repo")?
        .1
        .strip_prefix("github:")?;
    let (owner, name) = repo.split_once('/')?;
    let valid = |part: &str, extra: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
    };
    (valid(owner, "-") && valid(name, "._-") && name != "." && name != "..").then_some(repo)
}

/// Returns GitHub's answer for `hash` in `repo`, from the cache while it is
/// fresh.
///
/// Only a match or a miss is cached; any other reply is logged and returns
/// `None`.
fn lookup(
    cache_dir: &Path,
    repo: &str,
    hash: &str,
    now: u64,
    fetch: impl FnOnce(&str) -> Result<(u16, String)>,
) -> Option<Lookup> {
    let path = cache_dir.join(format!("{hash}.json"));
    if let Some(entry) = std::fs::read(&path)
        .ok()
        .and_then(|raw| serde_json::from_slice::<CacheEntry>(&raw).ok())
    {
        // An entry of another shape, from another version or edited by hand, is
        // asked again.
        let (ttl, valid) = match &entry.lookup {
            Lookup::Attested(build) => (MATCH_TTL, is_build_of(build, repo)),
            Lookup::Missing => (MISS_TTL, true),
        };
        if valid
            && now
                .checked_sub(entry.checked_at)
                .is_some_and(|age| age < ttl)
        {
            return Some(entry.lookup);
        }
    }
    let lookup = fetch(&format!(
        "https://api.github.com/repos/{repo}/attestations/sha256:{hash}"
    ))
    .and_then(|(status, body)| match status {
        200 => parse(&body, repo, hash).context("GitHub's reply could not be read"),
        404 => Ok(Lookup::Missing),
        status => Err(anyhow!("GitHub answered HTTP {status}")),
    })
    .inspect_err(|error| {
        log::warn!(
            "no usable answer from GitHub about the code with fingerprint {hash}: {error:#}"
        );
    })
    .ok()?;
    let entry = CacheEntry {
        checked_at: now,
        lookup,
    };
    let saved = std::fs::create_dir_all(cache_dir)
        .and_then(|()| std::fs::write(&path, serde_json::to_vec(&entry)?));
    if let Err(error) = saved {
        log::warn!(
            "could not save the GitHub lookup to {}, so the next run asks again: {error}",
            path.display()
        );
    }
    Some(entry.lookup)
}

/// Returns the build the first matching attestation in a GitHub reply names, or
/// `None` when the reply is not a list of attestations.
fn parse(body: &str, repo: &str, hash: &str) -> Option<Lookup> {
    let reply: Value = serde_json::from_str(body).ok()?;
    let build = reply
        .get("attestations")?
        .as_array()?
        .iter()
        .find_map(|attestation| release_build(attestation, repo, hash));
    Some(build.map_or(Lookup::Missing, Lookup::Attested))
}

/// Returns the build an attestation names when it is an SLSA provenance for
/// `hash` by the release workflow on `main` of `repo`.
fn release_build(attestation: &Value, repo: &str, hash: &str) -> Option<Build> {
    let payload = attestation
        .pointer("/bundle/dsseEnvelope/payload")?
        .as_str()?;
    let statement: Value = serde_json::from_slice(&STANDARD.decode(payload).ok()?).ok()?;
    let text = |pointer: &str| statement.pointer(pointer).and_then(Value::as_str);
    let workflow = |field: &str| {
        text(&format!(
            "/predicate/buildDefinition/externalParameters/workflow/{field}"
        ))
    };
    let lists_hash = statement
        .get("subject")?
        .as_array()?
        .iter()
        .any(|subject| subject.pointer("/digest/sha256").and_then(Value::as_str) == Some(hash));
    let build = Build {
        repo: repo.to_owned(),
        commit: text("/predicate/buildDefinition/resolvedDependencies/0/digest/gitCommit")?
            .to_owned(),
        run_url: text("/predicate/runDetails/metadata/invocationId")?.to_owned(),
    };
    (text("/predicateType") == Some(SLSA_PROVENANCE)
        && lists_hash
        && workflow("repository").and_then(|url| url.strip_prefix("https://github.com/"))
            == Some(repo)
        && workflow("path") == Some(WORKFLOW)
        && workflow("ref") == Some(WORKFLOW_REF)
        && is_build_of(&build, repo))
    .then_some(build)
}

/// Reports whether `build` names `repo`, a commit of 40 hex digits, and a run
/// in `repo`.
fn is_build_of(build: &Build, repo: &str) -> bool {
    build.repo == repo
        && build.commit.len() == 40
        && build.commit.bytes().all(|b| b.is_ascii_hexdigit())
        && is_run_url(&build.run_url, repo)
}

/// Reports whether `url` is `https://github.com/<repo>/actions/runs/<n>`, optionally followed by
/// `/attempts/<n>`.
fn is_run_url(url: &str, repo: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    url.strip_prefix("https://github.com/")
        .and_then(|rest| rest.strip_prefix(repo))
        .and_then(|rest| rest.strip_prefix("/actions/runs/"))
        .is_some_and(|rest| match rest.split_once("/attempts/") {
            Some((run, attempt)) => digits(run) && digits(attempt),
            None => digits(rest),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::config::TempDir;

    /// stellar-cli 28.1.0's Linux tarball, the subject of the fixture's one
    /// attestation.
    const HASH: &str = "c1680deee94301d33ada7a17f98411e642a4248c727afbd2e43050d345746462";
    const OTHER_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const FIXTURE: &str = include_str!("testdata/attestations.json");
    const FORK: &str = "someone/fork";
    const NOW: u64 = 1_800_000_000;

    fn fixture_statement() -> Value {
        let reply: Value = serde_json::from_str(FIXTURE).expect("fixture JSON");
        let payload = reply
            .pointer("/attestations/0/bundle/dsseEnvelope/payload")
            .and_then(Value::as_str)
            .expect("fixture payload");
        serde_json::from_slice(&STANDARD.decode(payload).expect("base64")).expect("statement")
    }

    /// The fixture's statement, as if `contracts-release.yml` on `main` of
    /// `repo` made it.
    fn release_statement(repo: &str) -> Value {
        let mut statement = fixture_statement();
        statement["predicate"]["buildDefinition"]["externalParameters"]["workflow"] = serde_json::json!({
            "repository": format!("https://github.com/{repo}"), "path": WORKFLOW, "ref": WORKFLOW_REF
        });
        statement["predicate"]["runDetails"]["metadata"]["invocationId"] =
            format!("https://github.com/{repo}/actions/runs/7/attempts/1").into();
        statement
    }

    fn set(mut statement: Value, pointer: &str, value: &str) -> Value {
        *statement.pointer_mut(pointer).expect("field") = value.into();
        statement
    }

    /// A GitHub reply listing `statements` in order, each in the fixture's
    /// envelope.
    fn reply(statements: &[Value]) -> String {
        let mut reply: Value = serde_json::from_str(FIXTURE).expect("fixture JSON");
        let envelope = reply["attestations"][0].clone();
        reply["attestations"] = statements
            .iter()
            .map(|statement| {
                let mut attestation = envelope.clone();
                attestation["bundle"]["dsseEnvelope"]["payload"] =
                    STANDARD.encode(statement.to_string()).into();
                attestation
            })
            .collect();
        reply.to_string()
    }

    fn parse_home(statements: &[Value]) -> Option<Lookup> {
        parse(&reply(statements), HOME_REPO, HASH)
    }

    fn verifier_b(recorded: Option<&'static str>) -> Expected<'static> {
        Expected {
            recorded,
            package: "circom-groth16-verifier",
            key: Some("B"),
            network: Some("testnet"),
        }
    }

    fn code(meta: &[(&str, &str)]) -> ContractCode {
        ContractCode {
            hash: HASH.into(),
            meta: meta
                .iter()
                .map(|(key, val)| (key.to_string(), val.to_string()))
                .collect(),
        }
    }

    fn release_code(repo: &str, feature: &str) -> ContractCode {
        code(&[
            ("cliver", "28.0.0"),
            ("bldopt", "--package=circom-groth16-verifier"),
            ("bldopt", "--locked"),
            ("bldopt", "--optimize"),
            ("bldopt", feature),
            ("source_repo", &format!("github:{repo}")),
        ])
    }

    fn offline(_: &str) -> Result<(u16, String)> {
        Err(anyhow::anyhow!("offline"))
    }

    /// One row's status, through [`statuses`].
    fn check(
        want: &Expected<'_>,
        code: &ContractCode,
        dir: &TempDir,
        now: u64,
        fetch: impl Fn(&str) -> Result<(u16, String)> + Sync,
    ) -> CodeStatus {
        let status = statuses(&[(want, Code::Wasm(code))], &dir.0, now, fetch).pop();
        status.expect("one status")
    }

    fn unknown(reason: UnknownReason) -> CodeStatus {
        CodeStatus::Unknown { reason }
    }

    #[test]
    fn the_fixture_decodes_and_is_not_a_release_attestation() {
        assert_eq!(fixture_statement()["subject"][0]["digest"]["sha256"], HASH);
        assert_eq!(
            parse(FIXTURE, "stellar/stellar-cli", HASH),
            Some(Lookup::Missing)
        );
    }

    #[test]
    fn code_status_follows_differs_attested_matches_unknown_order() {
        let code = release_code(HOME_REPO, "--features=vk-testnet-b");
        let attested = parse_home(&[release_statement(HOME_REPO)]);
        let build = Build {
            repo: HOME_REPO.into(),
            commit: "c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd".into(),
            run_url: format!("https://github.com/{HOME_REPO}/actions/runs/7/attempts/1"),
        };
        let status = code_status(
            &verifier_b(Some(HASH)),
            Code::Wasm(&code),
            attested.as_ref(),
        );
        assert_eq!(
            status,
            CodeStatus::Attested {
                build: build.clone(),
                other_repo: false
            }
        );
        assert_eq!(
            status.to_string(),
            format!(
                "built by {HOME_REPO} from source version c0f4d0d → {}",
                build.run_url
            )
        );
        let missing = Some(&Lookup::Missing);
        assert_eq!(
            code_status(&verifier_b(Some(HASH)), Code::Wasm(&code), missing),
            CodeStatus::MatchesManifest
        );
        assert_eq!(
            code_status(
                &verifier_b(Some(OTHER_HASH)),
                Code::Wasm(&code),
                attested.as_ref()
            ),
            CodeStatus::Differs
        );
        assert_eq!(
            code_status(&verifier_b(Some(HASH)), Code::Unread, attested.as_ref()),
            unknown(UnknownReason::CodeUnread)
        );
        assert_eq!(
            code_status(&verifier_b(None), Code::Wasm(&code), missing),
            unknown(UnknownReason::NotRecorded)
        );
        assert_eq!(
            code_status(&verifier_b(Some(HASH)), Code::Wasm(&code), None),
            unknown(UnknownReason::GithubUnchecked)
        );
    }

    #[test]
    fn a_contract_with_no_wasm_is_unknown() {
        let attested = parse_home(&[release_statement(HOME_REPO)]);
        for lookup in [attested.as_ref(), Some(&Lookup::Missing), None] {
            let status = code_status(&verifier_b(Some(HASH)), Code::NoWasm, lookup);
            assert_eq!(status, unknown(UnknownReason::NoCode));
        }
    }

    #[test]
    fn a_fork_that_attested_its_own_build_is_attested_and_flagged() {
        let lookup = parse(&reply(&[release_statement(FORK)]), FORK, HASH);
        let status = code_status(
            &verifier_b(Some(HASH)),
            Code::Wasm(&release_code(FORK, "--features=vk-testnet-b")),
            lookup.as_ref(),
        );
        assert!(
            matches!(&status, CodeStatus::Attested { build, other_repo: true } if build.repo == FORK)
        );
        assert_eq!(
            status.to_string(),
            format!(
                "built by {FORK}, which is not the project's official repository, from source \
                 version c0f4d0d → https://github.com/{FORK}/actions/runs/7/attempts/1"
            )
        );
    }

    #[test]
    fn an_attestation_made_in_another_repository_is_rejected() {
        let workflow = "/predicate/buildDefinition/externalParameters/workflow";
        let statement = set(
            release_statement(HOME_REPO),
            &format!("{workflow}/repository"),
            &format!("https://github.com/{FORK}"),
        );
        assert_eq!(parse_home(&[statement]), Some(Lookup::Missing));
    }

    #[test]
    fn an_attestation_of_another_file_or_kind_is_rejected() {
        let mut other_file = release_statement(HOME_REPO);
        other_file["subject"] = serde_json::json!([{ "digest": { "sha256": OTHER_HASH } }]);
        assert_eq!(parse_home(&[other_file]), Some(Lookup::Missing));
        let release_kind = set(
            release_statement(HOME_REPO),
            "/predicateType",
            "https://in-toto.io/attestation/release/v0.1",
        );
        assert_eq!(parse_home(&[release_kind]), Some(Lookup::Missing));
    }

    #[test]
    fn an_attestation_from_another_workflow_or_ref_is_rejected() {
        let workflow = "/predicate/buildDefinition/externalParameters/workflow";
        let other_workflow = set(
            release_statement(HOME_REPO),
            &format!("{workflow}/path"),
            ".github/workflows/release.yml",
        );
        assert_eq!(parse_home(&[other_workflow]), Some(Lookup::Missing));
        let other_ref = set(
            release_statement(HOME_REPO),
            &format!("{workflow}/ref"),
            "refs/heads/feature",
        );
        assert_eq!(parse_home(&[other_ref]), Some(Lookup::Missing));
    }

    #[test]
    fn a_matching_attestation_behind_another_workflows_provenance_is_used() {
        let workflow = "/predicate/buildDefinition/externalParameters/workflow";
        let first = set(
            set(
                release_statement(HOME_REPO),
                &format!("{workflow}/path"),
                ".github/workflows/release.yml",
            ),
            "/predicate/buildDefinition/resolvedDependencies/0/digest/gitCommit",
            &"a".repeat(40),
        );
        let lookup = parse_home(&[first, release_statement(HOME_REPO)]);
        assert!(matches!(lookup, Some(Lookup::Attested(build))
                if build.commit == "c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd"));
    }

    #[test]
    fn a_bad_commit_or_run_url_is_rejected() {
        let commit = "/predicate/buildDefinition/resolvedDependencies/0/digest/gitCommit";
        for bad in ["c0f4d0da", "g0f4d0da891bbf214c08b8c5035ae6db80e9a3bd"] {
            let statement = set(release_statement(HOME_REPO), commit, bad);
            assert_eq!(parse_home(&[statement]), Some(Lookup::Missing), "{bad}");
        }
        let run = format!("https://github.com/{HOME_REPO}/actions/runs/7");
        for bad in [
            format!("{run}/../8"),
            format!("{run}?attempt=1"),
            format!("{run}\n"),
        ] {
            let statement = set(
                release_statement(HOME_REPO),
                "/predicate/runDetails/metadata/invocationId",
                &bad,
            );
            assert_eq!(parse_home(&[statement]), Some(Lookup::Missing), "{bad:?}");
        }
    }

    #[test]
    fn a_verifier_whose_meta_does_not_fit_its_role_differs() {
        let missing = Some(&Lookup::Missing);
        let want = verifier_b(Some(HASH));
        let other_key = release_code(HOME_REPO, "--features=vk-testnet-a");
        assert_eq!(
            code_status(&want, Code::Wasm(&other_key), missing),
            CodeStatus::Differs
        );
        let other_network = release_code(HOME_REPO, "--features=vk-futurenet-b");
        assert_eq!(
            code_status(&want, Code::Wasm(&other_network), missing),
            CodeStatus::Differs
        );
        let any_network = Expected {
            network: None,
            ..verifier_b(Some(HASH))
        };
        assert_eq!(
            code_status(&any_network, Code::Wasm(&other_network), missing),
            CodeStatus::MatchesManifest
        );
        let gvk_v = Expected {
            key: Some("gvk_V"),
            ..any_network
        };
        let a_gvk_v = release_code(HOME_REPO, "--features=vk-testnet-a-gvk-v");
        assert_eq!(
            code_status(&gvk_v, Code::Wasm(&a_gvk_v), missing),
            CodeStatus::Differs
        );
        let gvk_v_code = release_code(HOME_REPO, "--features=vk-testnet-gvk-v");
        assert_eq!(
            code_status(&gvk_v, Code::Wasm(&gvk_v_code), missing),
            CodeStatus::MatchesManifest
        );
        let mut two_features = release_code(HOME_REPO, "--features=vk-testnet-b");
        two_features
            .meta
            .push(("bldopt".into(), "--features=vk-testnet-a".into()));
        assert_eq!(
            code_status(&want, Code::Wasm(&two_features), missing),
            CodeStatus::Differs
        );
        let mut two_packages = release_code(HOME_REPO, "--features=vk-testnet-b");
        two_packages
            .meta
            .push(("bldopt".into(), "--package=circom-groth16-verifier".into()));
        assert_eq!(
            code_status(&want, Code::Wasm(&two_packages), missing),
            CodeStatus::Differs
        );
    }

    #[test]
    fn a_wasm_without_a_valid_source_repo_sends_no_request() {
        let dir = TempDir::new("code-status-no-repo");
        for repo in [
            None,
            Some("github:owner/.."),
            Some("github:own er/x"),
            Some("gitlab:a/b"),
        ] {
            let mut meta = vec![("bldopt", "--package=circom-groth16-verifier")];
            meta.extend(repo.map(|repo| ("source_repo", repo)));
            let code = code(&meta);
            let want = Expected {
                key: None,
                ..verifier_b(Some(HASH))
            };
            let asked = AtomicBool::new(false);
            let status = check(&want, &code, &dir, NOW, |_| {
                asked.store(true, Ordering::SeqCst);
                offline("")
            });
            assert_eq!(status, CodeStatus::MatchesManifest, "{repo:?}");
            assert!(!asked.into_inner(), "{repo:?}");
            let unrecorded = Expected {
                recorded: None,
                ..want
            };
            assert_eq!(
                check(&unrecorded, &code, &dir, NOW, offline),
                unknown(UnknownReason::NotRecorded)
            );
        }
    }

    #[test]
    fn rows_sharing_a_wasm_ask_github_once_and_a_differing_row_never() {
        let dir = TempDir::new("code-status-once");
        let want = verifier_b(Some(HASH));
        let code = release_code(HOME_REPO, "--features=vk-testnet-b");
        let other = ContractCode {
            hash: OTHER_HASH.into(),
            ..release_code(HOME_REPO, "--features=vk-testnet-b")
        };
        let asked = AtomicUsize::new(0);
        let rows = [&code, &code, &other].map(|code| (&want, Code::Wasm(code)));
        let statuses = statuses(&rows, &dir.0, NOW, |_| {
            asked.fetch_add(1, Ordering::SeqCst);
            Ok((404, String::new()))
        });
        let (matches, differs) = (CodeStatus::MatchesManifest, CodeStatus::Differs);
        assert_eq!(statuses, [matches.clone(), matches, differs]);
        assert_eq!(asked.into_inner(), 1);
    }

    #[test]
    fn an_unreadable_reply_is_unknown_and_not_cached() {
        let dir = TempDir::new("code-status-unreadable");
        let code = release_code(HOME_REPO, "--features=vk-testnet-b");
        for reply in [(403, String::new()), (200, "{}".to_owned())] {
            let status = check(&verifier_b(Some(HASH)), &code, &dir, NOW, |url| {
                assert_eq!(
                    url,
                    format!("https://api.github.com/repos/{HOME_REPO}/attestations/sha256:{HASH}")
                );
                Ok(reply.clone())
            });
            assert_eq!(status, unknown(UnknownReason::GithubUnchecked));
            assert!(!dir.0.join(format!("{HASH}.json")).exists());
        }
    }

    #[test]
    fn a_request_with_no_answer_in_time_is_unknown_and_not_cached() {
        assert_eq!(GITHUB_TIMEOUT, Duration::from_secs(10));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let url = format!("http://{}/", listener.local_addr().expect("address"));
        // Holds the connection unanswered, then closes it, so a client without
        // the timeout fails on the close instead of hanging.
        std::thread::spawn(move || {
            let _connection = listener.accept();
            std::thread::sleep(Duration::from_secs(2));
        });
        let github = client(Duration::from_millis(50)).expect("client");
        let dir = TempDir::new("code-status-timeout");
        let code = release_code(HOME_REPO, "--features=vk-testnet-b");
        let timed_out = AtomicBool::new(false);
        let status = check(&verifier_b(Some(HASH)), &code, &dir, NOW, |_| {
            let reply = fetch(&github, &url);
            let timeout = reply.as_ref().is_err_and(|error| {
                error
                    .downcast_ref::<reqwest::Error>()
                    .is_some_and(reqwest::Error::is_timeout)
            });
            timed_out.store(timeout, Ordering::SeqCst);
            reply
        });
        assert_eq!(status, unknown(UnknownReason::GithubUnchecked));
        assert!(timed_out.into_inner());
        assert!(!dir.0.join(format!("{HASH}.json")).exists());
    }

    fn status_at(
        want: Option<&'static str>,
        dir: &TempDir,
        now: u64,
        fetch: impl Fn(&str) -> Result<(u16, String)> + Sync,
    ) -> CodeStatus {
        let code = release_code(HOME_REPO, "--features=vk-testnet-b");
        check(&verifier_b(want), &code, dir, now, fetch)
    }

    #[test]
    fn a_match_is_cached_for_24_hours_and_a_miss_for_10_minutes() {
        let (want, changed) = (Some(HASH), Some(OTHER_HASH));

        let dir = TempDir::new("code-status-match");
        let body = reply(&[release_statement(HOME_REPO)]);
        let first = status_at(want, &dir, NOW, |_| Ok((200, body.clone())));
        assert!(matches!(first, CodeStatus::Attested { .. }));
        let cached = status_at(want, &dir, NOW + 86_399, offline);
        assert!(matches!(cached, CodeStatus::Attested { .. }));
        assert_eq!(
            status_at(changed, &dir, NOW + 86_399, offline),
            CodeStatus::Differs
        );
        assert_eq!(
            status_at(want, &dir, NOW + 86_400, offline),
            unknown(UnknownReason::GithubUnchecked)
        );

        let dir = TempDir::new("code-status-miss");
        let not_found = |_: &str| Ok((404, String::new()));
        assert_eq!(
            status_at(want, &dir, NOW, not_found),
            CodeStatus::MatchesManifest
        );
        assert_eq!(
            status_at(want, &dir, NOW + 599, offline),
            CodeStatus::MatchesManifest
        );
        assert_eq!(
            status_at(changed, &dir, NOW + 599, offline),
            CodeStatus::Differs
        );
        assert_eq!(
            status_at(want, &dir, NOW + 600, offline),
            unknown(UnknownReason::GithubUnchecked)
        );

        // A miss stamped a week ahead, after the clock moved back, is stale.
        let dir = TempDir::new("code-status-future");
        status_at(want, &dir, NOW + 604_800, not_found);
        assert_eq!(
            status_at(want, &dir, NOW, offline),
            unknown(UnknownReason::GithubUnchecked)
        );
    }

    #[test]
    fn a_cached_build_of_another_shape_is_asked_again() {
        let dir = TempDir::new("code-status-bad-cache");
        let good = Build {
            repo: HOME_REPO.into(),
            commit: "c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd".into(),
            run_url: format!("https://github.com/{HOME_REPO}/actions/runs/7"),
        };
        for bad in [
            Build {
                commit: "c0f4d0d".into(),
                ..good.clone()
            },
            Build {
                run_url: "javascript:alert(1)".into(),
                ..good.clone()
            },
            Build {
                repo: FORK.into(),
                ..good.clone()
            },
        ] {
            let entry = CacheEntry {
                checked_at: NOW,
                lookup: Lookup::Attested(bad),
            };
            std::fs::create_dir_all(&dir.0).expect("cache directory");
            let raw = serde_json::to_vec(&entry).expect("JSON");
            std::fs::write(dir.0.join(format!("{HASH}.json")), raw).expect("cache entry");
            let not_found = |_: &str| Ok((404, String::new()));
            assert_eq!(
                status_at(Some(HASH), &dir, NOW, not_found),
                CodeStatus::MatchesManifest
            );
        }
    }

    #[test]
    fn code_status_serializes_in_snake_case() {
        assert_eq!(
            serde_json::to_value(CodeStatus::MatchesManifest).expect("JSON"),
            serde_json::json!({ "code_status": "matches_manifest" })
        );
        assert_eq!(
            serde_json::to_value(unknown(UnknownReason::GithubUnchecked)).expect("JSON"),
            serde_json::json!({ "code_status": "unknown", "reason": "github_unchecked" })
        );
        let build = Build {
            repo: HOME_REPO.into(),
            commit: "c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd".into(),
            run_url: "https://github.com/x/y/actions/runs/7".into(),
        };
        let status = CodeStatus::Attested {
            build,
            other_repo: false,
        };
        assert_eq!(
            serde_json::to_value(status).expect("JSON"),
            serde_json::json!({
                "code_status": "attested",
                "repo": HOME_REPO,
                "commit": "c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd",
                "run_url": "https://github.com/x/y/actions/runs/7",
                "other_repo": false,
            })
        );
    }
}
