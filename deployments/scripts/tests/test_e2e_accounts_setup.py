"""Exercise setup reset ordering without network calls or real identities."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "e2e-accounts-setup.sh"


class WalletResetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="spp-setup-test-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        scripts = root / "deployments/scripts"
        scripts.mkdir(parents=True)
        self.script = scripts / SCRIPT.name
        shutil.copyfile(SCRIPT, self.script)
        network = root / "deployments/testnet"
        network.mkdir()
        (network / "deployments.json").write_text(json.dumps({"pools": [
            {"enabled": True, "asset": {"kind": "native"}, "poolContractId": "test"}
        ]}))
        self.wallet = scripts / ".e2e-wallet-testnet"
        (self.wallet / "stellar/identity").mkdir(parents=True)
        self.preserved = ["stellar/identity/spp-e2e-a.toml", "config.toml", "spp.db.backup"]
        self.reset_files = [name + suffix
                            for name in ("spp.db", "spp.db.key", "spp.db.encrypting")
                            for suffix in ("", "-journal", "-wal", "-shm")] + ["spp-password"]
        for name in self.preserved + self.reset_files:
            (self.wallet / name).write_text("fixture")
        # Stop at the first identity generation, before it can replace a key.
        # At that point the storage cleanup must already have happened.
        binary = root / "bin"
        binary.mkdir()
        for name, body in {
            "stellar": 'if [ "$1 $2" = "keys generate" ]; then echo GENERATION_REACHED >&2; exit 73; fi\nexit 1',
            "git": '[ "$1" = check-ignore ]',
            "curl": 'echo UNEXPECTED_NETWORK >&2; exit 99',
        }.items():
            path = binary / name
            path.write_text("#!/bin/sh\n" + body + "\n")
            path.chmod(0o755)
        self.env = {**os.environ, "PATH": str(binary) + os.pathsep + os.environ["PATH"]}

    def run_setup(self, *args):
        result = subprocess.run(["bash", str(self.script), *args], env=self.env,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertIn("GENERATION_REACHED", result.stderr)
        self.assertNotIn("UNEXPECTED_NETWORK", result.stderr)
        for name in self.preserved:
            self.assertEqual((self.wallet / name).read_text(), "fixture")
        return result

    def test_force_resets_storage_before_replacing_identities(self):
        self.run_setup("--force")
        for name in self.reset_files:
            self.assertFalse((self.wallet / name).exists(), name)

    def test_ephemeral_resets_storage_before_replacing_identities(self):
        self.run_setup("--ephemeral", "--accounts", "c,d")
        for name in self.reset_files:
            self.assertFalse((self.wallet / name).exists(), name)

    def test_normal_provisioning_preserves_storage(self):
        self.run_setup()
        for name in self.reset_files:
            self.assertEqual((self.wallet / name).read_text(), "fixture")


if __name__ == "__main__":
    unittest.main()
