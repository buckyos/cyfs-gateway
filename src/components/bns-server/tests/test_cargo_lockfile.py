import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cargo_lockfile import ensure_cargo_lockfile


class CargoLockfileTests(unittest.TestCase):
    def test_missing_lockfile_is_generated(self):
        with tempfile.TemporaryDirectory(prefix="bns-lockfile-") as temp:
            workspace = Path(temp)
            env = dict(os.environ)
            with patch("cargo_lockfile.subprocess.run") as run:
                ensure_cargo_lockfile(workspace, env)
            run.assert_called_once_with(
                ["cargo", "generate-lockfile"],
                cwd=workspace, env=env, check=True,
            )

    def test_existing_lockfile_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="bns-lockfile-") as temp:
            workspace = Path(temp)
            lockfile = workspace / "Cargo.lock"
            contents = b"existing dependency resolution\n"
            lockfile.write_bytes(contents)
            with patch("cargo_lockfile.subprocess.run") as run:
                ensure_cargo_lockfile(workspace, dict(os.environ))
            run.assert_not_called()
            self.assertEqual(lockfile.read_bytes(), contents)

    def test_generation_failure_is_propagated(self):
        with tempfile.TemporaryDirectory(prefix="bns-lockfile-") as temp:
            failure = subprocess.CalledProcessError(1, ["cargo", "generate-lockfile"])
            with patch("cargo_lockfile.subprocess.run", side_effect=failure) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    ensure_cargo_lockfile(Path(temp), dict(os.environ))
            self.assertEqual(run.call_count, 1)

    def test_clean_workspace_supports_locked_cargo_after_generation(self):
        with tempfile.TemporaryDirectory(prefix="bns-lockfile-") as temp:
            workspace = Path(temp)
            (workspace / "src").mkdir()
            (workspace / "src/lib.rs").write_text("")
            (workspace / "Cargo.toml").write_text(
                '[package]\nname = "bns-lockfile-test"\nversion = "0.1.0"\nedition = "2021"\n'
            )
            env = dict(os.environ)
            ensure_cargo_lockfile(workspace, env)
            lockfile = workspace / "Cargo.lock"
            contents = lockfile.read_bytes()
            ensure_cargo_lockfile(workspace, env)
            subprocess.run(
                ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
                cwd=workspace, env=env, check=True, stdout=subprocess.DEVNULL,
            )
            self.assertEqual(lockfile.read_bytes(), contents)


if __name__ == "__main__":
    unittest.main()
