"""Offline root-only integration tests; all writes stay in a temporary directory.

Run: python3 -m unittest discover -s demos/acme-godaddy -p service_scripts_test.py
"""

import errno
import os
from pathlib import Path
import pty
import select
import shutil
import stat
import subprocess
import tempfile
import time
import unittest


SOURCE = Path(__file__).resolve().parent


@unittest.skipUnless(os.geteuid() == 0, "checks root-owned system service installation")
class ServiceScriptsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="acme-service-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env_file = self.root / "config" / "godaddy.env"
        self.unit_dir = self.root / "units"
        self.buckyos_root = self.root / 'buckyos with $dollar %percent "quote'

    def setup_token(self, token, *arguments):
        # A controlling TTY exercises the actual hidden prompt, without allowing
        # tokens in script arguments or relying on an environment fallback.
        child, terminal = pty.fork()
        if child == 0:
            os.execv(
                "/bin/bash",
                [
                    "bash",
                    "-x",
                    str(SOURCE / "setup_godaddy_token.sh"),
                    "--env-file",
                    str(self.env_file),
                    *arguments,
                ],
            )
        output = bytearray()
        sent = False
        deadline = time.monotonic() + 10
        try:
            while time.monotonic() < deadline:
                if not select.select([terminal], [], [], 0.1)[0]:
                    continue
                try:
                    chunk = os.read(terminal, 4096)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output.extend(chunk)
                if b"(PAT)" in output and not sent:
                    # read -s disables echo before read consumes input. Waiting
                    # briefly avoids typing into the PTY ahead of that operation.
                    time.sleep(0.05)
                    os.write(terminal, token.encode() + b"\n")
                    sent = True
            else:
                os.kill(child, 9)
                self.fail("token setup did not finish")
        finally:
            os.close(terminal)
            _, status = os.waitpid(child, 0)
        return os.waitstatus_to_exitcode(status), output.decode()

    def write_env(self):
        self.env_file.parent.mkdir(mode=0o755)
        self.env_file.write_text('GODADDY_PAT="fake-test-token"\n')
        self.env_file.chmod(0o600)

    def install(self, *arguments, no_enable=True, environment=None):
        command = [
            "bash",
            str(SOURCE / "install_service.sh"),
            "--env-file",
            str(self.env_file),
            "--buckyos-root",
            str(self.buckyos_root),
            "--unit-dir",
            str(self.unit_dir),
            "--deno",
            "/usr/bin/true",
            "--zone",
            "example.com",
            "--domain",
            "*.example.com",
            "--domain",
            "example.com",
            "--email",
            "user+$VALUE%literal@example.com",
            "--accept-terms",
            "--production",
            *arguments,
        ]
        if no_enable:
            command.append("--no-enable")
        return subprocess.run(command, capture_output=True, text=True, env=environment)

    def verify_units(self, service):
        verified = subprocess.run(
            ["systemd-analyze", "verify", str(service), str(service.with_suffix(".timer"))],
            capture_output=True,
            text=True,
            env=os.environ | {"SYSTEMD_LOG_LEVEL": "warning"},
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        # Some invalid directives are ignored with a warning and exit status 0.
        self.assertEqual(verified.stderr, "", verified.stderr)

    def test_token_is_private_hidden_and_escaped_for_environment_file(self):
        token = 'fake\\token"with$and`and%literal'
        result, output = self.setup_token(token)
        self.assertEqual(result, 0, output)
        self.assertNotIn(token, output)
        self.assertEqual(
            self.env_file.read_text(),
            'GODADDY_PAT="fake\\\\token\\"with\\$and\\`and%literal"\n',
        )
        self.assertEqual(stat.S_IMODE(self.env_file.stat().st_mode), 0o600)
        self.assertEqual(self.env_file.stat().st_uid, 0)
        old_inode = self.env_file.stat().st_ino
        result, output = self.setup_token("replacement-token")
        self.assertEqual(result, 0, output)
        self.assertNotEqual(old_inode, self.env_file.stat().st_ino)
        self.assertFalse(list(self.env_file.parent.glob(".acme-godaddy.env.*")))

    def test_empty_token_preserves_existing_secret(self):
        self.write_env()
        existing = self.env_file.read_bytes()
        result, _ = self.setup_token("   ")
        self.assertNotEqual(result, 0)
        self.assertEqual(existing, self.env_file.read_bytes())

    def test_token_refuses_symlinked_directory(self):
        destination = self.root / "other"
        destination.mkdir()
        self.env_file.parent.symlink_to(destination, target_is_directory=True)
        result, _ = self.setup_token("unused-token")
        self.assertNotEqual(result, 0)
        self.assertFalse((destination / self.env_file.name).exists())

    def test_installer_generates_valid_units_and_preserves_literal_arguments(self):
        self.write_env()
        result = self.install(
            "--propagation-delay", "180",
            "--propagation-timeout", "600",
            "--propagation-interval", "5",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        service = self.unit_dir / "acme-godaddy.service"
        content = service.read_text()
        self.assertIn('ExecStart=:"/usr/bin/true"', content)
        self.assertIn('"*.example.com" "--domain" "example.com"', content)
        self.assertIn('"user+$VALUE%%literal@example.com"', content)
        self.assertIn('"--propagation-delay" "180"', content)
        self.assertIn('"--propagation-timeout" "600"', content)
        self.assertIn('"--propagation-interval" "5"', content)
        self.assertIn('with $dollar %%percent \\"quote', content)
        self.assertNotIn("fake-test-token", content)
        self.assertIn("User=root", content)
        self.assertIn("UMask=0022", content)
        runtime = self.buckyos_root / "libexec" / "acme-godaddy"
        self.assertTrue((runtime / "main.ts").is_file())
        self.assertTrue((runtime / "deno.lock").is_file())
        self.assertFalse(list(runtime.glob("*_test.ts")))
        self.assertFalse(list(runtime.glob("*.env")))
        self.assertEqual(stat.S_IMODE(service.stat().st_mode), 0o644)
        if shutil.which("systemd-analyze"):
            self.verify_units(service)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "requires systemd's actual unit parser")
    def test_environment_file_path_is_retained_by_systemd(self):
        for index, name in enumerate(("godaddy.env", 'godaddy with $dollar %percent "quote.env')):
            with self.subTest(filename=name):
                self.env_file = self.root / f"config-{index}" / name
                self.write_env()
                result = self.install()
                self.assertEqual(result.returncode, 0, result.stderr)
                service = self.unit_dir / "acme-godaddy.service"
                self.verify_units(service)

                # verify does not run the service. Its debug unit dump exposes
                # parsed EnvironmentFile paths, so assert the directive was
                # retained and percent specifiers resolved, not silently ignored.
                parsed = subprocess.run(
                    ["systemd-analyze", "verify", str(service)],
                    capture_output=True,
                    text=True,
                    env=os.environ | {"SYSTEMD_LOG_LEVEL": "debug"},
                )
                self.assertEqual(parsed.returncode, 0, parsed.stderr)
                parsed_lines = [line.strip() for line in (parsed.stdout + parsed.stderr).splitlines()]
                self.assertIn(f"EnvironmentFile: {self.env_file}", parsed_lines)

    def test_installer_enables_timer_without_starting_issuance(self):
        self.write_env()
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        log = self.root / "systemctl.log"
        mock = binary_dir / "systemctl"
        mock.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$SYSTEMCTL_TEST_LOG"\n')
        mock.chmod(0o755)
        environment = os.environ | {
            "PATH": f"{binary_dir}:{os.environ['PATH']}",
            "SYSTEMCTL_TEST_LOG": str(log),
        }
        result = self.install(no_enable=False, environment=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            log.read_text().splitlines(),
            ["daemon-reload", f"enable {self.unit_dir}/acme-godaddy.timer"],
        )

    def test_installer_refuses_public_credentials_and_forced_renewal(self):
        self.write_env()
        self.env_file.chmod(0o644)
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.unit_dir.exists())
        self.env_file.chmod(0o600)
        result = self.install("--force")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.unit_dir.exists())


if __name__ == "__main__":
    unittest.main()
