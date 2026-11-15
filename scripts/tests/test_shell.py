#!/usr/bin/env python3
"""Unprivileged regression tests for shell argument handling and e2e helpers."""

import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
STUB = Path(__file__).with_name("stub_command.py")


class ShellScriptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="bruecke-shell-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for command in (
            "ip", "wg", "iptables", "ip6tables", "cat", "sysctl",
            "openssl", "curl", "sleep", "nc", "podman", "docker",
        ):
            (self.bin / command).symlink_to(STUB)
        self.state_path = self.root / "state.json"
        self.state_path.write_text("{}")
        self.environment = {
            **os.environ,
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "SHELL_TEST_STATE": str(self.state_path),
        }

    def state(self):
        return json.loads(self.state_path.read_text())

    def update_state(self, **values):
        self.state_path.write_text(json.dumps({**self.state(), **values}))

    def run_script(self, script, *arguments, expected=0, source=None):
        command = ["sh", str(SCRIPTS / script), *arguments]
        if source is not None:
            command = ["sh", "-s", "--", *arguments]
        result = subprocess.run(
            command, input=source, text=True, capture_output=True,
            env=self.environment, cwd=self.root, timeout=20,
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def client_command(self, *arguments):
        work = self.root / "work"
        work.mkdir(exist_ok=True)
        source = (SCRIPTS / "e2e/client.sh").read_text().replace("/work/", f"{work}/")
        return self.run_script("e2e/client.sh", *arguments, source=source)

    def test_wireguard_usage_rejects_missing_arguments(self):
        for script in SCRIPTS.glob("bruecke-wg-*"):
            with self.subTest(script=script.name):
                self.run_script(script.name, expected=2)
        self.assertEqual(self.state().get("calls", []), [])

    def test_gateway_rules_are_dual_stack_and_idempotent(self):
        arguments = (
            "wg-test", "10.44.0.1/24,fd44::1/64", "51820", "key file",
            "auto", "10.44.0.0/24,10.45.0.0/24", "fd44::/64,fd45::/64",
        )
        self.run_script("bruecke-wg-up", *arguments)
        self.run_script("bruecke-wg-up", *arguments)
        state = self.state()
        self.assertEqual(len(state["rules"]), 8)
        self.assertEqual(set(state["rules"].values()), {1})
        self.assertIn(["wg", "set", "wg-test", "private-key", "key file", "listen-port", "51820"], state["calls"])
        self.assertIn(["ip", "address", "replace", "fd44::1/64", "dev", "wg-test"], state["calls"])
        self.assertTrue(all("eth-test" in json.loads(rule) for rule in state["rules"]))

        self.run_script("bruecke-wg-down", "wg-test", "auto", arguments[5], arguments[6])
        self.run_script("bruecke-wg-down", "wg-test", "auto", arguments[5], arguments[6])
        self.assertEqual(set(self.state()["rules"].values()), {0})
        self.assertEqual(self.state()["interfaces"], [])

    def test_gateway_none_does_not_touch_firewall(self):
        self.run_script("bruecke-wg-up", "wg-test", "10.44.0.1/24", "51820", "key", "none")
        self.assertNotIn("rules", self.state())

    def test_peer_commands_preserve_arguments(self):
        public_key = "public key with spaces="
        self.run_script("bruecke-wg-apply-peer", "wg-test", public_key, "10.44.0.2/32,fd44::2/128")
        self.assertEqual(self.state()["calls"][-1], [
            "wg", "set", "wg-test", "peer", public_key, "allowed-ips", "10.44.0.2/32,fd44::2/128",
        ])
        self.update_state(peers=public_key)
        self.run_script("bruecke-wg-remove-peer", "wg-test", public_key)
        self.assertEqual(self.state()["calls"][-1], ["wg", "set", "wg-test", "peer", public_key, "remove"])
        self.run_script("bruecke-wg-peer-status", "wg-test")
        self.assertEqual(self.state()["calls"][-1], ["wg", "show", "wg-test", "latest-handshakes"])

    def test_enrollment_builds_json_and_dual_stack_commands(self):
        work = self.root / "work"
        work.mkdir()
        (work / "client.crt").write_text("test certificate")
        self.client_command("enroll", "10.88.0.0/24", "fd88:88::/64", "1", "fd89:89::10")
        payload = json.loads((work / "enroll-finish.json").read_text())
        self.assertEqual(payload, {
            "handshake_id": "handshake with spaces",
            "algorithm": "sha256-rsa",
            "signature": base64.b64encode(b"signature").decode(),
        })
        calls = self.state()["calls"]
        self.assertIn(["ip", "address", "add", "10.88.0.2/32", "dev", "wg0"], calls)
        self.assertIn(["ip", "-6", "address", "add", "fd88:88::2/128", "dev", "wg0"], calls)
        self.assertIn(["ip", "-6", "route", "replace", "default", "dev", "wg0"], calls)
        self.assertTrue(any("0.0.0.0/0,::/0" in call for call in calls))

    def test_remote_subnet_and_group_workflow(self):
        work = self.root / "work"
        work.mkdir()
        for site in ("free", "restricted"):
            (work / f"remote-{site}-client.ovpn").write_text("client\n")
        self.client_command(
            "configure-remote-subnets", "password ' with spaces", "client.example.test",
            "manual.example.test", "second.example.test", "10.222.0.0/24", "10.223.0.0/24",
        )
        self.assertEqual(json.loads((work / "admin-login.json").read_text())["password"], "password ' with spaces")
        self.client_command("grant-nested-group")
        self.client_command("set-remote-enabled", "false")
        self.client_command("set-remote-enabled", "true")
        self.client_command("revoke-remote-subnet")
        self.client_command("set-client-enabled", "false")
        self.client_command("set-client-enabled", "true")
        self.assertEqual(json.loads((work / "client-enabled.json").read_text()), {"enabled": True})
        self.assertEqual(json.loads((work / "remote-restricted-revoke.json").read_text()), {"group_ids": []})

    def test_service_waits_handle_ipv6_and_denial(self):
        self.update_state(curl_body="bruecke-internet-e2e-ok")
        self.client_command("wait-reachable", "http://[fd89::10]:18081/", "bruecke-internet-e2e-ok", "2", "not reachable")
        curl_call = self.state()["calls"][-1]
        self.assertEqual(curl_call[:3], ["curl", "-g", "-6"])
        self.update_state(curl_fail=True)
        self.client_command("wait-denied", "http://example.test/", "2", "still reachable")

    def test_http_service_preserves_response_and_filter(self):
        self.run_script("e2e/services.sh", "serve-http", "10.222.0.10", "18082", "bruecke-remote-free-ok", "10.222.0.2", expected=1)
        state = self.state()
        self.assertEqual(state["http_response"], "HTTP/1.1 200 OK\r\nContent-Length: 23\r\n\r\nbruecke-remote-free-ok\n")
        self.assertIn(["nc", "-l", "-s", "10.222.0.10", "-p", "18082"], state["calls"])
        self.assertEqual(len(state["rules"]), 2)

    def test_e2e_orchestration_only_calls_stubbed_runtime(self):
        result = subprocess.run(
            ["bash", str(SCRIPTS / "test-e2e")], env=self.environment,
            cwd=self.root, text=True, capture_output=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[e2e] success", result.stdout)
        state = self.state()
        self.assertGreaterEqual(state["shell_programs"], 25)
        helper_read = ["cat", str(SCRIPTS / "e2e/services.sh")]
        unexpected_calls = [
            call for call in state["calls"]
            if call[0] != "podman" and call != helper_read
        ]
        self.assertEqual(unexpected_calls, [])

    def test_embedded_shell_programs_pass_static_checks(self):
        count = 0
        for script in ("dev", "interactive-liftoff", "test-e2e"):
            source = (SCRIPTS / script).read_text()
            for match in re.finditer(r"<<'SHELL'\n(.*?)\nSHELL", source, re.DOTALL):
                with self.subTest(script=script, program=count):
                    for command in (["sh", "-n"], ["shellcheck", "-s", "sh", "-"]):
                        result = subprocess.run(
                            command, input=match.group(1), text=True,
                            capture_output=True, timeout=10,
                        )
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                count += 1
        self.assertEqual(count, 5)

    def test_cleanup_collects_literal_mount_paths_and_unique_images(self):
        # Load only function definitions, never the destructive cleanup body.
        definitions = (SCRIPTS / "cleanup").read_text().split("\nruntime=", 1)[0]
        assertions = r'''
images=()
append_image first
append_image first
append_image 'second image'
printf '%s\n' "${images[@]}"
data_kinds=()
data_values=()
data_mount_seen=false
inspect_value() { printf '/mount/[literal]\t/safe source\tbind\t\n'; }
append_container_data_targets fixture '/mount/[literal]/data'
printf '%s\n' "${data_values[@]}"
'''
        result = subprocess.run(
            ["bash", "-s"], input=definitions + assertions, text=True,
            capture_output=True, env=self.environment, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["first", "second image", "/safe source/data"])


if __name__ == "__main__":
    unittest.main()
