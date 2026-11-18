#!/usr/bin/env python3
"""Deterministic command doubles; never invoke real containers or networking."""

import base64
import json
import os
from pathlib import Path
import subprocess
import sys


def curl_response(arguments, state):
    url = next(argument for argument in arguments if argument.startswith("http"))
    payload = {}
    if "--data-binary" in arguments:
        payload_path = arguments[arguments.index("--data-binary") + 1]
        payload = json.loads(Path(payload_path.removeprefix("@")).read_text())

    if url.endswith("/enroll/start"):
        return json.dumps({
            "handshake_id": "handshake with spaces",
            "challenge": base64.b64encode(b"challenge").decode(),
        })
    if url.endswith("/enroll/finish"):
        return (
            "[Interface]\nPrivateKey = client-key\n"
            "Address = 10.88.0.2/32, fd88:88::2/128\n"
            "[Peer]\nPublicKey = server-key\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
        )
    if url.endswith("/api/admin/login"):
        return "{}"
    if url.endswith("/api/admin/clients"):
        return json.dumps({"clients": [{
            "hostname": "client.example.test",
            "id": "client|domain id",
            "domain_id": "domain id",
            "group_ids": ["all", "domain:domain id"],
        }]})
    if url.endswith("/api/admin/groups") and not payload:
        return json.dumps({"groups": [
            {"id": "all", "built_in": True},
            {"id": "domain:domain id", "type": "domain", "built_in": True},
        ]})
    if "/api/admin/domains/" in url:
        state["dns"] = payload["dns_servers"][0]
        return json.dumps({"id": "domain id", **payload})
    if url.endswith("/api/admin/remote-subnets"):
        return json.dumps({"id": payload["name"], **payload})
    if url.endswith("/api/admin/manual-enroll"):
        return json.dumps({
            "hostname": payload["hostname"],
            "config": f"[Interface]\nPrivateKey = manual-key\nDNS = {state['dns']}\n",
        })
    if url.endswith("/api/admin/groups"):
        return json.dumps({"id": payload["name"], **payload})
    if "-w" in arguments:
        Path(arguments[arguments.index("-o") + 1]).write_text("recursive group")
        return "400"
    if "/api/admin/" in url:
        return json.dumps(payload)
    return state.get("curl_body", "ok")


def run_command(command, arguments, state):
    if command == "ip":
        if arguments[:4] == ["-4", "route", "show", "default"]:
            print("default via 192.0.2.1 dev eth-test proto static")
        elif arguments[:3] == ["link", "show", "dev"]:
            return 0 if arguments[3] in state.get("interfaces", []) else 1
        elif arguments[:3] == ["link", "add", "dev"]:
            state.setdefault("interfaces", []).append(arguments[3])
        elif arguments[:3] == ["link", "delete", "dev"]:
            state["interfaces"].remove(arguments[3])
    elif command in ("iptables", "ip6tables"):
        action = next(argument for argument in arguments if argument in ("-A", "-C", "-D"))
        rule = json.dumps([command, *[argument for argument in arguments if argument != action]])
        rules = state.setdefault("rules", {})
        count = rules.get(rule, 0)
        if action == "-C":
            return 0 if count else 1
        rules[rule] = count + (1 if action == "-A" else -1)
    elif command == "cat":
        if arguments[0].startswith("/proc/sys/net/"):
            print("1")
        else:
            sys.stdout.write(Path(arguments[0]).read_text())
    elif command == "wg" and arguments[0] == "show":
        print(state.get("peers", "public-key"))
    elif command == "openssl":
        Path(arguments[arguments.index("-out") + 1]).write_bytes(b"signature")
    elif command == "curl":
        if state.get("curl_fail"):
            return 22
        sys.stdout.write(curl_response(arguments, state))
    elif command == "nc":
        state["http_response"] = sys.stdin.buffer.read().decode()
        return 1  # End an otherwise infinite HTTP loop after one response.
    elif command in ("podman", "docker"):
        shell_source = ""
        if "-i" in arguments or "-f" in arguments:
            shell_source = sys.stdin.read()
        if "sh" in arguments:
            shell_index = arguments.index("sh")
            if arguments[shell_index + 1] == "-lc":
                shell_source = arguments[shell_index + 2]
        if shell_source and not shell_source.startswith("FROM "):
            subprocess.run(["sh", "-n"], input=shell_source, text=True, check=True)
            state["shell_programs"] = state.get("shell_programs", 0) + 1
        if arguments[0] == "inspect":
            if "relaunch_inspect" in state:
                if arguments[1] == "--format":
                    print(state["relaunch_inspect"].get(arguments[2], ""))
            else:
                print("fd89:89::10" if "GlobalIPv6Address" in " ".join(arguments) else "10.231.0.10")
        elif "wg genkey" in shell_source:
            print("server-key")
        elif "htpasswd" in shell_source:
            print("bcrypt-hash")
    elif command not in ("sleep", "sysctl", "wg"):
        raise AssertionError(f"Unexpected stub command: {command}")
    return 0


def main():
    state_path = Path(os.environ["SHELL_TEST_STATE"])
    state = json.loads(state_path.read_text())
    command = Path(sys.argv[0]).name
    arguments = sys.argv[1:]
    state.setdefault("calls", []).append([command, *arguments])
    try:
        return run_command(command, arguments, state)
    finally:
        state_path.write_text(json.dumps(state))


if __name__ == "__main__":
    sys.exit(main())
