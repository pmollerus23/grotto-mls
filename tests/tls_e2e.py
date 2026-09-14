#!/usr/bin/env python3
"""TLS-backed CLI regression using fresh private state and independently pinned contacts.

Run after `cargo build --workspace --locked`. All child processes are reaped.
This covers restart/offline/history/opacity, not concurrent commit convergence.
"""
import os
import hashlib
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "target/debug/grotto-client"
RELAY = ROOT / "target/debug/grotto-relay"


class Process:
    def __init__(self, executable, env, arguments=()):
        self.process = subprocess.Popen([str(executable), *arguments], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, env=env, bufsize=1)
        self.lines = []
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        for line in self.process.stdout:
            self.lines.append(line.rstrip())

    def send(self, line):
        self.process.stdin.write(line + "\n")
        self.process.stdin.flush()

    def wait(self, pattern, start=0, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for line in self.lines[start:]:
                found = re.search(pattern, line)
                if found:
                    return found
            if self.process.poll() is not None:
                raise AssertionError(f"process exited while waiting for {pattern}: {self.lines}")
            time.sleep(0.02)
        raise AssertionError(f"timeout waiting for {pattern}: {self.lines}")

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        self.process.stdin.close()
        self.process.stdout.close()


def offline(env, *arguments):
    return subprocess.run([str(CLIENT), *arguments], env=env, check=True,
                          capture_output=True, text=True, timeout=15).stdout


def enroll(relay_env, card):
    raw = bytes.fromhex(card)
    output = subprocess.run([str(RELAY), "--enroll", raw[1:17].hex(),
                             hashlib.sha256(raw[17:49]).hexdigest()],
                            env=relay_env, check=True, capture_output=True, text=True, timeout=15).stdout
    return re.search(r"Enrollment token: ([0-9a-f]{64})", output).group(1)


def run():
    children = []
    with tempfile.TemporaryDirectory(prefix="grotto-e2e-") as temporary:
        base = Path(temporary)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            address = f"127.0.0.1:{reserve.getsockname()[1]}"
        common = {key: value for key, value in os.environ.items()
                  if not key.startswith("GROTTO_")}
        common["GROTTO_RELAY_ADDRESS"] = address
        alice_env = dict(common, XDG_DATA_HOME=str(base / "alice"))
        bob_env = dict(common, XDG_DATA_HOME=str(base / "bob"))
        alice_card = offline(alice_env, "--contact-export")
        bob_card = offline(bob_env, "--contact-export")
        cards = [re.search(r"Contact card: ([0-9a-f]+)\nFingerprint: ([0-9a-f]+)", output).groups()
                 for output in (alice_card, bob_card)]
        offline(alice_env, "--contact-import", *cards[1])
        offline(bob_env, "--contact-import", *cards[0])
        bob_id = cards[1][0][2:34]
        try:
            relay_env = dict(common, GROTTO_DATABASE_PATH=str(base / "relay.db"),
                             GROTTO_TLS_CERT_PATH=str(base / "cert.pem"),
                             GROTTO_TLS_KEY_PATH=str(base / "key.pem"))
            alice_env["GROTTO_ENROLLMENT_TOKEN"] = enroll(relay_env, cards[0][0])
            bob_env["GROTTO_ENROLLMENT_TOKEN"] = enroll(relay_env, cards[1][0])
            relay = Process(RELAY, relay_env)
            children.append(relay)
            fingerprint = relay.wait(r"Relay TLS fingerprint \(sha256\): ([0-9a-f]{64})").group(1)
            alice_env["GROTTO_RELAY_FINGERPRINT"] = fingerprint
            bob_env["GROTTO_RELAY_FINGERPRINT"] = fingerprint
            alice = Process(CLIENT, alice_env); children.append(alice)
            bob = Process(CLIENT, bob_env); children.append(bob)
            alice.wait(r"Identity accepted")
            bob.wait(r"Identity accepted")
            bob.send(f"/contact grant {cards[0][0][2:34]}")
            bob.wait("KeyPackage fetch grant updated")
            bob.send("/publish 1")
            bob.wait(r"Published 1 key package")
            alice.send("/create E2E")
            room = alice.wait(r"Room created: E2E \(([0-9a-f]{32})\)").group(1)
            alice.send(f"/add {room} {bob_id}")
            bob.wait(r"Joined room 'E2E'", timeout=45)
            alice.send(f"/send {room} authenticated-online-body")
            bob.wait(r"authenticated-online-body")
            for _ in range(2):
                start = len(bob.lines)
                bob.send(f"/history {room}")
                bob.wait(r"authenticated-online-body", start)
            bob.close(); children.remove(bob)
            alice.send(f"/send {room} authenticated-offline-body")
            # Read only the relay's opaque records to wait for durable delivery.
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                with sqlite3.connect(base / "relay.db") as connection:
                    bodies = [row[0] for row in connection.execute("SELECT record FROM delivery_events")]
                if len(bodies) >= 3:
                    break
                time.sleep(0.02)
            else:
                raise AssertionError("offline message was not durably appended")
            assert all(b"authenticated-online-body" not in blob and
                       b"authenticated-offline-body" not in blob for blob in bodies)
            bob = Process(CLIENT, bob_env); children.append(bob)
            bob.wait(r"authenticated-offline-body")
            start = len(bob.lines)
            bob.send(f"/history {room}")
            bob.wait(r"authenticated-online-body", start)
            bob.wait(r"authenticated-offline-body", start)
            # Real automatic reconnect: both clients stay alive across relay restart.
            alice_start, bob_start = len(alice.lines), len(bob.lines)
            relay.close(); children.remove(relay)
            relay = Process(RELAY, relay_env); children.append(relay)
            relay.wait(r"Relay TLS fingerprint")
            alice.wait("Identity accepted", alice_start, timeout=45)
            bob.wait("Identity accepted", bob_start, timeout=45)
            alice_start = len(alice.lines)
            bob.send(f"/send {room} after-relay-reconnect")
            alice.wait("after-relay-reconnect", alice_start)
        finally:
            for child in reversed(children):
                child.close()
    print("TLS E2E passed: verified contacts, messaging, history, restart, offline delivery, automatic reconnect, opacity")


if __name__ == "__main__":
    run()
