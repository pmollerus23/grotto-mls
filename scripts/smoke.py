#!/usr/bin/env python3
"""Run two real TLS clients locally from one interactive console."""
import argparse
import os
from pathlib import Path
import re
import socket
import signal
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from tls_e2e import CLIENT, RELAY, Process, offline, enroll  # noqa: E402


def interrupted(_signal, _frame):
    raise KeyboardInterrupt


def run():
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true", help="use existing debug binaries")
    args = parser.parse_args()
    if not args.no_build:
        subprocess.run(["cargo", "build", "--workspace", "--locked"], cwd=ROOT, check=True)
    # Retain state for inspection; never open or replace the user's normal databases.
    base = Path(tempfile.mkdtemp(prefix="grotto-smoke-"))
    print(f"Fresh local smoke-test state: {base}", flush=True)
    print("V9 ordered delivery with private enrollment and verified contacts.", flush=True)
    common = {key: value for key, value in os.environ.items() if not key.startswith("GROTTO_")}
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        common["GROTTO_RELAY_ADDRESS"] = f"127.0.0.1:{reserve.getsockname()[1]}"
    environments = {name: dict(common, XDG_DATA_HOME=str(base / name)) for name in ("alice", "bob")}
    cards = {}
    for name, environment in environments.items():
        output = offline(environment, "--contact-export")
        match = re.search(r"Contact card: ([0-9a-f]+)\nFingerprint: ([0-9a-f]+)", output)
        if not match:
            raise RuntimeError(f"could not export {name}'s contact")
        cards[name] = match.groups()
    # Both identities were generated locally by this runner: relay is not the trust source.
    offline(environments["alice"], "--contact-import", *cards["bob"])
    offline(environments["bob"], "--contact-import", *cards["alice"])
    clients = {}
    relay = None
    stop = threading.Event()
    display = None
    lock = threading.Lock()
    positions = {}
    try:
        relay_env = dict(common, GROTTO_DATABASE_PATH=str(base / "relay.db"),
                         GROTTO_TLS_CERT_PATH=str(base / "cert.pem"),
                         GROTTO_TLS_KEY_PATH=str(base / "key.pem"))
        for name, environment in environments.items():
            environment["GROTTO_ENROLLMENT_TOKEN"] = enroll(relay_env, cards[name][0])
        relay = Process(RELAY, relay_env)
        fingerprint = relay.wait(r"Relay TLS fingerprint \(sha256\): ([0-9a-f]{64})").group(1)
        for name, environment in environments.items():
            environment["GROTTO_RELAY_FINGERPRINT"] = fingerprint
            clients[name] = Process(CLIENT, environment)
            clients[name].wait("Identity accepted")
        clients["bob"].send(f"/contact grant {cards['alice'][0][2:34]}")
        clients["bob"].wait("KeyPackage fetch grant updated")
        clients["bob"].send("/publish 4")
        clients["bob"].wait("Published 4 key package")
        clients["alice"].send("/create Smoke")
        room = clients["alice"].wait(r"Room created: Smoke \(([0-9a-f]{32})\)").group(1)
        clients["alice"].send(f"/add {room} {cards['bob'][0][2:34]}")
        print("Waiting for Bob's automatic Welcome sync (up to 30 seconds)…", flush=True)
        clients["bob"].wait("Joined room 'Smoke'", timeout=45)
        positions.update({name: len(client.lines) for name, client in clients.items()})
        print(f"Room ready: {room}\n"
              "alice hello       send as Alice\n"
              "bob hello         send as Bob\n"
              "history alice     read Alice's authenticated local history\n"
              "offline bob       stop Bob; Alice can send while he is offline\n"
              "online bob        restart Bob with the same state and recover messages\n"
              "quit              stop all processes; retain files for inspection\n", flush=True)

        def show_output():
            while not stop.wait(0.1):
                with lock:
                    for name, client in clients.items():
                        end = len(client.lines)
                        for line in client.lines[positions.get(name, 0):end]:
                            print(f"[{name}] {line}", flush=True)
                        positions[name] = end

        display = threading.Thread(target=show_output, daemon=True)
        display.start()
        for line in sys.stdin:
            command, _, argument = line.strip().partition(" ")
            if command in ("quit", "exit"):
                break
            with lock:
                if command in environments:
                    if command not in clients:
                        print(f"{command} is offline", flush=True)
                    elif argument:
                        clients[command].send(f"/send {room} {argument}")
                elif command == "history" and argument in clients:
                    clients[argument].send(f"/history {room}")
                elif command == "offline" and argument in clients:
                    clients.pop(argument).close()
                    print(f"{argument} is offline", flush=True)
                elif command == "online" and argument in environments and argument not in clients:
                    client = Process(CLIENT, environments[argument])
                    clients[argument] = client
                    positions[argument] = 0
                    client.wait("Identity accepted")
                elif command:
                    print("Use alice TEXT, bob TEXT, history NAME, offline NAME, online NAME, or quit.", flush=True)
    finally:
        stop.set()
        if display:
            display.join(timeout=5)
        for client in clients.values():
            client.close()
        if relay:
            relay.close()
        print(f"Processes stopped. State retained at {base}", flush=True)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        pass
