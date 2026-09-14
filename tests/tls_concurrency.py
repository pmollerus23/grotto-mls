#!/usr/bin/env python3
"""Four real V9 CLI clients: concurrent additions and application sends over TLS."""
import os
from pathlib import Path
import re
import socket
import sqlite3
import tempfile
from tls_e2e import CLIENT, RELAY, Process, offline, enroll


def run():
    children = []
    with tempfile.TemporaryDirectory(prefix="grotto-concurrent-") as temporary:
        base = Path(temporary)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            address = f"127.0.0.1:{reserve.getsockname()[1]}"
        common = {key: value for key, value in os.environ.items() if not key.startswith("GROTTO_")}
        common["GROTTO_RELAY_ADDRESS"] = address
        names = ("alice", "bob", "carol", "dave")
        environments = {name: dict(common, XDG_DATA_HOME=str(base / name)) for name in names}
        cards = {name: re.search(r"Contact card: ([0-9a-f]+)\nFingerprint: ([0-9a-f]+)",
                                offline(env, "--contact-export")).groups()
                 for name, env in environments.items()}
        for name, env in environments.items():
            for peer in names:
                if peer != name:
                    offline(env, "--contact-import", *cards[peer])
        relay_env = dict(common, GROTTO_DATABASE_PATH=str(base / "relay.db"),
                         GROTTO_TLS_CERT_PATH=str(base / "cert.pem"), GROTTO_TLS_KEY_PATH=str(base / "key.pem"))
        for name, env in environments.items():
            env["GROTTO_ENROLLMENT_TOKEN"] = enroll(relay_env, cards[name][0])
        try:
            relay = Process(RELAY, relay_env); children.append(relay)
            fingerprint = relay.wait(r"Relay TLS fingerprint \(sha256\): ([0-9a-f]{64})").group(1)
            clients = {}
            for name, env in environments.items():
                env["GROTTO_RELAY_FINGERPRINT"] = fingerprint
                client = Process(CLIENT, env); children.append(client)
                client.wait("Identity accepted")
                clients[name] = client
            for name, requester in (("bob", "alice"), ("carol", "alice"), ("dave", "bob")):
                clients[name].send(f"/contact grant {cards[requester][0][2:34]}")
                clients[name].wait("KeyPackage fetch grant updated")
                clients[name].send("/publish 1")
                clients[name].wait("Published 1 key package")
            clients["alice"].send("/create Concurrent")
            room = clients["alice"].wait(r"Room created: Concurrent \(([0-9a-f]{32})\)").group(1)
            clients["alice"].send(f"/add {room} {cards['bob'][0][2:34]}")
            clients["bob"].wait("Joined room 'Concurrent'", timeout=45)
            clients["alice"].send(f"/add {room} {cards['carol'][0][2:34]}")
            clients["bob"].send(f"/add {room} {cards['dave'][0][2:34]}")
            clients["carol"].wait("Joined room 'Concurrent'", timeout=45)
            clients["dave"].wait("Joined room 'Concurrent'", timeout=45)
            for name in names:
                clients[name].send(f"/send {room} converged-from-{name}")
            for name in names:
                for sender in names:
                    clients[name].wait(f"converged-from-{sender}", timeout=45)
                database = base / name / "grotto/client.db"
                with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
                    rows = connection.execute("SELECT plaintext FROM authenticated_history ORDER BY plaintext").fetchall()
                assert rows == [(f"converged-from-{sender}".encode(),) for sender in names], (name, rows)
            with sqlite3.connect(f"file:{base / 'relay.db'}?mode=ro", uri=True) as connection:
                records = connection.execute("SELECT sequence,record FROM delivery_events ORDER BY sequence").fetchall()
            assert [sequence for sequence, _ in records] == list(range(1, 8))
            assert all(b"converged-from-" not in record for _, record in records)
        finally:
            for child in reversed(children):
                child.close()
    print("TLS concurrency passed: four clients, concurrent adds and sends, one history, ciphertext opacity")


if __name__ == "__main__":
    run()
