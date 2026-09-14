#!/usr/bin/env python3
"""Bounded loopback load: stalled handshakes, V8 rejection, oversized frames, recovery."""
import hashlib
import os
from pathlib import Path
import re
import socket
import ssl
import tempfile
import time
from tls_e2e import CLIENT, RELAY, Process, offline, enroll


def receive_exact(stream, length):
    result = b""
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        assert chunk, "unexpected TLS EOF"
        result += chunk
    return result


def run():
    children = []
    sockets = []
    with tempfile.TemporaryDirectory(prefix="grotto-load-") as temporary:
        base = Path(temporary)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            address = reserve.getsockname()
        common = {key: value for key, value in os.environ.items() if not key.startswith("GROTTO_")}
        common["GROTTO_RELAY_ADDRESS"] = f"{address[0]}:{address[1]}"
        environment = dict(common, GROTTO_DATABASE_PATH=str(base / "relay.db"),
                           GROTTO_TLS_CERT_PATH=str(base / "cert.pem"), GROTTO_TLS_KEY_PATH=str(base / "key.pem"),
                           GROTTO_MAX_CONNECTIONS="8", GROTTO_MAX_HANDSHAKES="4",
                           GROTTO_MAX_HANDSHAKES_PER_IP="2", GROTTO_HANDSHAKE_SECONDS="1",
                           GROTTO_PAYLOAD_BYTES=str(4 * 1024 * 1024))
        client_env = dict(common, XDG_DATA_HOME=str(base / "client"))
        card = re.search(r"Contact card: ([0-9a-f]+)", offline(client_env, "--contact-export")).group(1)
        client_env["GROTTO_ENROLLMENT_TOKEN"] = enroll(environment, card)
        try:
            relay = Process(RELAY, environment); children.append(relay)
            fingerprint = relay.wait(r"Relay TLS fingerprint \(sha256\): ([0-9a-f]{64})").group(1)
            client_env["GROTTO_RELAY_FINGERPRINT"] = fingerprint
            fd_path = Path(f"/proc/{relay.process.pid}/fd")
            baseline_fds = len(list(fd_path.iterdir()))
            for _ in range(2):
                for _ in range(40):
                    stream = socket.create_connection(address, timeout=3)
                    stream.settimeout(3)
                    sockets.append(stream)
                assert len(list(fd_path.iterdir())) <= baseline_fds + 8
                time.sleep(1.5)
                for stream in sockets:
                    try:
                        assert stream.recv(1) == b""
                    except ConnectionResetError:
                        pass
                    stream.close()
                sockets.clear()
                assert len(list(fd_path.iterdir())) <= baseline_fds + 2
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(socket.create_connection(address, timeout=3), server_hostname="localhost") as stream:
                assert hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest() == fingerprint
                stream.sendall(b"\x00\x00\x00\x02\x01\x08")
                header = receive_exact(stream, 4)
                length = int.from_bytes(header, "big")
                response = receive_exact(stream, length)
                assert response == bytes([4, 0, 1, 9, 8]), response
            with context.wrap_socket(socket.create_connection(address, timeout=3), server_hostname="localhost") as stream:
                stream.sendall((1024 * 1024 + 1).to_bytes(4, "big"))
                try:
                    assert stream.recv(1) == b""
                except (ConnectionResetError, ssl.SSLError):
                    pass
            status = Path(f"/proc/{relay.process.pid}/status").read_text()
            high_water_kib = int(re.search(r"VmHWM:\s+(\d+)", status).group(1))
            assert high_water_kib < 96 * 1024, high_water_kib
            client = Process(CLIENT, client_env); children.append(client)
            client.wait("Identity accepted")
            client.send("/create after-load")
            client.wait("Room created: after-load")
        finally:
            for stream in sockets:
                stream.close()
            for child in reversed(children):
                child.close()
    print("Bounded load passed: socket admission, deadlines, V8/frame rejection, memory and recovery")


if __name__ == "__main__":
    run()
