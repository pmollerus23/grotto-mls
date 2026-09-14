#!/usr/bin/env python3
"""Exercise the interactive launcher itself, including both chat directions."""
import os
from pathlib import Path
import shutil
import sys

from tls_e2e import Process, ROOT


def run():
    process = Process(sys.executable, os.environ.copy(),
                      [str(ROOT / "scripts/smoke.py"), "--no-build"])
    directory = None
    try:
        directory = Path(process.wait(r"Fresh local smoke-test state: (.+)").group(1))
        process.wait("Room ready:", timeout=60)
        process.send("alice hello-from-alice")
        process.wait(r"\[bob\].*hello-from-alice")
        process.send("bob hello-from-bob")
        process.wait(r"\[alice\].*hello-from-bob")
        process.send("offline bob")
        process.wait("bob is offline")
        process.send("alice while-bob-is-away")
        process.wait(r"\[alice\].*while-bob-is-away")
        process.send("online bob")
        process.wait(r"\[bob\].*while-bob-is-away")
        start = len(process.lines)
        process.send("history bob")
        process.wait(r"\[bob\].*hello-from-alice", start)
        process.wait(r"\[bob\].*while-bob-is-away", start)
        process.send("quit")
        assert process.process.wait(timeout=15) == 0
    finally:
        process.close()
        if directory is not None:
            shutil.rmtree(directory)
    print("Interactive smoke runner passed: both senders, offline recovery, history, clean shutdown")


if __name__ == "__main__":
    run()
