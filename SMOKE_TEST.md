# Local chat smoke test

From the repository root, run:

```sh
python3 scripts/smoke.py
```

Requires Rust/Cargo and Python 3 on Linux. The launcher builds with the lockfile,
starts a loopback TLS relay, creates fresh Alice and Bob identities, exchanges
and verifies their contact cards locally, pins the relay certificate, privately enrolls both identities, grants package access, and adds
Bob to a room. Wait for `Room ready` (Welcome synchronization can take 30 seconds).
It never opens your normal client or relay databases.

Type these commands interactively, waiting for the receiving client's output:

```text
alice hello Bob
bob hello Alice
history bob
offline bob
alice this should arrive when you return
online bob
history bob
quit
```

`alice TEXT` and `bob TEXT` send through separate real MLS clients. `[alice]` and
`[bob]` label each client's output. `history NAME` reads that client's saved
history. `offline NAME` stops that client; `online NAME` starts it with the same
identity/database and recovers pending traffic. The launcher controls offline/online restarts. Clients also reconnect automatically
after transient network failures or a relay restart.

`quit`, Ctrl-C, or EOF stops the child processes. The printed temporary directory
is retained for inspection. It contains plaintext local histories and identity
secrets and uses owner-only permissions. Remove that specific directory when
finished. Each new invocation creates another fresh environment. Use
`--no-build` to skip building after a successful workspace build.

For automated verification:

```sh
cargo test --workspace --locked
python3 tests/tls_e2e.py
python3 tests/smoke_runner.py
python3 tests/tls_concurrency.py
python3 tests/bounded_load.py
```

The TLS suite checks messaging, history, restart, offline recovery, and absence
of known message plaintext in relay ciphertext rows. The launcher regression
also exercises both senders and the commands above. Automated tests clean up
all their state and child processes.

## Release status

The wire protocol is **V9**. Conditional ordered appends, pending-commit conflict
rebuild, private enrollment, authorized package allocation, and cursor recovery
are implemented. The four-client TLS suite exercises concurrent membership
changes and sends. See [README.md](README.md) for verification commands and
[STORAGE.md](STORAGE.md) for real-user setup, storage policies, and limits.

Contact pins must be independently verified when communicating with actual
people; this local launcher verifies its own freshly generated identities.

Existing databases are never migrated. Relay databases must be in a private
0700 directory, with a 0600 regular file; unsupported schemas are rejected. TLS
certificate/key files must be regular 0600 files. An incomplete TLS identity is
rejected rather than replaced.
