# Grotto

Grotto is an end-to-end encrypted command-line chat application written in Rust.
It uses MLS for group encryption, TLS for transport, and SQLite for durable
client state and opaque relay delivery.

## Build and try it

Requires Rust/Cargo and Python 3 on Linux.

```sh
cargo build --workspace --locked
python3 scripts/smoke.py --no-build
```

The smoke launcher creates fresh private state for Alice and Bob, starts a local
relay, and opens a room. See [SMOKE_TEST.md](SMOKE_TEST.md) for interactive
messaging, offline recovery, and history commands.

For deployment, enrollment, contact verification, storage configuration, and
resource limits, see [STORAGE.md](STORAGE.md).

## Workspace

- `grotto-protocol`: V9 wire format, bounded framing, and delivery messages.
- `grotto-mls`: MLS library integration.
- `grotto-client`: CLI, verified contacts, encryption, and durable local state.
- `grotto-relay`: TLS delivery service and bounded SQLite worker.

## Verification

```sh
cargo fmt --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
python3 tests/tls_e2e.py
python3 tests/smoke_runner.py
python3 tests/bounded_load.py
python3 tests/tls_concurrency.py
```

The process suites require loopback network access.

## Supported scope

V9 requires fresh databases; older protocols and database formats are rejected
without automatic migration or replacement. Contacts must be independently
verified. One client per identity is supported.

Local databases contain plaintext history and private identity/MLS secrets.
Production local storage is not encrypted. The relay stores opaque messages,
but sees delivery metadata. Ordering assumes an honest relay; a malicious relay
can withhold records or present divergent histories.

Multi-device use, key rotation, automatic retention, and encrypted local storage
are outside the current scope. The test suite is not an independent
cryptographic audit.
