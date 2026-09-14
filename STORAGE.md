# V9 storage and operation

## Fresh state only

V9 rejects old protocols and database formats. Client and relay use schema 9
with application IDs `0x4752433a` and `0x4752523a`, respectively. Earlier
provisional schema 9 files are also rejected. There are no migrations and no
automatic database replacement. Use a new private directory for this release;
preserve any older database separately if you need its contents.

On Linux, defaults are `$XDG_DATA_HOME/grotto/client.db` and
`$XDG_DATA_HOME/grotto-relay/relay.db`; absent XDG_DATA_HOME, use
`$HOME/.local/share`. Relay TLS cert/key live beside its default database.
Overrides: `GROTTO_CLIENT_DB_PATH`, `GROTTO_RELAY_PIN_PATH`,
`GROTTO_DATABASE_PATH`, `GROTTO_TLS_CERT_PATH`, `GROTTO_TLS_KEY_PATH`.
`GROTTO_MLS_DB_PATH` and legacy split client identity/MLS files are rejected.

Database parents must be owned by the current user and mode 0700. Database,
lock-bearing files, pins, and TLS identity files must be regular owner-only
0600 files. Creation uses those modes from the outset. Symlinks, unsafe
ancestors/sidecars, and incomplete TLS identities fail closed. A lifetime file
lock prevents simultaneous opens. Run only one client per identity; the relay
also rejects a second authenticated session until the first has fully closed.

## Private enrollment and contacts

Build with `cargo build --workspace --locked`. Each participant first runs:

```sh
./target/debug/grotto-client --contact-export
```

This works offline and prints a signed contact card, its fingerprint, user ID,
and the transport-key fingerprint needed for enrollment. Keep the same client
state directory for subsequent commands. Exchange cards and verify their card
fingerprints through an independent trusted channel, then import:

```sh
./target/debug/grotto-client --contact-import CARD INDEPENDENT_CARD_FINGERPRINT
```

Every member must import every other member before processing their group.
Changed keys never overwrite a pin. `/contacts` lists pins; `/contact export`
and `/contact import CARD FINGERPRINT` are the connected equivalents.

The operator uses the intended user's transport-key fingerprint, independently
verified with that user, to issue enrollment from the relay state directory:

```sh
./target/debug/grotto-relay --enroll USER_ID TRANSPORT_KEY_FINGERPRINT
```

The command prints one secret enrollment token. Store/transmit it privately.
Only its hash is saved. It expires after 24 hours and is consumed atomically
with registration after proof of key possession. Wrong user/key bindings,
expired tokens, and reused tokens cannot enroll a new identity. Existing
registered identities authenticate without another token.

The operator command requires exclusive database access: stop the relay, issue
tokens using the same path configuration, then restart it. Connected clients
reconnect automatically. To start the relay:

```sh
./target/debug/grotto-relay
```

The default listener is loopback. Set `GROTTO_RELAY_ADDRESS=HOST:PORT` on relay
and clients as needed. The relay prints its SHA-256 TLS certificate fingerprint.
Verify it independently and set `GROTTO_RELAY_FINGERPRINT` on clients; absent an
explicit pin, first use records a TOFU pin and subsequent changes fail closed.
Supply the issued token as `GROTTO_ENROLLMENT_TOKEN` for the client's first
connection. Avoid putting literal tokens in saved shell history.

Bob authorizes Alice to reserve a KeyPackage:

```text
/contact grant ALICE_USER_ID
/publish 4
```

Alice creates and populates a room:

```text
/create Cave
/add ROOM_ID BOB_USER_ID
/send ROOM_ID hello Bob
/history ROOM_ID
```

Bob can `/contact revoke ALICE_USER_ID` to stop new allocations. Existing
allocations remain stable for exact retries. Allocation limits are four per
requester/recipient pair per hour, sixteen per recipient per hour, and a reserve
pool of at most 64 packages. An allocated package never returns to the pool.
Every verified MLS member may add another verified contact; the old relay role,
owner, invitation, leave, and removal commands are absent from V9.

## Durability and privacy

The client database contains plaintext authenticated history **and private
identity/MLS secrets**. Protect it and its backups as secret material. The
client's dependency graph enables bundled SQLCipher and tests explicit keyed
storage, including rejection of a wrong passphrase. Production SQLite opens
without a key, so this does **not** encrypt client.db. A standalone relay build
does not enable SQLCipher. Encrypted local storage is outside this release.

Relay events are opaque MLS records. Relay metadata includes user IDs, room
names, subscription relationships, timing, sizes, and signed Welcome descriptors.
The relay cannot decrypt application bodies. Ordering assumes an honest relay;
a malicious relay can withhold or fork history despite independent key pins.

There is no automatic retention, message deletion, key rotation, or multi-device
support. ACKs do not remove events, Welcomes, or idempotency results. Local
history reads never advance MLS state or processing cursors. Runtime database files are excluded from version control.

## Resource limits

Limits reject new writes rather than deleting existing data. Relay admission
runs in the mutation transaction and accounts conservatively for request/result
rows, indexes, bodies, and Welcome copies. Sender/room ledgers avoid full-history
scans. Physical checks include SQLite pages, WAL size, and available filesystem
space. The recovery reserve keeps space available for receipts; retries of
existing results and recovery reads bypass new-data admission.

| Setting | Default |
| --- | ---: |
| GROTTO_MAX_CONNECTIONS | 128 |
| GROTTO_MAX_HANDSHAKES | 16 |
| GROTTO_MAX_HANDSHAKES_PER_IP | 4 |
| GROTTO_HANDSHAKE_SECONDS | 10 |
| GROTTO_FRAME_SECONDS | 15 after first byte |
| GROTTO_WRITE_SECONDS | 10 |
| GROTTO_PAYLOAD_BYTES | 67108864 (64 MiB) |
| GROTTO_DATABASE_QUEUE | 128 |
| GROTTO_REQUESTS_PER_SECOND | 20 |
| GROTTO_REQUEST_BURST | 40 |
| GROTTO_STORAGE_GLOBAL_BYTES | 1073741824 (1 GiB) |
| GROTTO_STORAGE_SENDER_BYTES | 104857600 (100 MiB) |
| GROTTO_STORAGE_ROOM_BYTES | 104857600 (100 MiB) |
| GROTTO_RECOVERY_RESERVE_BYTES | 67108864 (64 MiB) |
| GROTTO_CLIENT_STORAGE_BYTES | 1073741824 (1 GiB) |

The connection working-payload budget is 2 MiB, acquired before frame allocation
and retained through queued database work and output. It is part of the global
payload budget; TLS/library/process overhead is additional. Room creation is
limited to 64 per identity. Pages contain at most 100 records and fit the
768 KiB serialized payload cap. Each MLS blob is at most 512 KiB and each package
16 KiB. Local storage has a fixed additional 64 MiB SQLite recovery allowance.
When full, increase the configured budget or move the entire stopped state to
larger storage; no records are silently pruned.

Clients periodically synchronize every 30 seconds and retry transient network
failures with jittered exponential backoff of 1–30 seconds. Authentication,
protocol, pin, schema, and unsafe-file failures require operator attention.
SIGINT/SIGTERM shut down the relay's supervised sessions. Structured `grotto_*`
metric lines report queue pressure, timeouts, quota rejections, blocked processing,
commit conflicts, and recovery failures. Logs exclude message bodies, private
keys, and enrollment tokens (except explicit token issuance output).
