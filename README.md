# AltNet

A peer-to-peer alternative internet. Sites live under the **`.alt`**
namespace and are served by the peers that hold them — not by any central
server. Run a node, and you can resolve and serve `name.alt` content
straight from the network.

`.alt` is reserved by the IETF (**RFC 9476**) for non-DNS namespaces, so
AltNet names never collide with the regular internet.

This repository is the **protocol and node** — the network layer, written
in Go with the standard library only (plus the Go crypto packages). The
desktop client (AltNet Studio) and the account/registration backend are
separate and not part of this repo.

## Features

- **Kademlia DHT** — distributed routing and content storage.
- **Ed25519 identities** — every peer is a keypair; the node ID derives
  from the public key.
- **Encrypted transport** — X25519 key exchange + AES-256-GCM; all traffic
  authenticated.
- **Content addressing** — files are split into chunks and stored by
  SHA-256 hash, so tampering is detectable and identical content dedupes.
- **Signed naming** — a `name → content-root` record signed by its owner,
  with versioning and TTL-based expiry.
- **Permissioned naming (optional)** — when a node is configured with a
  trusted-registrar authority key, it only resolves names signed by that
  authority. Empty by default (open, first-writer naming).
- **Signed revocation** — a trusted authority can broadcast a signed
  `dht_revoke` that purges a name's chunks from nodes network-wide.
- **Content blocklist** — nodes refuse to store or serve known-bad content
  hashes.
- **Relay / NAT traversal** — nodes behind home routers register with a
  relay so other peers can reach them.
- **HTTP & HTTPS gateways** — browse `*.alt` with any browser; HTTPS uses a
  per-install local CA constrained to `.alt`.
- **DNS resolver** — captures `.alt` and forwards everything else upstream.
- **Registrar API** — authenticated HTTP endpoints to publish content,
  register/update/revoke names, and read per-site stats.
- **Durability** — persistent on-disk store with LRU eviction, periodic
  republish, multi-bootstrap, auto-reconnect, and dead-peer pruning.

## Build

Requires Go 1.26+.

```sh
go build -o altnet ./cli      # add .exe on Windows
```

## Run a node

```sh
./altnet -listen 0.0.0.0:9000 \
         -gateway 127.0.0.1:8080 \
         -dns 127.0.0.1:5353 \
         -data data/store -keydir data/keys \
         -headless
```

Join an existing network by bootstrapping to a known peer:

```sh
./altnet -listen 0.0.0.0:9001 -bootstrap host:9000 \
         -data data/store2 -keydir data/keys2 -headless
```

Run `./altnet` without `-headless` for an interactive REPL (`help`, `put`,
`get`, `resolve`, `publish`, `register`, `stats`, …). To browse `*.alt` in
a real browser, route `.alt` DNS at the node's `-dns` address (e.g. a
Windows NRPT rule, a systemd-resolved drop-in, or an `/etc/hosts` entry)
and visit `http://name.alt/` through the gateway.

Useful flags: `-relay-listen` (run a relay), `-relay` (use relays),
`-registrar`/`-registrar-token` (registrar API), `-gateway-tls`/`-ca-dir`
(HTTPS), `-metrics`, `-public`. See `./altnet -h` for the full list.

## Permissioned naming & revocation

The node reads two optional files from its data dir:

- `trusted-registrars.txt` — one Ed25519 **public key** (hex) per line.
  If non-empty, only names signed by one of these authorities resolve.
- `trusted-revokers.txt` — authority keys whose signed `dht_revoke`
  messages this node honors (purge + blocklist the named content).

This is how an operator runs a gatekept network (only approved names
resolve, takedowns propagate) while the code stays fully open — security
rests on the authority's private key, never on the code.

## Layout

```
core/
  peer/    P2P node: TCP listener, framed messaging, dispatch
  secure/  encrypted, authenticated transport
  crypto/  Ed25519 identities, signatures, key persistence
  dht/     Kademlia DHT, store, maintenance, blocklist, revocation
  name/    signed name records (name -> content root)
  relay/   relay client + server for NAT traversal
apps/
  files/      chunking + directory publish/fetch
  gateway/    HTTP/HTTPS server (browse by Host header)
  dns/        UDP .alt resolver
  registrar/  authenticated registration/publish/revoke API
  altca/      per-install local CA, Name-Constrained to .alt
  metrics/    JSON node-status endpoint
  sitestats/  per-site request stats
cli/         daemon entry point wiring it all together
```

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
