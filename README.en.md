# DPI Mesh: Blocking Detection

[English summary — see [README.md](README.md) for the full operator guide in Russian.]

A Zabbix 7.0 monitoring system that detects **directional DPI/RKN blocking**
of your own services. Multiple vantage points (Zabbix server + proxies across
different regions/ISPs, e.g. EU/BY/RU and RU alt-ISP) probe every target in
the `DPI Targets` host group with protocol-aware checks (HTTPS, SMTP/SMTPS,
RDP, RDGW, SSH, WireGuard, OpenVPN).

A separate **aggregator host** (single Zabbix phantom host) reads each
vantage's `dpi.verdict` via `last_foreach(/*/...)` and runs the consensus
layer — calculated items + a 4-tier severity ladder. Each `(target, kind,
port)` produces exactly **one** alert no matter how many vantages observe
the same condition, eliminating the N-times-fire-per-event noise that
per-vantage triggers used to produce.

## Quick start

```bash
# Deploy the probe to a vantage host (one-shot from GitHub):
./deploy/deploy-to.sh <ssh-host> --from-git https://github.com/IT-for-Prof/zabbix-dpi-checker.git main

# Run the probe manually for debugging (as the zabbix user):
runuser -u zabbix -- /usr/lib/zabbix/externalscripts/dpi_probe \
    target-stub https 443 www.example.com www.example.com 10
# → {"verdict":"OK","reason":"TLS handshake completed","latency_ms":253.4,...}
```

## New Probe Kinds

| Kind | Purpose | TSPU signature it catches |
|---|---|---|
| `https-bytes` | Push 64 KB after TLS handshake (interleaved write+read) | `THROTTLE_DETECTED` if RST lands in the 14-34 KB window |
| `tls-frag` | ClientHello in 4-byte TCP segments | Fragmentation bypass signal for SNI-parser DPI |
| `tspu-liveness` | Aggregate canary-SNI probe | `TSPU_ACTIVE` flag per vantage |
| `wg-handshake` | Userspace WireGuard HandshakeInit | `WG_HANDSHAKE_PASS` / `WG_HANDSHAKE_BLOCKED` |

`wg-handshake` requires no kernel WireGuard and no sudo. Configure via
environment variables: `DPI_WG_SERVER_PUB` (server's public key, base64),
`DPI_WG_CLIENT_PRIV` (vantage client private key, base64, use Zabbix Secret macro),
and `DPI_WG_CLIENT_PUB` (vantage client public key, base64). Register
the client public key as a `[Peer]` block on the WireGuard server side.

`tspu-liveness` canary SNIs are configurable via
`DPI_TSPU_LIVENESS_SNIS` (comma-separated). Default:
`rutracker.org,x.com,www.linkedin.com`. Quorum override:
`DPI_TSPU_LIVENESS_QUORUM` (absolute int) or
`DPI_TSPU_LIVENESS_QUORUM_RATIO` (float in (0,1]).

`tspu-liveness` runs at its own cadence `{$DPI.LIVENESS_INTERVAL}`
(default `15m`), separate from `{$DPI.INTERVAL}` (default `5m` for
per-target probes) — the canary SNIs are public sites and we shouldn't
hammer them every 5 minutes from N vantages.

## Components

- `probe/` — stdlib-only Python 3.11+ probe library and CLI.
- `template/dpi-mesh-blocking-detection.yaml` — vantage template: LLD + verdict
  items + per-vantage Info-level stale-data trigger. No severity triggers.
- `template/dpi-mesh-aggregator.yaml` — aggregator template: 4 calc items
  (`dpi.peers_ok`, `dpi.vantages_total`, `dpi.affected`,
  `dpi.discriminator_any`) per (target, kind, port), plus 4 severity-tier
  triggers (gated on `last(dpi.discriminator_any) ≥ 1`) and 1 Info-sentinel
  stale trigger.
- `deploy/` — installer (`install-prober.sh`) and remote-deploy helper
  (`deploy-to.sh`).

## Architecture

```
Vantages (probe layer):                    Aggregator (consensus layer):
  Zabbix server (EU)    ──┐                  Phantom host dpi-mesh-aggregator
  Zabbix proxy  (BY)    ──┤   dpi.verdict      ├─ dpi.peers_ok       (calc)
  Zabbix proxy  (RU)    ──┼──────────────────► ├─ dpi.vantages_total (calc)
  Zabbix proxy  (RU2)   ──┤   per (T,K,P)      ├─ dpi.affected       (calc)
  Zabbix proxy  (RU3)   ──┘                    │
                                               └─ 4 severity tiers + Info stale
                                                  (1 alert per (T,K,P))
```

LLD on every host (vantages and aggregator alike) queries the Zabbix API
under the same scoped read-only `dpi-vantage` user (allow-list: `host.get`,
`hostgroup.get`, `usermacro.get`; no frontend; read access only on the
`DPI Targets` group). Each target's `{$DPI.KINDS}` macro
(e.g. `https:443,smtp:25`) is expanded into one item set per pair.

### Severity ladder (auto-scales with mesh size)

Four calc items on the aggregator drive the ladder:
- `dpi.peers_ok` — vantages reporting verdict `OK`
- `dpi.affected` — vantages reporting any non-OK verdict
- `dpi.vantages_total` — total vantages currently reporting
- `dpi.discriminator_any` — vantages whose verdict is one of the
  HIGH-confidence DPI fingerprints: `DNS_LIE`, `TCP_RST_MID_STREAM`,
  `TLS_RESET_POST_HELLO`, `CERT_MISMATCH`, `HTTP_STUB`

`VANTAGE_UNAVAILABLE` (control-endpoint failure) is LOW confidence and
therefore not in `dpi.discriminator_any` — a single broken vantage can
appear in `dpi.affected` but the discriminator gate keeps it out of the
alert path.

Every consensus tier carries a final `last(dpi.discriminator_any) >= 1` gate,
so a tier fires only when at least one vantage saw an attributable DPI
signature. Bare `PORT_FILTERED` (LOW confidence — ambiguous between RU ISP
outbound :25 anti-spam, target firewall, and other generic drops) is kept in
history for forensics but does **not** page anyone. Debounce is `count(#3,...)=3`
≈ 15 min at default `{$DPI.INTERVAL}=5m`. Tiers are gated by `vantages_total`
to stay mutually exclusive at small mesh sizes:

| Condition (sustained 3 cycles)               | Severity | Meaning                                            |
|----------------------------------------------|:--------:|----------------------------------------------------|
| `affected = 1`, `vantages_total ≥ 2`         | Info     | 1 vantage affected — single-ISP local glitch       |
| `affected = 2`, `vantages_total ≥ 3`         | Warning  | 2 vantages affected — single-region block          |
| `affected ≥ 3`, `peers_ok ≥ 1`, `total ≥ 4`  | Average  | Majority but not all — cross-region block          |
| `peers_ok = 0`                               | High     | All vantages affected — global outage or DPI       |

All four tiers additionally require `discriminator_any ≥ 1` — a real DPI
fingerprint on at least one vantage. Stock per-target service templates
(`Template App HTTPS Service`, `SMTP Service`, `RDP Service`) already
cover plain availability with their own severity, so DPI Mesh deliberately
stays in the supplementary-signal lane: it answers "is this being blocked?",
not "is this up?".

Each trigger ships with **operational data** (`opdata`) shown inline in the
alert list:
- `aff=X/Y dpi=N` (lower tiers) — X affected of Y reporting, N saw DPI fingerprint
- `peers_ok=X/Y dpi=N` ("all affected" tier) — X is always 0 at fire time, useful
  on resolve

Plus a per-vantage Info-level `DPI vantage probe stale` trigger
(diagnostic only, fires when one vantage's probe has been silent for
`{$DPI.NODATA_WINDOW}`, default 1h), and an aggregator-side Info-level
`DPI Mesh stale` sentinel that suppresses the 4 severity tiers if the
aggregator itself freezes.

## Verdict codes

`OK`, `TCP_RST_HANDSHAKE`, `TCP_RST_MID_STREAM`, `TLS_RESET_POST_HELLO`,
`TLS_TIMEOUT`, `CERT_MISMATCH`, `BANNER_MISMATCH`, `REMOTE_HUNGUP_AFTER_CONNECT`,
`VANTAGE_UNAVAILABLE`, `DNS_LIE`, `HTTP_STUB`, `ROUTE_BLACKHOLE`,
`PORT_FILTERED`, `REMOTE_DOWN`, `UDP_BLIND`, `TSPU_ACTIVE`, `TSPU_BYPASS_OK`,
`THROTTLE_DETECTED`, `WG_HANDSHAKE_PASS`, `WG_HANDSHAKE_BLOCKED`,
`ERROR_INTERNAL` — see Russian README for descriptions and typical causes.

Each JSON also carries a `confidence` field (`HIGH` / `MEDIUM` / `LOW`)
derived from the verdict code, useful for routing alerts.

## Development

```bash
python3.11 -m venv .venv-dev && source .venv-dev/bin/activate
pip install pytest ruff mypy pyyaml cryptography
pytest -q && ruff check probe template && mypy --strict probe/lib probe/dpi_probe.py
```

CI runs the same on every push (see `.github/workflows/ci.yml`).

## Roadmap / Detection gaps

After the 2026-05-14 real-environment test session (probes deployed to
all 5 vantages, cross-vantage matrix against rutracker / linkedin /
mullvad.net / 65.21.40.204), 8 blocking classes are NOT yet caught by
the current probe stack, ordered by priority:

| Gap | Why current probes miss it | Closing design |
|---|---|---|
| **Volume-threshold throttle** (first N MB clean, then drop) | `https-bytes` pushes 64 KB max | New `wg-throughput` kind pumping N MB, slope-detect rate cliff |
| **Long-flow heuristic** (flow active > N min triggers DPI) | Probes are stateless single-shot | Persistent-agent mode (architectural — deferred) |
| **Sustained-throughput slowdown** (gradual rate decay) | Probes don't measure rate over time | Covered by `wg-throughput` |
| **Time-of-day rules** (operator schedule-based DPI) | Single snapshot per cycle | 5-min cadence + Grafana aggregation over 24h |
| **Real VPN packet-shape fingerprinting** (size/timing distribution) | Canonical handshake bytes ≠ realistic VPN traffic | Out of scope — replay-driven probe |
| **QUIC blocking** | QUIC kind descoped — crude Initial without RFC 9001 header protection | Future plan with `cryptography` + proper header protection |
| **End-to-end OpenVPN session** (HARD_RESET ≠ TLS done) | First-packet only | New `ovpn-tls-full` kind |
| **Asymmetric path differences** (outbound clean, inbound dropped) | Peer-firewall artifacts mask signal | Echo-server on known endpoint + `wg-data-plane` kind |

### What the current stack DOES catch (validated 2026-05-14)

- ✅ Registry-level IP/domain blocks: `TLS_TIMEOUT` from RU vantages on
  `mullvad.net` / `nordvpn.com` / `protonvpn.com` (vs EU 141 ms)
- ✅ SNI-rule TLS blocks: `TLS_RESET_POST_HELLO` / `TLS_TIMEOUT` on
  `rutracker.org` / `linkedin.com` / `x.com` from RU vantages
- ✅ DNS poisoning via DoH-divergence (`DNS_LIE`)
- ✅ Fragmented-ClientHello bypass (`TSPU_BYPASS_OK`) — caught on 4 of 5
  vantages; one operator catches the fragmentation itself (60%
  probabilistic drop on burst tests)
- ✅ TSPU bytes-counter signature (`THROTTLE_DETECTED`) — methodology
  validated against hyperion-cs (`DPI_THR_BYTES = 64 * 1024`) and
  Runnin4ik (`chunks_count = 16, chunk_size = 4000`)
- ✅ Real WireGuard handshake reachability (`WG_HANDSHAKE_PASS / BLOCKED`)
  — cryptographically validated against WireGuard whitepaper §5.4
  byte-for-byte; round-trip server-side decryption test recovers
  `client_pub` from `encrypted_static`
- ✅ Cross-vantage variance via mesh quorum
- ✅ Per-vantage TSPU-liveness flag — separates "DPI off today" from
  "no DPI on this destination"

### Notable real-environment findings (2026-05-14)

1. **TSPU enforcement is intermittent**. Same canary SNIs from the same
   RU vantage flipped from all-blocked (morning) to all-OK (afternoon)
   within hours. Probes correctly report the current state.
2. **VPN-provider domains are firmly blocked from RU**. `mullvad.net` /
   `nordvpn.com` / `protonvpn.com` show 8+ second TLS timeouts from RU
   while responding in 141 ms from EU.
3. **Per-operator variance is real**. Same SNI blocked on one RU
   operator but reachable on another. Mesh quorum handles this.
4. **Own infrastructure on Hetzner Helsinki passes**. 3 MB sustained
   outbound from RU vantage flowed cleanly — TSPU is destination-list-
   driven; non-VPN-provider ASN + non-default port + not on RKN registry
   = passes.

---

## Credits

Probes are written from scratch in stdlib Python, but the verdict taxonomy
and the layered DNS→TCP→TLS→banner probe pattern were shaped by reading
other open-source DPI checkers (rkn-block-checker, dpi-checkers, dpi-detector,
…) and protocol specs (RFC 5246/8446, MS-RDPBCGR, WireGuard whitepaper,
OpenVPN protocol notes). Full list with direct links: [`CREDITS.md`](CREDITS.md).

## License

MIT — see [LICENSE](LICENSE).
