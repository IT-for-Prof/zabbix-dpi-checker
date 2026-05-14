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
| `https-bytes` | Push 32 KB after TLS handshake | `THROTTLE_DETECTED` if RST lands in the 14-34 KB window |
| `tls-frag` | ClientHello in 4-byte TCP segments | Fragmentation bypass signal for SNI-parser DPI |
| `tspu-liveness` | Aggregate canary-SNI probe | `TSPU_ACTIVE` flag per vantage |
| `wg-rekey` | Forced fresh WireGuard handshake | `WG_REKEY_PASS` / `WG_REKEY_BLOCKED` |
| `quic` | RFC-9000 Initial packet | `PORT_FILTERED` if QUIC/UDP is dropped |

`wg-rekey` deployment requires `/usr/bin/wg`, passwordless sudo for the
`zabbix` user via `deploy/sudoers.d/dpi-probe`, and per-peer config via
environment variables: `DPI_WG_REKEY_IFACE`, `DPI_WG_REKEY_PEER`,
`DPI_WG_REKEY_ORIG_EP`, `DPI_WG_REKEY_ALLOWED_IPS`,
`DPI_WG_REKEY_KEEPALIVE` (optional, default `25`), and
`DPI_WG_REKEY_PING` (optional AllowedIPs target to force traffic).

`tspu-liveness` canary SNIs are configurable via
`DPI_TSPU_LIVENESS_SNIS` (comma-separated). Default:
`rutracker.org,x.com,www.linkedin.com`.

## Components

- `probe/` — stdlib-only Python 3.11+ probe library and CLI.
- `template/dpi-mesh-blocking-detection.yaml` — vantage template: LLD + verdict
  items + per-vantage Info-level stale-data trigger. No severity triggers.
- `template/dpi-mesh-aggregator.yaml` — aggregator template: 5 calc items
  (`dpi.peers_ok`, `dpi.vantages_total`, `dpi.affected`, `dpi.unavailable`,
  `dpi.discriminator_any`) per (target, kind, port), plus 4 severity-tier
  triggers (gated on `discriminator_any ≥ 1`) and 1 Info-sentinel stale
  trigger.
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
- `dpi.peers_ok` — vantages with verdict `OK`
- `dpi.affected` — vantages with non-OK verdict (excludes `VANTAGE_UNAVAILABLE`)
- `dpi.vantages_total` — total vantages currently reporting
- `dpi.discriminator_any` — count of vantages whose probe extracted a HIGH-confidence DPI fingerprint (TSPU RST source mismatch, TLS-post-Hello reset, RKN HTTP stub, DNS lie, etc.)

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
`TLS_TIMEOUT`, `CERT_MISMATCH`, `BANNER_MISMATCH`, `DNS_LIE`, `HTTP_STUB`,
`ROUTE_BLACKHOLE`, `PORT_FILTERED`, `REMOTE_DOWN`, `UDP_BLIND`,
`ERROR_INTERNAL` — see Russian README for descriptions and typical causes.

Each JSON also carries a `confidence` field (`HIGH` / `MEDIUM` / `LOW`)
derived from the verdict code, useful for routing alerts.

## Development

```bash
python3.11 -m venv .venv-dev && source .venv-dev/bin/activate
pip install pytest ruff mypy pyyaml
pytest -q && ruff check probe template && mypy --strict probe/lib probe/dpi_probe.py
```

CI runs the same on every push (see `.github/workflows/ci.yml`).

## Credits

Probes are written from scratch in stdlib Python, but the verdict taxonomy
and the layered DNS→TCP→TLS→banner probe pattern were shaped by reading
other open-source DPI checkers (rkn-block-checker, dpi-checkers, dpi-detector,
…) and protocol specs (RFC 5246/8446, MS-RDPBCGR, WireGuard whitepaper,
OpenVPN protocol notes). Full list with direct links: [`CREDITS.md`](CREDITS.md).

## License

MIT — see [LICENSE](LICENSE).
