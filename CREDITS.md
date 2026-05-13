# Credits & References

This project's design and protocol probes draw on the following specifications
and open-source prior art. The code itself is original (probes are stdlib-only
Python written from scratch); this file credits sources that informed the
design.

## Protocol specifications

- **TLS 1.2 / 1.3** — [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) and
  [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446). Used by `probe_https.py`
  and `probe_smtp.py` (`smtps` kind) for ClientHello / handshake detection.
- **SMTP** — [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321). Banner format
  used by `probe_smtp.py`.
- **SSH** — [RFC 4253 §4.2](https://www.rfc-editor.org/rfc/rfc4253#section-4.2).
  Banner format and version-string handling used by `probe_ssh.py`.
- **RDP (X.224 Connection Request)** —
  [MS-RDPBCGR §2.2.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10).
  Connection request format used by `probe_rdp.py`.
- **RD Gateway over TLS** —
  [MS-TSGU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/0007d661-a86d-4e8f-89f7-7f77f8824188).
  TLS handshake test used by `probe_rdgw.py`.
- **WireGuard** —
  [Donenfeld, "WireGuard: Next Generation Kernel Network Tunnel"](https://www.wireguard.com/papers/wireguard.pdf),
  §5.4 Handshake Initiation. Packet format used by `probe_wireguard.py`. See
  the caveat in `README.md` about MAC1 validation without a known server pubkey.
- **OpenVPN** — protocol notes in the
  [OpenVPN community wiki](https://community.openvpn.net/openvpn/wiki/SecurityOverview).
  `P_CONTROL_HARD_RESET_CLIENT_V2` packet used by `probe_openvpn.py`.
- **DNS over HTTPS (DoH)** — [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484).
  Referenced in the `DNS_LIE` verdict semantics (resolver disagreement signal).

## Zabbix

- [Zabbix 7.0 documentation](https://www.zabbix.com/documentation/7.0/en/manual) —
  template format, LLD JavaScript preprocessing, External check item type,
  trigger expression syntax, calculated items and `count_foreach` /
  `last_foreach` aggregates.
- The deployed template uses Zabbix's
  [host.get API](https://www.zabbix.com/documentation/7.0/en/manual/api/reference/host/get)
  to discover targets and is exported via
  [configuration.export](https://www.zabbix.com/documentation/7.0/en/manual/api/reference/configuration/export).

## Open-source DPI checkers that informed the verdict taxonomy

The probe's `VerdictCode` enum (RST-during-handshake, RST-mid-stream,
TLS-reset-after-ClientHello, port-filtered, banner-mismatch, …) was shaped by
reading the source of several prior tools. No code was copied; the projects
below are credited for validating which DPI signatures are observable in
practice.

- [MayersScott/rkn-block-checker](https://github.com/MayersScott/rkn-block-checker) —
  layered DNS→TCP→TLS→HTTP probe pattern, DoH-vs-system resolver comparison,
  confidence levels, stub-page body markers. Python.
- [hyperion-cs/dpi-checkers](https://github.com/hyperion-cs/dpi-checkers) —
  TCP 16-20K active-probe methodology (planned future enhancement). Go + JS.
- [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector) —
  detailed DNS+TLS+TCP test sequence. Python async.
- [vernette/censorcheck](https://github.com/vernette/censorcheck) —
  HTTP status-code-only check (used as a baseline contrast). Bash.
- [LL33ch/dpi-rip](https://github.com/LL33ch/dpi-rip) —
  Cloudflare `cdn-cgi/trace` exit-point check (idea for VPN diagnostics
  out-of-scope here). TypeScript / Next.js.
- [LordArrin/openwrt-dpi-checker](https://github.com/LordArrin/openwrt-dpi-checker) —
  `tcpdump`-based RST capture. Bash. (We use `ConnectionResetError` at the
  syscall level instead, which is observationally equivalent without root.)

## Operational concepts

- "Vantage point" / mesh-probe pattern for distinguishing directional blocking
  from service outage — common in network-measurement research; see e.g.
  [OONI](https://ooni.org/) and the
  [Censored Planet](https://censoredplanet.org/) project's methodology.
- The quorum trigger expression (one vantage sees non-OK while ≥ N peers see
  OK) is a basic application of distributed-observation consensus to
  monitoring; see also Zabbix's own discussion of
  [aggregate functions across hosts](https://www.zabbix.com/documentation/7.0/en/manual/config/items/itemtypes/calculated/aggregate).
