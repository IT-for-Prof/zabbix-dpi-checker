# Deploy dpi_probe to a Zabbix vantage host

Three equivalent ways to install the probe on a new vantage:

## 1. One-shot from GitHub (recommended)

From a workstation with SSH access to the target:

```bash
./deploy/deploy-to.sh <ssh-host> --from-git https://github.com/IT-for-Prof/zabbix-dpi-checker.git main
```

Or directly on the target (no workstation needed):

```bash
ssh root@<host>
curl -fsSL https://raw.githubusercontent.com/IT-for-Prof/zabbix-dpi-checker/main/deploy/install-prober.sh \
  | sudo bash -s -- --from-git https://github.com/IT-for-Prof/zabbix-dpi-checker.git main
```

## 2. rsync from a local checkout

```bash
./deploy/deploy-to.sh <ssh-host>
```

Does rsync + ssh + run-installer in one command. Useful when iterating on changes
that aren't pushed yet.

## 3. Manual on the target host

```bash
ssh root@<host>
git clone https://github.com/IT-for-Prof/zabbix-dpi-checker.git /tmp/dpi-checker
sudo /tmp/dpi-checker/deploy/install-prober.sh /tmp/dpi-checker
```

## What the installer does

1. Installs `python3.11`+ (`dnf` on RHEL-family, `apt-get` on Debian-family).
   Accepts 3.11/3.12/3.13 — picks the first found.
2. Creates `/opt/dpi-probe/venv` (stdlib only, no pip packages).
3. Deploys `probe/` into `/opt/dpi-probe/`.
4. Symlinks `/usr/lib/zabbix/externalscripts/dpi_probe` → `/opt/dpi-probe/dpi_probe`.
   Script bootstraps `sys.path` internally; no wrapper, no `PYTHONPATH`.
5. **Enforces `root:zabbix 0750` ownership on every run** — re-applied each time
   so drift gets corrected automatically.
6. Smoke-tests as `runuser -u zabbix --` — proves the zabbix user can execute the
   probe end-to-end. Aborts the install if not.

Every run appends to `/var/log/dpi-probe/install.log` for post-mortem.

## Idempotence

Re-running the installer is safe and is the canonical upgrade path. The installer:
- Skips Python install if `python3.11+` is already present.
- Reuses the existing venv if its Python version is acceptable.
- Overwrites probe files (no in-place migration — the install is the deliverable).
- Re-applies permissions every run.

## Required prerequisites on the target

- Linux with `systemd` (RHEL 8+/Debian 11+/Ubuntu 22.04+).
- `zabbix` user and group (installed by `zabbix-agent` or `zabbix-proxy`).
- Network access to apt/dnf mirrors **and** to GitHub (for `--from-git` flow).
- Root SSH access (for `deploy-to.sh`) or local sudo.

## After install: wire up the host in Zabbix

The probe binary alone does nothing — Zabbix has to invoke it. On each vantage:

1. Link the **DPI Mesh: Blocking Detection** template to the host.
2. Set the only required host macro:
   - `{$DPI.API_TOKEN}` (**Secret** type) — API token issued under a dedicated
     read-only `dpi-vantage` user (see the main README for role/user setup).
     One token per vantage, for blast-radius isolation and audit.
   - Optional overrides if the defaults don't fit:
     - `{$DPI.API_URL}` — override if Zabbix frontend lives at a different URL or
       this vantage has a faster internal path.
     - `{$DPI.SELF_TARGETS}` — regex of DNS names this vantage itself hosts
       (excludes them from probing to avoid NAT-hairpinning false positives).
3. If this is a region-pinned vantage, make sure the host is monitored *via*
   a specific proxy (`monitored_by=1`, `proxyid=<that proxy>`) — not via a
   proxy group with HA failover, which would let the External check execute
   from a different region on any given day.

LLD picks up targets automatically and creates one item-set + one
`dpi.peers_ok` calculated item per `(target, kind, port)` per vantage.

## Opt-in syslog logging

The probe writes only JSON to stdout by default. To also emit one syslog line per
invocation, set `DPI_PROBE_SYSLOG=1` in the environment Zabbix uses to run external
scripts (e.g. systemd override for `zabbix-server.service` or `zabbix-proxy.service`).
Then `journalctl -t dpi_probe` shows live probe activity without going through Zabbix UI.
