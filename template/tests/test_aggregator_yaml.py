"""Structural tests for the DPI Mesh Aggregator template.

The aggregator template is exported from a separate Zabbix template
(`DPI Mesh Aggregator`) and lives on a single phantom host that holds the
mesh-wide consensus/alerting layer. The vantage template (`DPI Mesh
Blocking Detection`) handles the data layer (probes + verdict items) and
is covered in `test_template_yaml.py`.

These tests pin three invariants of the aggregator design:
  1. Three calc items per (target, kind, port): peers_ok, vantages_total,
     affected — drive the auto-scaling severity ladder.
  2. Four severity tiers (Warning / Average / High / Disaster) plus one
     stale-data sentinel (Info), each with its own `count(#3,...)` debounce
     and `vantages_total` gate so tiers stay mutually exclusive at small N.
  3. All severity tiers depend on the stale-data trigger — a frozen
     aggregator must not produce false consensus alerts.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "dpi-mesh-aggregator.yaml"


@pytest.fixture(scope="module")
def doc() -> dict[str, Any]:
    with TEMPLATE_PATH.open() as f:
        return cast("dict[str, Any]", yaml.safe_load(f))


def _template(doc: dict[str, Any]) -> dict[str, Any]:
    return cast("dict[str, Any]", doc["zabbix_export"]["templates"][0])


def _lld(doc: dict[str, Any]) -> dict[str, Any]:
    return cast("dict[str, Any]", _template(doc)["discovery_rules"][0])


def _all_trigger_prototypes(doc: dict[str, Any]) -> list[dict[str, Any]]:
    lld = _lld(doc)
    triggers = list(cast("list[dict[str, Any]]", lld.get("trigger_prototypes") or []))
    for ip in lld.get("item_prototypes") or []:
        triggers.extend(ip.get("trigger_prototypes") or [])
    return triggers


def test_template_identity(doc: dict) -> None:  # type: ignore[type-arg]
    """The aggregator template must be identifiable by name and have a unique
    UUID. We pin the template technical name because trigger expressions
    reference it literally as `/DPI Mesh Aggregator/dpi.peers_ok[...]`."""
    t = _template(doc)
    assert t["template"] == "DPI Mesh Aggregator", (
        f"template technical name must be 'DPI Mesh Aggregator' (referenced "
        f"literally in trigger expressions); got {t['template']!r}"
    )
    assert "uuid" in t, "template must have a UUID"
    assert len(t["uuid"]) == 32, "template UUID must be 32 hex chars"


def test_template_macros_default_to_failopen_placeholders(doc: dict) -> None:  # type: ignore[type-arg]
    """Public-repo defaults must NOT contain a real Zabbix URL or token.
    The aggregator inherits the same fail-open posture as the vantage template:
    if a host doesn't override the macros, LLD fails harmlessly with 'invalid
    URL' rather than leaking the previous owner's secrets."""
    macros = {m["macro"]: m for m in _template(doc).get("macros", [])}
    assert "{$DPI.API_URL}" in macros
    assert "your-zabbix.example.com" in macros["{$DPI.API_URL}"]["value"], (
        f"API_URL default must be a placeholder; got {macros['{$DPI.API_URL}']!r}"
    )

    # API_TOKEN must be Secret type with empty default (no token leakage).
    assert "{$DPI.API_TOKEN}" in macros
    assert macros["{$DPI.API_TOKEN}"].get("type") == "SECRET_TEXT", (
        f"API_TOKEN must be type=Secret; got {macros['{$DPI.API_TOKEN}']!r}"
    )
    assert macros["{$DPI.API_TOKEN}"].get("value", "") == "", (
        "API_TOKEN default value must be empty (real tokens are per-host overrides)"
    )

    # EXCLUDE_KINDS and SELF_TARGETS must default to ^$ (matches nothing
    # → nothing excluded → aggregator discovers everything).
    for name in ("{$DPI.EXCLUDE_KINDS}", "{$DPI.SELF_TARGETS}"):
        assert name in macros, f"missing macro {name}"
        assert macros[name]["value"] == "^$", (
            f"{name} default must be ^$ (no exclusion); got {macros[name]!r}"
        )


def test_lld_uses_same_endpoint_as_vantage(doc: dict) -> None:  # type: ignore[type-arg]
    """The aggregator's LLD reuses the vantage discovery pattern: HTTP-agent
    POST to {$DPI.API_URL} → host.get → JS preprocessing → (target,kind,port)
    rows. Reusing the same shape means a single scoped API token (dpi-vantage)
    serves both roles."""
    lld = _lld(doc)
    assert lld["key"] == "dpi.targets.discovery"
    assert lld.get("type") == "HTTP_AGENT", (
        f"LLD must be HTTP_AGENT to query Zabbix API; got {lld.get('type')!r}"
    )
    assert "{$DPI.API_URL}" in lld.get("url", "")
    posts = lld.get("posts", "")
    assert "host.get" in posts, "LLD body must call the host.get API method"
    assert "{$DPI.API_TOKEN}" in posts, "LLD body must auth with scoped token"
    preproc = lld.get("preprocessing") or []
    assert any("javascript" in (p.get("type", "")).lower() for p in preproc), (
        "LLD must use JS preprocessing to expand KINDS CSV into rows"
    )


def test_three_calc_item_prototypes_present(doc: dict) -> None:  # type: ignore[type-arg]
    """The aggregator must materialize exactly the three calc items the
    severity ladder reads. Listing them here also guards against accidental
    leftovers (e.g., probe-side keys leaking into the aggregator template
    via copy-paste)."""
    keys = {ip["key"]: ip for ip in (_lld(doc).get("item_prototypes") or [])}
    required = {
        "dpi.peers_ok[{#TARGET},{#KIND},{#PORT}]": ('"eq"', '"OK"'),  # counts OK verdicts only
        "dpi.vantages_total[{#TARGET},{#KIND},{#PORT}]": (
            '"regexp"',
            '"."',
        ),  # counts ANY non-empty verdict
        "dpi.affected[{#TARGET},{#KIND},{#PORT}]": ('"ne"', '"OK"'),  # counts non-OK verdicts only
    }
    assert set(keys) == set(required), (
        f"aggregator must have exactly these item prototypes; got {sorted(keys)}"
    )
    for key, (op, val) in required.items():
        item = keys[key]
        assert item.get("type") == "CALCULATED", (
            f"{key}: must be calculated; got {item.get('type')!r}"
        )
        params = item.get("params", "")
        assert "last_foreach" in params, (
            f"{key}: must use last_foreach over /*/dpi.verdict; got {params!r}"
        )
        assert "/*/dpi.verdict[{#TARGET},{#KIND},{#PORT}]" in params, (
            f"{key}: must aggregate the matching verdict tuple; got {params!r}"
        )
        assert op in params, f"{key}: expected operator {op} in params; got {params!r}"
        assert val in params, f"{key}: expected pattern {val} in params; got {params!r}"


def _by_priority(doc: dict) -> dict[str, dict]:  # type: ignore[type-arg]
    return {t["priority"]: t for t in _all_trigger_prototypes(doc) if "consensus" in t["name"]}


def test_four_severity_tiers_with_auto_scaling_expressions(doc: dict) -> None:  # type: ignore[type-arg]
    """The severity ladder is encoded against dpi.affected (literal-integer
    comparisons in count(#3,"eq",N)) plus dpi.peers_ok for the all-affected
    floor. Tiers are gated by dpi.vantages_total >= N so they remain mutually
    exclusive across mesh sizes 1..6, and every tier additionally requires
    last(dpi.discriminator_any) >= 1 so PORT_FILTERED alone (LOW confidence,
    no DPI fingerprint) never fires — ISP outbound filters and generic
    firewall drops stay forensic-only.

        affected = 1,  vantages_total >= 2    → INFO
        affected = 2,  vantages_total >= 3    → WARNING
        affected >= 3, peers_ok >= 1,
                       vantages_total >= 4    → AVERAGE (majority but not all)
        peers_ok = 0                          → HIGH (all affected)

    Using `dpi.affected` rather than `last(vantages_total) - last(peers_ok)`
    inside count() is deliberate: Zabbix's count() pattern argument is a
    literal string/number, not an expression — the calc item gives us that
    literal."""
    by_prio = _by_priority(doc)
    assert set(by_prio) == {"INFO", "WARNING", "AVERAGE", "HIGH"}, (
        f"expected exactly 4 severity tiers; got {sorted(by_prio)}"
    )

    def _norm(s: str) -> str:
        return "".join(s.split())

    info = _norm(by_prio["INFO"]["expression"])
    warn = _norm(by_prio["WARNING"]["expression"])
    avg = _norm(by_prio["AVERAGE"]["expression"])
    high = _norm(by_prio["HIGH"]["expression"])

    # All four directional tiers must use count(...,#3,...)=3 debounce so a
    # single calc-cycle blip doesn't fire. Pin both the #3 selector AND the
    # =3 close so a regression like count(...,#3,"eq","1")>0 (which only
    # requires 1 of 3 cycles to match) doesn't slip through. Each tier must
    # also include the discriminator gate so PORT_FILTERED without a
    # fingerprint stays out of the alert path.
    debounce_re = re.compile(r'count\([^)]+,#3,"[a-z]+","\d+"\)=3')
    for name, expr in [("INFO", info), ("WARNING", warn), ("AVERAGE", avg), ("HIGH", high)]:
        assert ",#3," in expr, f"{name}: must use #3 selector; got {expr}"
        assert debounce_re.search(expr), (
            f"{name}: must use count(...,#3,...)=3 debounce idiom "
            f"(NOT count(...)>0 or similar); got {expr}"
        )
        assert "discriminator_any[{#TARGET},{#KIND},{#PORT}])>=1" in expr, (
            f"{name}: must gate on last(dpi.discriminator_any[...])>=1 so "
            f"PORT_FILTERED without a DPI fingerprint stays forensic-only; "
            f"got {expr}"
        )

    # INFO: affected=1, vantages_total>=2.
    assert 'affected[{#TARGET},{#KIND},{#PORT}],#3,"eq","1"' in info
    assert "vantages_total[{#TARGET},{#KIND},{#PORT}])>=2" in info

    # WARNING: affected=2, vantages_total>=3.
    assert 'affected[{#TARGET},{#KIND},{#PORT}],#3,"eq","2"' in warn
    assert "vantages_total[{#TARGET},{#KIND},{#PORT}])>=3" in warn

    # AVERAGE: affected>=3 AND peers_ok>=1 (excludes HIGH), vantages_total>=4.
    assert 'affected[{#TARGET},{#KIND},{#PORT}],#3,"ge","3"' in avg
    assert 'peers_ok[{#TARGET},{#KIND},{#PORT}],#3,"ge","1"' in avg
    assert "vantages_total[{#TARGET},{#KIND},{#PORT}])>=4" in avg

    # HIGH: peers_ok=0 sustained — no vantages_total gate so it covers
    # even single-vantage all-affected scenarios (still requires the
    # discriminator gate, checked above).
    assert 'peers_ok[{#TARGET},{#KIND},{#PORT}],#3,"eq","0"' in high


def test_every_consensus_tier_has_opdata(doc: dict) -> None:  # type: ignore[type-arg]
    """All four consensus tier prototypes must carry an `opdata` line so the
    Zabbix UI shows live `aff=X/Y dpi=N` (or `peers_ok=X/Y dpi=N` for the
    all-affected tier) next to each alert. Operators reading the alert list
    rely on this for triage without clicking through to Latest data."""
    by_prio = _by_priority(doc)
    for prio, t in by_prio.items():
        opdata = t.get("opdata") or ""
        assert opdata.strip(), f"{prio}: consensus tier must have non-empty opdata; got {opdata!r}"
        assert "dpi=" in opdata, (
            f"{prio}: opdata must include dpi=… (count of vantages with a "
            f"discriminator fingerprint); got {opdata!r}"
        )


def test_stale_trigger_and_dependencies(doc: dict) -> None:  # type: ignore[type-arg]
    """The Info-level stale trigger must fire on nodata over the
    {$DPI.NODATA_WINDOW} macro (default 1h) for the aggregator's peers_ok
    item. All four severity tiers must depend on it so a frozen aggregator
    can't produce false consensus events."""
    triggers = _all_trigger_prototypes(doc)
    stale = next((t for t in triggers if "stale" in t["name"].lower()), None)
    assert stale is not None, "missing 'DPI Mesh stale' trigger prototype"
    expr = stale["expression"]
    assert "nodata(" in expr, f"stale trigger must use nodata(); got: {expr}"
    assert "{$DPI.NODATA_WINDOW}" in expr, (
        f"stale trigger must use the macro for tunability; got: {expr}"
    )
    assert '"strict"' in expr, (
        "stale trigger must use nodata(...,'strict') so freshly-discovered "
        "items don't trip before their first calc cycle"
    )
    assert stale["priority"] == "INFO", (
        f"stale trigger must be INFO priority (diagnostic only); got {stale['priority']!r}"
    )

    for t in (t for t in triggers if "consensus" in t["name"]):
        deps = t.get("dependencies") or []
        assert any("stale" in (d.get("name", "")).lower() for d in deps), (
            f"consensus trigger {t['name']!r} must depend on the stale-data "
            f"trigger. Dependencies: {deps}"
        )


def test_all_triggers_reference_aggregator_host_path(doc: dict) -> None:  # type: ignore[type-arg]
    """Trigger expressions in template form use the template's technical name
    as the `/host/key` path. On link to a real host, Zabbix substitutes the
    template name to the host name — but the literal must match the template's
    own `template` field, otherwise materialization breaks silently."""
    template_name = _template(doc)["template"]
    expected_path = f"/{template_name}/"
    for t in _all_trigger_prototypes(doc):
        assert expected_path in t["expression"], (
            f"trigger {t['name']!r} must reference {expected_path}; got: {t['expression']}"
        )
