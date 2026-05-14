from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "dpi-mesh-blocking-detection.yaml"
UUID_RE = re.compile(r"^[0-9a-f]{32}$")


@pytest.fixture(scope="module")
def doc() -> dict[str, Any]:
    assert TEMPLATE_PATH.exists(), f"missing {TEMPLATE_PATH}"
    return cast("dict[str, Any]", yaml.safe_load(TEMPLATE_PATH.read_text()))


def test_top_level_has_zabbix_export_70_or_higher(doc: dict) -> None:  # type: ignore[type-arg]
    assert "zabbix_export" in doc
    version = doc["zabbix_export"]["version"]
    major = int(version.split(".")[0])
    assert major >= 7, f"expected Zabbix 7.0+, got {version}"


def test_value_map_dpi_verdict_present_with_all_codes(doc: dict) -> None:  # type: ignore[type-arg]
    # Zabbix 7.0 export puts valuemaps inside the template block, not at top level.
    tpl = doc["zabbix_export"]["templates"][0]
    vmaps = tpl.get("valuemaps") or []
    by_name = {v["name"]: v for v in vmaps}
    assert "DPI verdict" in by_name, "value map 'DPI verdict' missing"
    vmap = by_name["DPI verdict"]
    assert UUID_RE.match(vmap["uuid"]), f"value map uuid invalid: {vmap['uuid']}"
    mappings = {m["value"]: m["newvalue"] for m in vmap["mappings"]}
    required = {
        "OK",
        "TCP_RST_HANDSHAKE",
        "TCP_RST_MID_STREAM",
        "TLS_RESET_POST_HELLO",
        "TLS_TIMEOUT",
        "CERT_MISMATCH",
        "BANNER_MISMATCH",
        "REMOTE_HUNGUP_AFTER_CONNECT",
        "VANTAGE_UNAVAILABLE",
        "DNS_LIE",
        "HTTP_STUB",
        "ROUTE_BLACKHOLE",
        "PORT_FILTERED",
        "REMOTE_DOWN",
        "UDP_BLIND",
        "ERROR_INTERNAL",
    }
    missing = required - set(mappings)
    assert not missing, f"missing verdict mappings: {missing}"


def test_valuemap_contains_new_verdict_codes(doc: dict[str, Any]) -> None:
    from probe.lib.verdict import VerdictCode

    tpl = doc["zabbix_export"]["templates"][0]
    vmaps = tpl.get("valuemaps") or []
    dpi_vm = next(vm for vm in vmaps if vm["name"] == "DPI verdict")
    mapped_values = {m["value"] for m in dpi_vm["mappings"]}

    required = {code.value for code in VerdictCode}
    missing = required - mapped_values
    assert not missing, f"DPI verdict valuemap missing entries: {sorted(missing)}"


def test_template_has_tspu_liveness_item(doc: dict[str, Any]) -> None:
    items = doc["zabbix_export"]["templates"][0].get("items", [])
    key_to_item = {it["key"]: it for it in items}
    liveness_key = "dpi_probe[vantage-self,tspu-liveness,0,vantage-self,vantage-self,30]"
    assert "dpi.tspu_liveness.verdict" in key_to_item, (
        f"missing tspu-liveness verdict item; have: {list(key_to_item.keys())}"
    )
    master = key_to_item.get(liveness_key)
    assert master is not None, "missing master item for tspu-liveness"
    assert master["type"] == "EXTERNAL"
    assert "params" not in master
    assert key_to_item["dpi.tspu_liveness.verdict"]["master_item"]["key"] == liveness_key


def test_template_has_wg_handshake_item(doc: dict[str, Any]) -> None:
    items = doc["zabbix_export"]["templates"][0].get("items", [])
    key_to_item = {it["key"]: it for it in items}
    wg_key = (
        "dpi_probe[wg-handshake,wg-handshake,51820,"
        "wg-handshake,wg-handshake,{$DPI.PROBE_TIMEOUT}]"
    )
    assert wg_key in key_to_item, (
        f"missing wg-handshake master item; have: {list(key_to_item)}"
    )
    assert key_to_item[wg_key]["type"] == "EXTERNAL"
    assert "dpi.wg_handshake.verdict" in key_to_item
    assert key_to_item["dpi.wg_handshake.verdict"]["master_item"]["key"] == wg_key


def test_host_level_external_items_do_not_use_params(doc: dict[str, Any]) -> None:
    items = doc["zabbix_export"]["templates"][0].get("items", [])
    offenders = [
        item["key"] for item in items if item.get("type") == "EXTERNAL" and "params" in item
    ]
    assert offenders == [], f"EXTERNAL host items must encode args in key, not params: {offenders}"


def test_lld_uses_wireguard_pubkey_macro_for_wireguard_rows(doc: dict[str, Any]) -> None:
    lld = doc["zabbix_export"]["templates"][0]["discovery_rules"][0]
    script = lld["preprocessing"][0]["parameters"][0]
    assert "{$DPI.WG.PUBKEY}" in script
    assert 'kind === "wireguard" ? wgPubkey : certFp' in script


def test_template_has_tspu_active_trigger(doc: dict[str, Any]) -> None:
    triggers = doc["zabbix_export"]["templates"][0].get("triggers", [])
    names = {trigger["name"] for trigger in triggers}
    assert any("TSPU active" in name for name in names), f"have: {names}"


def test_template_block_present_with_uuid_and_macros(doc: dict) -> None:  # type: ignore[type-arg]
    tpls = doc["zabbix_export"].get("templates") or []
    assert len(tpls) == 1, "expected exactly one template"
    tpl = tpls[0]
    assert tpl["template"] == "DPI Mesh Blocking Detection"
    assert UUID_RE.match(tpl["uuid"]), f"template uuid invalid: {tpl['uuid']}"
    assert tpl["description"].strip(), "template description must not be empty"
    macros_by_name = {m["macro"]: m for m in tpl.get("macros", [])}
    assert "{$DPI.PROBE_TIMEOUT}" in macros_by_name
    assert "{$DPI.CERT_FINGERPRINT}" in macros_by_name
    assert "{$DPI.INTERVAL}" in macros_by_name
    for m in macros_by_name.values():
        assert m.get("description", "").strip(), f"macro {m['macro']} needs description"


def test_template_groups_reference_dpi_probers(doc: dict) -> None:  # type: ignore[type-arg]
    groups = doc["zabbix_export"].get("template_groups") or []
    names = {g["name"] for g in groups}
    assert "Templates/DPI Mesh" in names
    for g in groups:
        assert UUID_RE.match(g["uuid"])


def test_lld_rule_present_with_required_macros(doc: dict) -> None:  # type: ignore[type-arg]
    tpl = doc["zabbix_export"]["templates"][0]
    rules = tpl.get("discovery_rules") or []
    assert len(rules) >= 1
    lld = next(r for r in rules if r["key"] == "dpi.targets.discovery")
    assert lld["type"] == "HTTP_AGENT"
    assert UUID_RE.match(lld["uuid"])
    assert lld["description"].strip()
    # CSV expansion happens in JavaScript preprocessing; the JS step is
    # responsible for emitting {#TARGET}, {#DNS}, {#REGION}, {#KIND}, {#PORT}, {#SNI}.
    preproc = lld.get("preprocessing", [])
    js_steps = [p for p in preproc if p.get("type") == "JAVASCRIPT"]
    assert js_steps, "LLD must have JAVASCRIPT preprocessing for CSV-to-rows expansion"
    # Zabbix 7.0 export wraps the JS body in a `parameters: [<src>]` list.
    # Older hand-crafted YAML used `params: <src>` directly. Accept both.
    raw = js_steps[0].get("parameters") or js_steps[0].get("params")
    js_src = raw[0] if isinstance(raw, list) else raw
    assert js_src, "JAVASCRIPT preprocessing step has no source body"
    for required_macro in (
        "{#TARGET}",
        "{#DNS}",
        "{#REGION}",
        "{#KIND}",
        "{#PORT}",
        "{#SNI}",
        "{#CERT_FP}",
    ):
        assert required_macro in js_src, f"JS preprocessing must emit {required_macro}"


def test_lld_rule_has_all_three_exclusion_conditions(doc: dict) -> None:  # type: ignore[type-arg]
    """LLD filter must enforce three per-vantage exclusions, all as NOT-regexp.

    Dropping any of these would silently re-enable the corresponding source
    of false-positive triggers (probing self, self-hosted targets, ISP-filtered
    kinds), which is exactly the regression class these macros were added to
    prevent. Test asserts the full (macro, value, operator) tuple set.
    """
    lld = doc["zabbix_export"]["templates"][0]["discovery_rules"][0]
    conds = lld.get("filter", {}).get("conditions") or []
    got = {(c["macro"], c["value"], c.get("operator", "")) for c in conds}
    expected = {
        ("{#TARGET}", "^{HOST.HOST}$", "NOT_MATCHES_REGEX"),
        ("{#TARGET}", "{$DPI.SELF_TARGETS}", "NOT_MATCHES_REGEX"),
        ("{#KIND}", "{$DPI.EXCLUDE_KINDS}", "NOT_MATCHES_REGEX"),
    }
    missing = expected - got
    assert not missing, f"LLD filter missing conditions: {missing}; have: {got}"


def test_template_ships_failopen_defaults_for_exclusion_macros(doc: dict) -> None:  # type: ignore[type-arg]
    """The two per-vantage exclusion macros must ship with default `^$` (fail-open).

    `^$` matches only the empty string; `{#TARGET}` / `{#KIND}` are always
    non-empty, so the NOT-regexp condition passes. Any other default could
    silently drop items on fresh template imports.
    """
    tpl = doc["zabbix_export"]["templates"][0]
    macros = {m["macro"]: m for m in tpl.get("macros", [])}
    for name in ("{$DPI.SELF_TARGETS}", "{$DPI.EXCLUDE_KINDS}"):
        assert name in macros, f"template must ship macro {name}"
        assert macros[name].get("value") == "^$", (
            f"{name} default must be `^$` (fail-open), got {macros[name].get('value')!r}"
        )


def test_template_api_url_default_is_a_placeholder(doc: dict) -> None:  # type: ignore[type-arg]
    """Template default for {$DPI.API_URL} must be a generic example.example.com URL.

    The template YAML is shipped in a public repo; the production URL must live
    only as a host-level override on real vantages, never in the template
    default — otherwise re-exporting the template re-leaks the URL into the
    public commit (regression observed once already; this test prevents recurrence).
    """
    tpl = doc["zabbix_export"]["templates"][0]
    macros = {m["macro"]: m for m in tpl.get("macros", [])}
    api_url = macros.get("{$DPI.API_URL}", {}).get("value", "")
    assert "example.com" in api_url or "example.org" in api_url, (
        f"template {{$DPI.API_URL}} default must be a placeholder *.example.com, "
        f"got {api_url!r} — production URL leaks to public repo when re-exported"
    )


def test_item_prototypes_have_uuids_and_master_key(doc: dict) -> None:  # type: ignore[type-arg]
    lld = doc["zabbix_export"]["templates"][0]["discovery_rules"][0]
    protos = lld.get("item_prototypes") or []
    assert len(protos) >= 5, "expected master + 5 dependent item prototypes"
    uuids = [p["uuid"] for p in protos]
    assert len(set(uuids)) == len(uuids), "item prototype UUIDs must be unique"
    # External check master item must include {#DNS}, {#SNI}, {$DPI.PROBE_TIMEOUT}
    # in its key so Zabbix passes them as positional shell args (params: is ignored
    # for EXTERNAL type).
    master = next((p for p in protos if p.get("type") == "EXTERNAL"), None)
    assert master is not None, "must have an EXTERNAL master item prototype"
    assert "{#DNS}" in master["key"], "master item key must include {#DNS}"
    assert "{#SNI}" in master["key"], "master item key must include {#SNI}"
    assert "{$DPI.PROBE_TIMEOUT}" in master["key"], (
        "master item key must include {$DPI.PROBE_TIMEOUT}"
    )
    assert "{#CERT_FP}" in master["key"], "master item key must include {#CERT_FP}"
    assert "--with-control" in master["key"], "target probes must run the control gate"
    assert "params" not in master, (
        "EXTERNAL items must not use params: field (it is ignored by Zabbix)"
    )
    # Master item must have NO preprocessing — the probe's try/except in main() plus
    # the ZabbixSafe argparse guarantee a valid JSON line on every code path. A
    # preprocessing fallback would just hide probe bugs. Dependent items handle
    # field extraction via JSONPATH.
    assert "preprocessing" not in master or not master["preprocessing"], (
        "master EXTERNAL item must have no preprocessing — probe contract guarantees valid JSON"
    )
    # Master item key must start with 'dpi_probe[' (renamed from legacy 'dpi.probe[' —
    # Zabbix uses the prefix-before-[ as the script filename; we keep one canonical name).
    assert master["key"].startswith("dpi_probe["), (
        f"master item key must start with 'dpi_probe[', got {master['key']!r}"
    )
    dependent = [p for p in protos if p.get("type") == "DEPENDENT"]
    for dep in dependent:
        assert "master_item" in dep, f"dependent item {dep['key']} missing master_item"
        assert master["key"] == dep["master_item"]["key"], (
            f"dependent {dep['key']} master_item key must match EXTERNAL item key"
        )


def test_vantage_template_has_control_items(doc: dict) -> None:  # type: ignore[type-arg]
    tpl = doc["zabbix_export"]["templates"][0]
    items = {i["key"]: i for i in (tpl.get("items") or [])}
    assert "dpi_probe[--control-only]" in items
    assert "dpi.control_verdict" in items
    assert "dpi.control_latency_ms" in items
    assert items["dpi_probe[--control-only]"]["type"] == "EXTERNAL"
    for key in ("dpi.control_verdict", "dpi.control_latency_ms"):
        assert items[key]["type"] == "DEPENDENT"
        assert items[key]["master_item"]["key"] == "dpi_probe[--control-only]"


def test_vantage_template_extracts_discriminator(doc: dict) -> None:  # type: ignore[type-arg]
    lld = doc["zabbix_export"]["templates"][0]["discovery_rules"][0]
    items = {ip["key"]: ip for ip in (lld.get("item_prototypes") or [])}
    item = items["dpi.discriminator[{#TARGET},{#KIND},{#PORT}]"]
    assert item["type"] == "DEPENDENT"
    preproc = item["preprocessing"][0]
    assert preproc["type"] == "JSONPATH"
    assert preproc["parameters"] == ["$.discriminator"]
    assert preproc["error_handler"] == "CUSTOM_VALUE"


def _all_trigger_prototypes(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect every trigger prototype from the template, walking both the
    LLD-level `trigger_prototypes` and the per-item-prototype nested ones.

    Zabbix exports a trigger prototype under the item prototype that anchors
    its primary expression target (nodata(verdict) → nested under the verdict
    item prototype; count() over verdict that also references peers_ok →
    LLD-top-level). Tests must walk both locations.
    """
    lld = doc["zabbix_export"]["templates"][0]["discovery_rules"][0]
    triggers = list(cast("list[dict[str, Any]]", lld.get("trigger_prototypes") or []))
    for ip in lld.get("item_prototypes") or []:
        triggers.extend(ip.get("trigger_prototypes") or [])
    return triggers


def test_vantage_template_has_only_diagnostic_info_triggers(doc: dict) -> None:  # type: ignore[type-arg]
    """After the aggregator-host split, the vantage template's alerting role
    is limited to per-vantage diagnostics: an Info-level stale-data trigger
    that fires when THIS vantage's dpi.verdict stops updating. All mesh-wide
    severity tiers (Warning/Average/High/Disaster) live on the separate
    DPI Mesh Aggregator template — see test_aggregator_yaml.py.

    The per-vantage stale trigger uses nodata() and stays Info severity
    deliberately: it's operator-visibility for "one probe died" without
    contributing to the consensus/alerting layer. A single broken probe
    must not produce a Warning/Average/High/Disaster on the vantage host
    (that's what the aggregator is for).

    If any non-Info severity trigger reappears on the vantage template,
    mesh-wide events will fire N times (one per vantage) again instead of
    once on the aggregator. This test is the structural guard against that
    regression."""
    triggers = _all_trigger_prototypes(doc)
    non_info = [t for t in triggers if t.get("priority") != "INFO"]
    assert non_info == [], (
        f"vantage template must contain ONLY Info-level diagnostic triggers "
        f"(consensus/alerting belongs on DPI Mesh Aggregator); found "
        f"non-Info trigger(s): "
        f"{[(t.get('name'), t.get('priority')) for t in non_info]}"
    )

    # The diagnostic Info trigger must exist (re-added after the aggregator
    # split — without it, a single dead vantage probe is silent because the
    # aggregator's stale sentinel only fires when ALL vantages go quiet).
    info_stale = [
        t for t in triggers if t.get("priority") == "INFO" and "stale" in t.get("name", "").lower()
    ]
    assert info_stale, (
        "vantage template must have an Info-level per-vantage stale trigger "
        "(nodata on dpi.verdict). Without it, a single broken probe is "
        "invisible until vantages_total drops are noticed manually."
    )
    expr = info_stale[0]["expression"]
    assert "nodata(" in expr, f"per-vantage stale trigger must use nodata(); got: {expr}"
    assert "{$DPI.NODATA_WINDOW}" in expr, (
        f"per-vantage stale trigger must use the NODATA_WINDOW macro for tunability; got: {expr}"
    )
    assert '"strict"' in expr, (
        "per-vantage stale trigger must use nodata(...,'strict') so it doesn't "
        "trip on freshly-discovered items before their first probe"
    )
    # No dependencies — this trigger is diagnostic, not gated by anything.
    deps = info_stale[0].get("dependencies") or []
    assert deps == [], f"per-vantage stale trigger must be standalone (no deps); got: {deps}"


def test_vantage_template_has_no_aggregate_calc_items(doc: dict) -> None:  # type: ignore[type-arg]
    """Calculated items dpi.peers_ok / dpi.vantages_total / dpi.affected belong
    on the aggregator template. If they exist on the vantage template they'd
    materialize on every vantage host — each running its own last_foreach over
    /*/dpi.verdict — multiplying calc-engine load by N for no added information."""
    lld = doc["zabbix_export"]["templates"][0]["discovery_rules"][0]
    keys = {ip["key"] for ip in (lld.get("item_prototypes") or [])}
    forbidden = {
        "dpi.peers_ok[{#TARGET},{#KIND},{#PORT}]",
        "dpi.vantages_total[{#TARGET},{#KIND},{#PORT}]",
        "dpi.affected[{#TARGET},{#KIND},{#PORT}]",
    }
    leaked = keys & forbidden
    assert not leaked, (
        f"vantage template must not contain aggregator calc items "
        f"(they belong on DPI Mesh Aggregator); found: {sorted(leaked)}"
    )


def test_all_uuids_are_well_formed(doc: dict) -> None:  # type: ignore[type-arg]
    """Every uuid: field in the template must be a 32-char lowercase hex (Zabbix UUID form).

    The YAML is authoritative — exported from Zabbix via configuration.export — so we
    don't maintain a separate registry comment; we just sanity-check the UUIDs in place.
    """
    text = TEMPLATE_PATH.read_text()
    uuids = re.findall(r"\buuid:\s*([0-9a-fA-F]{32})\b", text)
    assert uuids, "expected at least one uuid: field in the template"
    bad = [u for u in uuids if not UUID_RE.match(u)]
    assert not bad, f"UUIDs not in lowercase hex form: {bad}"
