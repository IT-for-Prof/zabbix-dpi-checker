#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALLER="${REPO_ROOT}/deploy/install-prober.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

# shellcheck disable=SC1090
INSTALL_PROBER_TESTING=1 source "${INSTALLER}"

reset_detection_state() {
    unset EXTERNAL_DIR ZABBIX_CONF
    EXT_DIR=""
    EXT_DIR_SOURCE=""
    ZABBIX_CONF_DEFAULTS=()
    KNOWN_EXTERNALSCRIPT_DIRS=()
}

assert_eq() {
    local expected="$1"
    local actual="$2"
    local label="$3"
    if [[ "${actual}" != "${expected}" ]]; then
        printf 'FAIL: %s\nexpected: %s\nactual:   %s\n' "${label}" "${expected}" "${actual}" >&2
        exit 1
    fi
}

assert_fails_helpfully() {
    local output_file="${TMP}/failure-output"
    if resolve_externalscripts_dir >"${output_file}" 2>&1; then
        echo "FAIL: resolve_externalscripts_dir unexpectedly succeeded" >&2
        exit 1
    fi
    if ! grep -q 'EXTERNAL_DIR=/real/path' "${output_file}"; then
        echo "FAIL: failure did not mention EXTERNAL_DIR=/real/path" >&2
        cat "${output_file}" >&2
        exit 1
    fi
}

test_external_dir_override_wins() {
    reset_detection_state
    local conf="${TMP}/override.conf"
    printf 'ExternalScripts=/usr/share/zabbix/externalscripts\n' > "${conf}"
    EXTERNAL_DIR="${TMP}/custom"
    ZABBIX_CONF="${conf}"
    KNOWN_EXTERNALSCRIPT_DIRS=("${TMP}/fallback")

    resolve_externalscripts_dir

    assert_eq "${TMP}/custom" "${EXT_DIR}" "EXTERNAL_DIR override path"
    assert_eq "EXTERNAL_DIR" "${EXT_DIR_SOURCE}" "EXTERNAL_DIR override source"
}

test_zabbix_conf_active_external_scripts_is_used() {
    reset_detection_state
    local conf="${TMP}/zabbix_server.conf"
    printf 'ExternalScripts=/usr/share/zabbix/externalscripts\n' > "${conf}"
    ZABBIX_CONF="${conf}"

    resolve_externalscripts_dir

    assert_eq "/usr/share/zabbix/externalscripts" "${EXT_DIR}" "ZABBIX_CONF path"
    assert_eq "${conf}" "${EXT_DIR_SOURCE}" "ZABBIX_CONF source"
}

test_commented_external_scripts_is_ignored() {
    reset_detection_state
    local conf="${TMP}/commented.conf"
    local fallback="${TMP}/known"
    mkdir -p "${fallback}"
    printf '# ExternalScripts=/usr/share/zabbix/externalscripts\n' > "${conf}"
    ZABBIX_CONF="${conf}"
    KNOWN_EXTERNALSCRIPT_DIRS=("${fallback}")

    resolve_externalscripts_dir

    assert_eq "${fallback}" "${EXT_DIR}" "commented config falls back"
    assert_eq "existing fallback directory" "${EXT_DIR_SOURCE}" "commented config fallback source"
}

test_missing_config_falls_back_to_first_existing_known_dir() {
    reset_detection_state
    local missing="${TMP}/missing"
    local first="${TMP}/first"
    local second="${TMP}/second"
    mkdir -p "${first}" "${second}"
    ZABBIX_CONF_DEFAULTS=("${missing}")
    KNOWN_EXTERNALSCRIPT_DIRS=("${TMP}/absent" "${first}" "${second}")

    resolve_externalscripts_dir

    assert_eq "${first}" "${EXT_DIR}" "first existing known fallback"
    assert_eq "existing fallback directory" "${EXT_DIR_SOURCE}" "known fallback source"
}

test_no_config_and_no_known_dir_fails_helpfully() {
    reset_detection_state
    ZABBIX_CONF_DEFAULTS=("${TMP}/missing")
    KNOWN_EXTERNALSCRIPT_DIRS=("${TMP}/absent")

    assert_fails_helpfully
}

test_relative_external_dir_override_fails_helpfully() {
    reset_detection_state
    EXTERNAL_DIR="relative/path"

    assert_fails_helpfully
}

test_relative_config_external_scripts_fails_helpfully() {
    reset_detection_state
    local conf="${TMP}/relative.conf"
    printf 'ExternalScripts=relative/path\n' > "${conf}"
    ZABBIX_CONF="${conf}"

    assert_fails_helpfully
}

test_first_readable_config_wins() {
    reset_detection_state
    local first="${TMP}/first.conf"
    local second="${TMP}/second.conf"
    printf 'ExternalScripts=/first/path\n' > "${first}"
    printf 'ExternalScripts=/second/path\n' > "${second}"
    ZABBIX_CONF_DEFAULTS=("${first}" "${second}")

    resolve_externalscripts_dir

    assert_eq "/first/path" "${EXT_DIR}" "first readable config path"
    assert_eq "${first}" "${EXT_DIR_SOURCE}" "first readable config source"
}

test_external_dir_override_wins
test_zabbix_conf_active_external_scripts_is_used
test_commented_external_scripts_is_ignored
test_missing_config_falls_back_to_first_existing_known_dir
test_no_config_and_no_known_dir_fails_helpfully
test_relative_external_dir_override_fails_helpfully
test_relative_config_external_scripts_fails_helpfully
test_first_readable_config_wins

echo "PASS: install-prober externalscripts detection"
