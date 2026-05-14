#!/usr/bin/env bash
# install-prober.sh — idempotent install of dpi_probe on a Zabbix prober host.
#
# Two ways to run:
#
#   1) From a local checkout (rsync-then-install, dev or air-gapped hosts):
#        sudo ./install-prober.sh [/path/to/repo]
#      Defaults REPO_DIR to the parent of this script.
#
#   2) From GitHub (one-shot bootstrap, recommended for new vantages):
#        sudo ./install-prober.sh --from-git https://github.com/IT-for-Prof/zabbix-dpi-checker.git [REF]
#      Or via curl pipe (the script reruns itself with --from-git):
#        curl -fsSL https://raw.githubusercontent.com/IT-for-Prof/zabbix-dpi-checker/main/deploy/install-prober.sh \
#          | sudo bash -s -- --from-git https://github.com/IT-for-Prof/zabbix-dpi-checker.git main
#
# Detects OS (RHEL-family vs Debian-family), installs python3.11+ if needed,
# creates a venv at /opt/dpi-probe/venv, deploys the probe package, symlinks
# /usr/lib/zabbix/externalscripts/dpi_probe → /opt/dpi-probe/dpi_probe, and
# enforces root:zabbix 0750 ownership on every run.
#
# Every run appends to /var/log/dpi-probe/install.log for post-mortem.

set -euo pipefail

INSTALL_DIR="/opt/dpi-probe"
VENV_DIR="${INSTALL_DIR}/venv"
EXT_DIR="/usr/lib/zabbix/externalscripts"
LOG_DIR="/var/log/dpi-probe"
LOG_FILE="${LOG_DIR}/install.log"

# --- Argument parsing -------------------------------------------------------
FROM_GIT_URL=""
FROM_GIT_REF=""
REPO_DIR=""
TMP_CLONE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-git)
            FROM_GIT_URL="${2:-}"
            FROM_GIT_REF="${3:-main}"
            shift 3 || { echo "FATAL: --from-git needs URL [REF]" >&2; exit 1; }
            ;;
        -h|--help)
            sed -n '2,21p' "$0"
            exit 0
            ;;
        *)
            REPO_DIR="$1"
            shift
            ;;
    esac
done

# --- Logging ----------------------------------------------------------------
# Tee everything to a persistent log so we can audit failed installs later.
mkdir -p "${LOG_DIR}"
exec > >(tee -a "${LOG_FILE}") 2>&1

ts() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
log() { printf '[install-prober %s] %s\n' "$(ts)" "$*"; }

cleanup() {
    if [[ -n "${TMP_CLONE}" && -d "${TMP_CLONE}" ]]; then
        rm -rf "${TMP_CLONE}"
    fi
}
trap cleanup EXIT

log "==== install run started ===="
log "argv: --from-git=${FROM_GIT_URL:-<unset>} ref=${FROM_GIT_REF:-<unset>} repo_dir=${REPO_DIR:-<auto>}"

# --- OS detection -----------------------------------------------------------
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091  # /etc/os-release is the standard distro probe; not a file we ship.
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_ID_LIKE="${ID_LIKE:-}"
else
    log "FATAL: /etc/os-release not found"
    exit 1
fi
log "OS: ${OS_ID} (id_like=${OS_ID_LIKE})"

# --- Python resolution ------------------------------------------------------
# 3.11 preferred (matches dev), 3.12+ accepted (Ubuntu 24.04+). stdlib-only probe.
_resolve_python() {
    for py in python3.11 python3.12 python3.13; do
        if command -v "$py" >/dev/null 2>&1; then
            printf '%s' "$py"
            return
        fi
    done
    printf ''
}

install_python_3() {
    local py
    py=$(_resolve_python)
    if [[ -n "$py" ]]; then
        log "${py} already present: $($py --version 2>&1)"
        return
    fi
    case "${OS_ID}${OS_ID_LIKE}" in
        *rhel*|*centos*|*almalinux*|*rocky*)
            log "Installing python3.11 via dnf"
            dnf install -y python3.11
            ;;
        *debian*|*ubuntu*)
            log "Installing python3 via apt"
            apt-get update
            # Prefer 3.11 on Debian 12; fall back to distro python3 + venv on Ubuntu 24.04+.
            apt-get install -y python3.11 python3.11-venv 2>/dev/null || \
                apt-get install -y python3 python3-venv
            ;;
        *)
            log "FATAL: unsupported OS family ${OS_ID}/${OS_ID_LIKE}; install python3.11+ manually"
            exit 1
            ;;
    esac
}

install_git_if_needed() {
    if command -v git >/dev/null 2>&1; then
        return
    fi
    case "${OS_ID}${OS_ID_LIKE}" in
        *rhel*|*centos*|*almalinux*|*rocky*)
            dnf install -y git
            ;;
        *debian*|*ubuntu*)
            apt-get update && apt-get install -y git
            ;;
        *)
            log "FATAL: git not present and unsupported OS — install git manually"
            exit 1
            ;;
    esac
}

# --- Source preparation -----------------------------------------------------
fetch_from_git() {
    install_git_if_needed
    TMP_CLONE=$(mktemp -d -t dpi-checker-XXXXXX)
    log "Cloning ${FROM_GIT_URL} (ref=${FROM_GIT_REF}) to ${TMP_CLONE}"
    git clone --depth 1 --branch "${FROM_GIT_REF}" "${FROM_GIT_URL}" "${TMP_CLONE}"
    REPO_DIR="${TMP_CLONE}"
}

# --- Install steps ----------------------------------------------------------
ensure_venv() {
    local py
    py=$(_resolve_python)
    if [[ -z "$py" ]]; then
        log "FATAL: no python3.11+ found after install step"
        exit 1
    fi
    if [[ -x "${VENV_DIR}/bin/python" ]] && \
       "${VENV_DIR}/bin/python" --version 2>&1 | grep -qE '3\.(1[1-9]|[2-9][0-9])'; then
        log "venv already exists at ${VENV_DIR} ($("${VENV_DIR}/bin/python" --version 2>&1))"
        return
    fi
    log "Creating venv at ${VENV_DIR} using ${py}"
    mkdir -p "${INSTALL_DIR}"
    "$py" -m venv "${VENV_DIR}"
}

# --- Install project dependencies into venv -------------------------------
# The wg-handshake probe kind needs the `cryptography` library for X25519 +
# ChaCha20-Poly1305 (BLAKE2s is stdlib). Declared in pyproject.toml
# [project.dependencies]; pinned here so the installer doesn't need to parse TOML.
# If the project gains more deps, update both this line and pyproject.toml.
install_deps() {
    local deps="cryptography>=42"
    # Older venvs may lack pip (created implicitly with --without-pip, or
    # before this branch added install_deps at all). Detect and bootstrap
    # via ensurepip — works as long as the Python ships ensurepip (the
    # python3-venv apt package; required for `python -m venv` anyway).
    if [[ ! -x "${VENV_DIR}/bin/pip" ]]; then
        log "pip missing in venv; bootstrapping via ensurepip"
        "${VENV_DIR}/bin/python" -m ensurepip --upgrade --default-pip \
            >> "${LOG_FILE}" 2>&1 \
            || { log "FATAL: ensurepip failed — remove ${VENV_DIR} and re-run installer"; exit 1; }
    fi
    log "Installing project dependencies into venv: ${deps}"
    # NOTE: no --quiet so pip's real error (network issue, missing wheel,
    # missing build deps for source-only install) lands in ${LOG_FILE}
    # verbatim instead of being hidden behind a generic FATAL message.
    "${VENV_DIR}/bin/pip" install --disable-pip-version-check --upgrade-strategy only-if-needed ${deps} \
        >> "${LOG_FILE}" 2>&1 \
        || { log "FATAL: pip install ${deps} failed — see ${LOG_FILE} above for pip's output"; exit 1; }
    log "Dependencies installed"
}

deploy_probe() {
    log "Deploying probe/ tree from ${REPO_DIR} to ${INSTALL_DIR}"
    install -d "${INSTALL_DIR}/probe/lib"
    install -m 0644 "${REPO_DIR}/probe/lib/"*.py "${INSTALL_DIR}/probe/lib/"
    install -m 0755 "${REPO_DIR}/probe/dpi_probe.py" "${INSTALL_DIR}/dpi_probe"

    # Rewrite shebang to point at our venv
    sed -i '1c\
#!'"${VENV_DIR}"'/bin/python' "${INSTALL_DIR}/dpi_probe"

    # Make probe/ a package importable when running from /opt/dpi-probe
    touch "${INSTALL_DIR}/probe/__init__.py"
}

ensure_externalscripts_dir() {
    if [[ ! -d "${EXT_DIR}" ]]; then
        log "Creating ${EXT_DIR}"
        install -d -o zabbix -g zabbix -m 0755 "${EXT_DIR}"
    fi
}

install_externalscripts_symlink() {
    # The script accepts positional args natively (target kind port dns sni timeout)
    # and bootstraps sys.path internally; the Zabbix entry-point is a direct symlink.
    # Idempotent on hosts that previously ran the pre-cleanup installer: removes
    # the legacy dotted symlink and bash wrapper if present.
    rm -f "${EXT_DIR}/dpi.probe" "${INSTALL_DIR}/dpi_probe.wrapper"
    ln -sf "${INSTALL_DIR}/dpi_probe" "${EXT_DIR}/dpi_probe"
    log "Installed externalscripts entry: dpi_probe -> ${INSTALL_DIR}/dpi_probe"
}

fix_permissions() {
    # Zabbix executes External checks as user `zabbix`. The install tree must be
    # readable+traversable by that user — root:zabbix with group-rX on dirs and
    # files. No world access. Re-applied on every install run so drift is fixed.
    if ! getent group zabbix >/dev/null 2>&1; then
        log "FATAL: group 'zabbix' missing — install zabbix-agent or zabbix-proxy first"
        exit 1
    fi
    log "Setting ownership root:zabbix and mode g+rX (no world access) on ${INSTALL_DIR}"
    chown -R root:zabbix "${INSTALL_DIR}"
    chmod -R u=rwX,g=rX,o= "${INSTALL_DIR}"
    chown -h root:zabbix "${EXT_DIR}/dpi_probe"
    # Log dir: zabbix needs to write its own log; install dir is read-only for it.
    chown -R zabbix:zabbix "${LOG_DIR}"
    chmod 0750 "${LOG_DIR}"
}

smoke_test() {
    # Run as user `zabbix` — the same user that will execute External checks.
    # Catches import failures AND permission drift in one step. --help avoids
    # network (RU/BY vantages may block example.com).
    log "Smoke test: runuser -u zabbix -- dpi_probe --help"
    if ! runuser -u zabbix -- "${EXT_DIR}/dpi_probe" --help >/dev/null 2>&1; then
        log "FATAL: smoke test failed — zabbix user cannot execute the probe"
        log "       reproduce with: runuser -u zabbix -- ${EXT_DIR}/dpi_probe --help"
        exit 1
    fi
    log "Smoke test OK (zabbix user can load and run the CLI)"
}

# --- Main -------------------------------------------------------------------
main() {
    if [[ $EUID -ne 0 ]]; then
        log "FATAL: must run as root"
        exit 1
    fi

    if [[ -n "${FROM_GIT_URL}" ]]; then
        fetch_from_git
    elif [[ -z "${REPO_DIR}" ]]; then
        REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
        log "Using local checkout at ${REPO_DIR}"
    else
        log "Using provided REPO_DIR=${REPO_DIR}"
    fi

    if [[ ! -f "${REPO_DIR}/probe/dpi_probe.py" ]]; then
        log "FATAL: ${REPO_DIR}/probe/dpi_probe.py not found — wrong path?"
        exit 1
    fi

    install_python_3
    ensure_venv
    install_deps
    deploy_probe
    ensure_externalscripts_dir
    install_externalscripts_symlink
    fix_permissions
    smoke_test
    log "==== install run completed OK ===="
}

main "$@"
