#!/usr/bin/env bash
# deploy-to.sh — one-shot remote install of dpi_probe on a Zabbix vantage host.
#
# Usage:
#   ./deploy-to.sh <ssh-host>                  # rsync local checkout + run installer
#   ./deploy-to.sh <ssh-host> --from-git URL [REF]
#                                              # ssh in, clone, install (no rsync)
#
# Examples:
#   ./deploy-to.sh ifp-vps12
#   ./deploy-to.sh ifp-vps15 --from-git https://github.com/IT-for-Prof/zabbix-dpi-checker.git main
#
# The remote host needs: SSH root access, network for apt/dnf, zabbix group present.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    sed -n '2,15p' "$0"
    exit 1
fi

HOST="$1"
shift
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "${1:-}" == "--from-git" ]]; then
    GIT_URL="${2:-}"
    GIT_REF="${3:-main}"
    if [[ -z "${GIT_URL}" ]]; then
        echo "FATAL: --from-git requires a URL" >&2
        exit 1
    fi
    echo "[deploy-to] Bootstrapping ${HOST} from ${GIT_URL} (${GIT_REF})"
    # Pipe the installer over ssh stdin so remote `bash -s` reads it as the script.
    # (Process substitution `<(...)` without `<` would just append a /dev/fd path
    # to ssh's argv and the remote shell would never receive the script.)
    INSTALLER_URL="${GIT_URL%.git}/raw/${GIT_REF}/deploy/install-prober.sh"

    # Download to a temp file so we can validate before piping. A bare
    # `curl ... | ssh ... bash -s` succeeds silently when curl delivers an
    # empty body (rare, but seen with stale CDN caches and edge cases); the
    # remote bash then runs zero lines, exits 0, and the install is a no-op.
    tmp_installer=$(mktemp)
    trap 'rm -f "${tmp_installer}"' EXIT

    if ! curl -fsSL "${INSTALLER_URL}" -o "${tmp_installer}"; then
        echo "[deploy-to] curl failed to fetch ${INSTALLER_URL}" >&2
        exit 1
    fi
    if [[ ! -s "${tmp_installer}" ]]; then
        echo "[deploy-to] FATAL: downloaded installer is empty (URL: ${INSTALLER_URL})" >&2
        exit 1
    fi
    if ! head -1 "${tmp_installer}" | grep -qE '^#!.*(bash|sh)'; then
        echo "[deploy-to] FATAL: downloaded installer lacks a shell shebang — not a script" >&2
        echo "[deploy-to] First line: $(head -1 "${tmp_installer}")" >&2
        exit 1
    fi

    # shellcheck disable=SC2029  # Intentional: ${GIT_URL}/${GIT_REF} expand on client side.
    if ssh "root@${HOST}" "bash -s -- --from-git ${GIT_URL} ${GIT_REF}" < "${tmp_installer}"; then
        :  # curl-pipe path worked
    else
        echo "[deploy-to] curl-pipe failed; falling back to git-clone-on-remote"
        # shellcheck disable=SC2029  # Intentional: ${GIT_URL}/${GIT_REF} expand on client side.
        ssh "root@${HOST}" "set -e
            tmp=\$(mktemp -d)
            git clone --depth 1 --branch ${GIT_REF} ${GIT_URL} \"\${tmp}\"
            bash \"\${tmp}/deploy/install-prober.sh\" --from-git ${GIT_URL} ${GIT_REF}
            rm -rf \"\${tmp}\""
    fi
else
    echo "[deploy-to] rsync ${REPO_DIR}/ → ${HOST}:/root/dpi-checker/"
    rsync -av --delete \
        --exclude='.venv-dev' --exclude='.git' --exclude='.pytest_cache' \
        --exclude='.mypy_cache' --exclude='.ruff_cache' --exclude='.serena' \
        --exclude='__pycache__' --exclude='docs/' --exclude='.mcp.json' \
        "${REPO_DIR}/" "root@${HOST}:/root/dpi-checker/"

    echo "[deploy-to] Running installer on ${HOST}"
    ssh "root@${HOST}" 'bash /root/dpi-checker/deploy/install-prober.sh /root/dpi-checker'
fi

echo "[deploy-to] Smoke test as zabbix user on ${HOST}"
ssh "root@${HOST}" "runuser -u zabbix -- /usr/lib/zabbix/externalscripts/dpi_probe \
    target-stub https 443 www.example.com www.example.com 5"

echo "[deploy-to] Done."
