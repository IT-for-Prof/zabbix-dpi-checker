#!/usr/bin/env bash
# Integration test for deploy/deploy-to.sh --from-git.
#
# Mocks `curl` and `ssh` to verify deploy-to:
#   (a) downloads the installer to a temp file (curl -o),
#   (b) validates non-empty + shebang,
#   (c) pipes the file contents to remote ssh's stdin,
#   (d) ssh argv is `root@HOST bash -s -- --from-git URL REF`.
#
# These were the exact failure modes of the original silent-no-op bug
# (PR 7d13298) plus its review-time hardening (PR 20e0604). Run from repo root.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEPLOY="${REPO_ROOT}/deploy/deploy-to.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

# --- mock `curl`: write fake installer to the -o destination ---
cat > "${TMP}/curl" <<'EOF'
#!/usr/bin/env bash
dest=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) dest="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[[ -n "$dest" ]] || { echo "fake-curl: no -o flag" >&2; exit 99; }
cat > "$dest" <<'INSTALLER'
#!/usr/bin/env bash
echo "fake-installer-OK"
INSTALLER
exit 0
EOF
chmod +x "${TMP}/curl"

# --- mock `ssh`: deploy-to.sh invokes ssh twice (install + smoke test);
#     number each invocation so assertions can target the install call. ---
cat > "${TMP}/ssh" <<EOF
#!/usr/bin/env bash
n=\$(( \$(cat "${TMP}/ssh-counter" 2>/dev/null || echo 0) + 1 ))
echo \$n > "${TMP}/ssh-counter"
printf '%s\n' "\$@" > "${TMP}/ssh-args.\$n"
cat > "${TMP}/ssh-stdin.\$n"
EOF
chmod +x "${TMP}/ssh"

# --- run deploy-to.sh with PATH overriding curl + ssh ---
PATH="${TMP}:${PATH}" "${DEPLOY}" \
    fake-host \
    --from-git https://example.com/owner/repo.git some-ref \
    >"${TMP}/deploy-stdout" 2>"${TMP}/deploy-stderr" || {
    echo "FAIL: deploy-to.sh exited non-zero"
    echo "--- stdout ---"; cat "${TMP}/deploy-stdout"
    echo "--- stderr ---"; cat "${TMP}/deploy-stderr"
    exit 1
}

# --- assert ssh invocation #1 received the installer body on stdin ---
if ! grep -q 'fake-installer-OK' "${TMP}/ssh-stdin.1"; then
    echo "FAIL: ssh#1 did not receive installer body on stdin"
    echo "stdin received:"; cat "${TMP}/ssh-stdin.1"
    exit 1
fi

# --- assert ssh#1 argv: [root@fake-host, "bash -s -- --from-git URL REF"] ---
if ! grep -qx 'root@fake-host' "${TMP}/ssh-args.1"; then
    echo "FAIL: ssh#1 first arg not 'root@fake-host'"
    cat "${TMP}/ssh-args.1"
    exit 1
fi
if ! grep -qx 'bash -s -- --from-git https://example.com/owner/repo.git some-ref' "${TMP}/ssh-args.1"; then
    echo "FAIL: ssh#1 second arg wrong"
    cat "${TMP}/ssh-args.1"
    exit 1
fi

echo "PASS: deploy-to.sh --from-git pipes installer to ssh stdin with correct argv"
