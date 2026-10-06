#!/usr/bin/env bash
# =============================================================================
# fix-lab-curl - replace the HTTP/3 curl bundled with the ESR TP1 lab package
# =============================================================================
# The lab ships tools/curl-http3/bin/curl.bin compiled against glibc >= 2.38
# via a bundled OpenSSL 3.4 libcrypto.so.3. The coreemu container is Ubuntu
# 22.04 (glibc 2.35), so the binary cannot run and get-http3.sh reports
# "does not have functional HTTP/3 support".
#
# This script overwrites curl.bin with the fully static musl curl installed
# at /opt/http3-curl/curl. The wrapper bin/curl is left untouched (its
# LD_LIBRARY_PATH export is harmless for a static binary).
#
# Usage:
#   fix-lab-curl [-q|--quiet] [path/to/curl-http3/bin/curl.bin]
#
# Default target: $HOME/esr/TP1/tools/curl-http3/bin/curl.bin
# =============================================================================
set -euo pipefail

QUIET=0
if [[ "${1:-}" == "-q" || "${1:-}" == "--quiet" ]]; then
    QUIET=1
    shift
fi

if [[ $# -ge 1 ]]; then
    TARGET="$1"
else
    TARGET="${HOME}/esr/TP1/tools/curl-http3/bin/curl.bin"
fi

STATIC=/opt/http3-curl/curl

if [[ ! -x "$STATIC" ]]; then
    [[ "$QUIET" -eq 1 ]] || echo "fix-lab-curl: error: $STATIC not present in this image" >&2
    exit 1
fi

if [[ ! -e "$TARGET" ]]; then
    [[ "$QUIET" -eq 1 ]] || {
        echo "fix-lab-curl: error: lab curl not found at $TARGET" >&2
        echo "usage: fix-lab-curl [-q] [path/to/curl-http3/bin/curl.bin]" >&2
    }
    exit 1
fi

# Fast path: already patched and still working.
if "$TARGET" -V >/dev/null 2>&1; then
    exit 0
fi

# Keep a one-time backup of the original (broken) binary.
if [[ ! -e "${TARGET}.orig" ]]; then
    cp -a "$TARGET" "${TARGET}.orig" 2>/dev/null || true
fi

install -m 0755 "$STATIC" "$TARGET"

if [[ "$QUIET" -eq 0 ]]; then
    echo "fix-lab-curl: patched $TARGET"
    "$TARGET" -V | head -n 2
fi