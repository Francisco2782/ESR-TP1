#!/usr/bin/env bash
# =============================================================================
# ESR TP1 container init
# =============================================================================
# Runs on every interactive shell (login via /etc/profile.d, non-login via
# /etc/bash.bashrc). Two idempotent jobs:
#
#   1. Unpack /volume/ESR-TP1-26-27-resources.zip into ~/esr
#   2. Replace the lab's bundled HTTP/3 curl with the fully static one
#
# Both are cheap on re-run: a sentinel file short-circuits the unzip, and
# fix-lab-curl is a no-op once the target already works.
#
# Set ESR_TP1_INIT_VERBOSE=1 to see what it does.

# -----------------------------------------------------------------------------
# Step 1: unzip the lab package into ~/esr
# -----------------------------------------------------------------------------
_esr_tp1_unzip() {
    local zip="${ESR_TP1_ZIP:-/volume/ESR-TP1-26-27-resources.zip}"
    local dest="${HOME}/esr"
    local stamp="${dest}/.tp1-unpacked"

    # Nothing to unpack if the zip isn't there.
    [ -r "$zip" ] || return 0

    # If we already unpacked and the resulting tree is still present, skip.
    if [ -e "$stamp" ] && [ -d "${dest}/TP1" ]; then
        return 0
    fi

    if ! command -v unzip >/dev/null 2>&1; then
        echo "[esr-tp1-init] warning: unzip is not installed; cannot unpack $zip" >&2
        return 0
    fi

    mkdir -p "$dest"
    if unzip -q -o "$zip" -d "$dest"; then
        : >"$stamp" 2>/dev/null || true
        if [ -n "${ESR_TP1_INIT_VERBOSE:-}" ]; then
            echo "[esr-tp1-init] unpacked $zip -> $dest"
        fi
    else
        echo "[esr-tp1-init] warning: failed to unzip $zip" >&2
    fi
}

# -----------------------------------------------------------------------------
# Step 2: heal the lab's bundled curl.bin
# -----------------------------------------------------------------------------
_esr_tp1_fix_curl() {
    if [ -x /usr/local/bin/fix-lab-curl ]; then
        /usr/local/bin/fix-lab-curl -q >/dev/null 2>&1 || true
    fi
}

# -----------------------------------------------------------------------------
# Combined entry point
# -----------------------------------------------------------------------------
_esr_tp1_init() {
    # Only act for the user that actually owns the lab.
    [ -n "${HOME:-}" ] || return 0
    [ -w "$HOME" ] || return 0

    _esr_tp1_unzip
    _esr_tp1_fix_curl
}

# Run once now, so `docker exec -it <ctr> bash` after the container is up
# already unpacks things before the first prompt.
_esr_tp1_init

# Also run on every prompt, so unzipping in the current shell is caught.
if [ -n "${BASH_VERSION-}" ]; then
    case "${PROMPT_COMMAND-}" in
        *_esr_tp1_init*) ;;
        *) PROMPT_COMMAND="_esr_tp1_init${PROMPT_COMMAND:+; $PROMPT_COMMAND}" ;;
    esac
fi

export -f _esr_tp1_init _esr_tp1_unzip _esr_tp1_fix_curl 2>/dev/null || true