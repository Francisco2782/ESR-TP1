#!/bin/bash

# =========================================================
# CORE topology verification
# - One kitty terminal per node (independent child process)
# - Each terminal sources tp1-env.sh, exports GROUP/PROFILE
#   locally, then runs the pings
# - Terminal stays open as a normal interactive shell
# =========================================================

set -u

CONTAINER="core"
SESSION="/tmp/pycore.1"

NODES=(
    "Streamer"
    "PC1"
    "PC2"
    "PC3"
    "PC4"
)

PING_COUNT=10
PING_TIMEOUT=1
MIN_SUCCESS=90

DELAY=0.3

LOGDIR="/tmp/core-verify"
mkdir -p "$LOGDIR"
rm -f "$LOGDIR"/*.log "$LOGDIR"/*.status "$LOGDIR"/*.sh


# =========================================================
# Sanity checks
# =========================================================

if ! command -v kitty >/dev/null 2>&1; then
    echo "ERROR: kitty not found in PATH"
    exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    echo "ERROR: docker container '$CONTAINER' is not running"
    exit 1
fi


# =========================================================
# Generate the per-node script
# =========================================================

generate_node_script() {
    local NODE="$1"
    local SCRIPT="$LOGDIR/$NODE.sh"

    cat > "$SCRIPT" <<EOF
#!/bin/bash
# -----------------------------------------------------------
# Verification script for node: $NODE
# Runs INSIDE the kitty window.
# -----------------------------------------------------------

set -u

CONTAINER="$CONTAINER"
SESSION="$SESSION"
NODE="$NODE"
PING_COUNT=$PING_COUNT
PING_TIMEOUT=$PING_TIMEOUT
MIN_SUCCESS=$MIN_SUCCESS
LOGDIR="$LOGDIR"

NODES=( ${NODES[*]} )

# Helper: run a command inside another node from the host
run_node() {
    local N="\$1"; shift
    docker exec "\$CONTAINER" vcmd -c "\$SESSION/\$N" -- bash -c "\$*"
}

# Helper: get a node's IPv4 address
get_ip() {
    local N="\$1"
    run_node "\$N" '
        ip -4 addr show scope global |
        awk "/inet / {print \\\$2}" |
        cut -d/ -f1 |
        head -n1
    '
}

echo "=================================================="
echo " Checking node: \$NODE"
echo " Session:      \$SESSION"
echo "=================================================="
echo

NODE_FAILED=0

# -----------------------------------------------------------
# [1/3] Environment  (sourced in THIS terminal's context)
# -----------------------------------------------------------
echo "[1/3] Loading TP1 environment..."

ENV_OUT=\$(run_node "\$NODE" '
    ENV_FILE=\$(find /root -maxdepth 5 -type f \\
        -path "*/esr/TP1/scripts/tp1-env.sh" \\
        -print -quit)

    if [ -z "\$ENV_FILE" ]; then
        echo "ERROR: tp1-env.sh not found"
        exit 10
    fi

    source "\$ENV_FILE"

    export GROUP=PL30
    export PROFILE=A

    echo "ENV_FILE=\$ENV_FILE"
    echo "GROUP=\$GROUP"
    echo "PROFILE=\$PROFILE"

    if [ "\$GROUP"   != "PL30" ]; then echo "ERROR: GROUP is not PL30"; exit 11; fi
    if [ "\$PROFILE" != "A"    ]; then echo "ERROR: PROFILE is not A";  exit 12; fi

    exit 0
')
ENV_STATUS=\$?

echo "\$ENV_OUT"

if [ \$ENV_STATUS -ne 0 ]; then
    echo "✗ Environment configuration FAILED (exit \$ENV_STATUS)"
    NODE_FAILED=1
else
    echo "✓ Environment configuration OK"
fi

# -----------------------------------------------------------
# IP
# -----------------------------------------------------------
IP=\$(get_ip "\$NODE")

echo
if [ -z "\$IP" ]; then
    echo "✗ Could not determine IP address"
    echo
    echo "✗ \$NODE FAILED"
    echo "FAIL" > "\$LOGDIR/\$NODE.status"
else
    echo "IP address: \$IP"

    # -------------------------------------------------------
    # [2/3] Connectivity
    # -------------------------------------------------------
    echo
    echo "[2/3] Checking connectivity..."
    echo "      Sending \$PING_COUNT pings"
    echo "      Minimum success: \${MIN_SUCCESS}%"
    echo

    for OTHER in "\${NODES[@]}"; do
        [ "\$OTHER" = "\$NODE" ] && continue

        OTHER_IP=\$(get_ip "\$OTHER")

        if [ -z "\$OTHER_IP" ]; then
            echo "  \$NODE -> \$OTHER: ✗ NO IP"
            NODE_FAILED=1
            continue
        fi

        echo -n "  \$NODE -> \$OTHER (\$OTHER_IP): "

        OK=0
        for _ in 1 2; do
            if run_node "\$NODE" "ping -c 1 -W \$PING_TIMEOUT \$OTHER_IP >/dev/null 2>&1"; then
                OK=1
                break
            fi
        done

        if [ "\$OK" -eq 1 ]; then
            echo "✓ ONLINE"
        else
            echo "✗ OFFLINE"
            NODE_FAILED=1
        fi
    done

    # -------------------------------------------------------
    # [3/3] Result
    # -------------------------------------------------------
    echo
    echo "[3/3] Node \$NODE complete"
    echo

    if [ "\$NODE_FAILED" -eq 0 ]; then
        echo "✓ \$NODE PASSED"
        echo "PASS" > "\$LOGDIR/\$NODE.status"
    else
        echo "✗ \$NODE FAILED"
        echo "FAIL" > "\$LOGDIR/\$NODE.status"
    fi
fi

# -----------------------------------------------------------
# Hand over to an interactive shell INSIDE the node, with
# the TP1 environment already sourced and exported.
# -----------------------------------------------------------
echo
echo "=================================================="
echo " Verification done."
echo " Dropping into an interactive shell on \$NODE"
echo " with the TP1 environment already loaded."
echo " Type 'exit' to close."
echo "=================================================="
echo

exec docker exec -it "\$CONTAINER" vcmd -c "\$SESSION/\$NODE" -- bash -lc '
    ENV_FILE=\$(find /root -maxdepth 5 -type f \
        -path "*/esr/TP1/scripts/tp1-env.sh" \
        -print -quit)
    [ -n "\$ENV_FILE" ] && source "\$ENV_FILE"
    export GROUP=PL30
    export PROFILE=A
    exec bash -l
'
EOF

    chmod +x "$SCRIPT"
}


# =========================================================
# Launch a kitty for a node
# =========================================================

open_kitty() {
    local NODE="$1"
    local SCRIPT="$LOGDIR/$NODE.sh"

    echo "→ Launching kitty for $NODE"

    kitty \
        --title "CORE: $NODE" \
        --single-instance \
        -o confirm_os_window_close=0 \
        bash "$SCRIPT" &
}


# =========================================================
# MAIN
# =========================================================

echo
echo "======================================================"
echo " CORE topology verification"
echo " Container: $CONTAINER"
echo " Session:   $SESSION"
echo " Nodes:     ${NODES[*]}"
echo "======================================================"
echo

for NODE in "${NODES[@]}"; do
    generate_node_script "$NODE"
done

for NODE in "${NODES[@]}"; do
    open_kitty "$NODE"
    sleep "$DELAY"
done

echo
echo "✓ All terminals launched."
echo "  Logs:    $LOGDIR/<node>.log"
echo "  Status:  $LOGDIR/<node>.status"
exit 0