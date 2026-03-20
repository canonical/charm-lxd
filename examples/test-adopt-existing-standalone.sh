#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  test-adopt-existing-standalone.sh <model> <machine-id> [app-name]

This script exercises the standalone adoption flow on a single existing Juju
machine. It expects:

- the target machine already exists in the model
- the host is reachable with `juju ssh`
- a local charm artifact is available at ./lxd_ubuntu@24.04-amd64.charm

Flow:
1. Deploy the charm with `adopt-existing=true`
2. Show the blocked adoption state if LXD is installed but uninitialized
3. Run `lxd init --auto` on the machine
4. Remove and redeploy the charm to re-run the install-time adoption path
5. Hand control back to the normal management path with `adopt-existing=false`

Environment overrides:
  CHARM_PATH   Path to the charm artifact to deploy
EOF
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage
    exit 1
fi

MODEL="$1"
MACHINE_ID="$2"
APP_NAME="${3:-lxd-adopt-test}"
CHARM_PATH="${CHARM_PATH:-./lxd_ubuntu@24.04-amd64.charm}"

if [[ ! -f "${CHARM_PATH}" ]]; then
    echo "Charm artifact not found: ${CHARM_PATH}" >&2
    exit 1
fi

wait_for_app_idle() {
    local app="$1"
    while true; do
        if juju status --model "${MODEL}" "${app}" --format json \
            | python3 -c 'import json,sys; data=json.load(sys.stdin)["applications"]; app=next(iter(data.values())); units=app.get("units", {}); print("ready" if units and all(u.get("agent-status", {}).get("current") == "idle" for u in units.values()) else "wait")' \
            | grep -qx "ready"; then
            break
        fi
        sleep 3
    done
}

wait_for_app_removed() {
    local app="$1"
    while juju status --model "${MODEL}" "${app}" >/dev/null 2>&1; do
        sleep 3
    done
}

echo "Deploying ${APP_NAME} to machine ${MACHINE_ID} in model ${MODEL}"
juju deploy --model "${MODEL}" "${CHARM_PATH}" "${APP_NAME}" \
    --to "${MACHINE_ID}" \
    --config adopt-existing=true

wait_for_app_idle "${APP_NAME}"

echo
echo "Status after first deploy:"
juju status --model "${MODEL}" "${APP_NAME}"

echo
echo "Running 'lxd init --auto' on machine ${MACHINE_ID}"
juju ssh --model "${MODEL}" "${MACHINE_ID}" 'sudo lxd init --auto'

echo
echo "Removing ${APP_NAME} so the install hook can be re-run on the initialized host"
juju remove-application --model "${MODEL}" "${APP_NAME}"
wait_for_app_removed "${APP_NAME}"

echo
echo "Redeploying ${APP_NAME} with adopt-existing=true"
juju deploy --model "${MODEL}" "${CHARM_PATH}" "${APP_NAME}" \
    --to "${MACHINE_ID}" \
    --config adopt-existing=true

wait_for_app_idle "${APP_NAME}"

echo
echo "Status after adoption:"
juju status --model "${MODEL}" "${APP_NAME}"

echo
echo "Handing control back to the normal management path"
juju config --model "${MODEL}" "${APP_NAME}" adopt-existing=false
wait_for_app_idle "${APP_NAME}"

echo
echo "Final status:"
juju status --model "${MODEL}" "${APP_NAME}"
