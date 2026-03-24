#!/usr/bin/env bash

set -euo pipefail

MODEL="${1:-ci-adoption-readme}"
CHARM_PATH="${2:-./lxd_ubuntu@24.04-amd64.charm}"
STEP_NAME="README adoption examples"

if [[ ! -f "${CHARM_PATH}" ]]; then
    echo "Charm artifact not found: ${CHARM_PATH}" >&2
    exit 1
fi

debug() {
    local rc="$?"

    {
        echo "# === ${STEP_NAME} ends === #"
        juju status --model "${MODEL}" --relations
        juju debug-log --model "${MODEL}" --replay --level debug
    } >> juju-debug.log 2>&1 || true

    exit "${rc}"
}

trap debug err exit
echo "# === ${STEP_NAME} starts === #" >> juju-debug.log

parse_machine_id() {
    python3 -c '
import json
import re
import sys

text = sys.stdin.read()
try:
    data = json.loads(text)
except json.JSONDecodeError:
    data = None

if isinstance(data, dict):
    for key in ("machine", "id"):
        value = data.get(key)
        if isinstance(value, (int, str)) and str(value):
            print(value)
            raise SystemExit(0)

match = re.search(r"\b(\d+)\b", text)
if match:
    print(match.group(1))
    raise SystemExit(0)

raise SystemExit("unable to determine machine id")
'
}

wait_for_machine_ready() {
    local machine_id="$1"
    local deadline=$((SECONDS + 900))

    while (( SECONDS < deadline )); do
        if juju status --model "${MODEL}" --format json | python3 -c '
import json
import sys

machine_id = sys.argv[1]
data = json.load(sys.stdin).get("machines", {}).get(machine_id, {})
instance = data.get("instance-status", {}).get("current")
juju_status = data.get("juju-status", {}).get("current")
agent_status = data.get("agent-status", {}).get("current")
if instance == "running" and (juju_status in {"started", "idle"} or agent_status in {"started", "idle"}):
    raise SystemExit(0)
raise SystemExit(1)
' "${machine_id}"
        then
            return 0
        fi
        sleep 5
    done

    echo "Timed out waiting for machine ${machine_id} to become ready" >&2
    juju status --model "${MODEL}" >&2 || true
    return 1
}

wait_for_app_status() {
    local app="$1"
    local status="$2"
    local deadline=$((SECONDS + 1200))

    while (( SECONDS < deadline )); do
        if juju status --model "${MODEL}" --format json | python3 -c '
import json
import sys

app_name = sys.argv[1]
expected = sys.argv[2]
app = json.load(sys.stdin).get("applications", {}).get(app_name, {})
units = app.get("units", {})
app_status = app.get("application-status", {}).get("current")

def unit_ready(unit):
    workload = unit.get("workload-status", {}).get("current")
    juju_status = unit.get("juju-status", {}).get("current")
    agent_status = unit.get("agent-status", {}).get("current")
    return workload == expected and (juju_status == "idle" or agent_status == "idle")

if app_status == expected and units and all(unit_ready(unit) for unit in units.values()):
    raise SystemExit(0)
raise SystemExit(1)
' "${app}" "${status}"
        then
            juju status --model "${MODEL}" "${app}"
            return 0
        fi
        sleep 5
    done

    echo "Timed out waiting for ${app} to become ${status}" >&2
    juju status --model "${MODEL}" "${app}" >&2 || true
    return 1
}

assert_unit_message_contains() {
    local app="$1"
    local expected="$2"

    juju status --model "${MODEL}" --format json | python3 -c '
import json
import sys

app_name = sys.argv[1]
expected = sys.argv[2]
units = json.load(sys.stdin).get("applications", {}).get(app_name, {}).get("units", {})
message = next(iter(units.values())).get("workload-status", {}).get("message", "")
if expected not in message:
    raise SystemExit(f"expected {expected!r} in unit status message, got {message!r}")
' "${app}" "${expected}"
}

add_machine() {
    local output
    output="$(juju add-machine --model "${MODEL}" --format json)"
    parse_machine_id <<<"${output}"
}

prepare_existing_host() {
    local machine_id="$1"
    local initialize="${2:-false}"

    juju ssh --model "${MODEL}" "${machine_id}" "sudo snap install lxd"
    if [[ "${initialize}" == "true" ]]; then
        juju ssh --model "${MODEL}" "${machine_id}" "sudo lxd init --auto"
    fi
}

assert_open_port() {
    local app="$1"
    local port="$2"

    juju exec --model "${MODEL}" --unit "${app}/leader" -- opened-ports | grep -x "${port}/tcp"
}

assert_has_default_storage_pool() {
    local app="$1"

    juju exec --model "${MODEL}" --unit "${app}/leader" -- lxc storage list --format csv \
        | grep -q '^default,'
}

echo "Creating model ${MODEL}"
juju add-model "${MODEL}"
juju model-config --model "${MODEL}" logging-config="<root>=WARNING;unit=DEBUG"

echo "Creating blank, uninitialized, and initialized target machines"
BLANK_MACHINE="$(add_machine)"
UNINITIALIZED_MACHINE="$(add_machine)"
INITIALIZED_MACHINE="$(add_machine)"

wait_for_machine_ready "${BLANK_MACHINE}"
wait_for_machine_ready "${UNINITIALIZED_MACHINE}"
wait_for_machine_ready "${INITIALIZED_MACHINE}"

echo "Preparing existing LXD hosts"
prepare_existing_host "${UNINITIALIZED_MACHINE}" false
prepare_existing_host "${INITIALIZED_MACHINE}" true

echo "Testing blank-host README example"
juju deploy --model "${MODEL}" "${CHARM_PATH}" lxd-blank \
    --to "${BLANK_MACHINE}" \
    --config adopt-existing=true
wait_for_app_status lxd-blank active
assert_has_default_storage_pool lxd-blank

echo "Testing installed-but-uninitialized README example"
juju deploy --model "${MODEL}" "${CHARM_PATH}" lxd-uninitialized \
    --to "${UNINITIALIZED_MACHINE}" \
    --config adopt-existing=true
wait_for_app_status lxd-uninitialized blocked
assert_unit_message_contains lxd-uninitialized "does not appear initialized"

echo "Testing initialized-standalone README example"
juju deploy --model "${MODEL}" "${CHARM_PATH}" lxd-initialized \
    --to "${INITIALIZED_MACHINE}" \
    --config adopt-existing=true
wait_for_app_status lxd-initialized active
assert_has_default_storage_pool lxd-initialized

echo "Confirming adopted host resumes normal config management"
juju config --model "${MODEL}" lxd-initialized lxd-listen-https=true
wait_for_app_status lxd-initialized active
assert_open_port lxd-initialized 8443

echo "Cleaning up ${MODEL}"
juju destroy-model --destroy-storage --force --no-prompt "${MODEL}"
