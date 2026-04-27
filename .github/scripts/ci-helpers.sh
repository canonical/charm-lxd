#!/bin/bash
set -euo pipefail

debug() {
  rc="$?"
  (
    set +e
    echo "# === debug-log start === #"
    juju debug-log --replay --level debug
    echo "# === debug-log end === #"
    echo "# === relations start === #"
    juju status --relations
    echo "# === relations end === #"
  ) >> juju-debug.log
  exit "$rc"
}

# Collect debug information on error or exit
trap debug err exit

waitForApps() {
  for app in "${@}"; do
    juju wait-for application "${app}" --query='life=="alive" && status=="active" && forEach(units, unit => unit.workload-status == "active" && unit.agent-status == "idle")' || true
  done
  juju status --relations
}

checkOnlineMembers() {
  local node_created="${1}"
  local node_joined
  node_joined="$(juju exec --unit lxd/leader -- lxc cluster list --format csv | grep -cF ',ONLINE,Fully operational')"
  [ "${node_joined}" -eq "${node_created}" ]
}

checkForErrors() {
  if juju status --format=oneline | grep -qF workload:error; then
    echo "Juju failed to deploy"
    juju status --format=oneline
    exit 1
  fi
}
