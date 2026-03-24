#!/usr/bin/env bash

set -euo pipefail

if ! command -v charmcraft >/dev/null 2>&1; then
    echo "charmcraft is required to fetch charm libraries" >&2
    exit 1
fi

charmcraft fetch-lib charms.grafana_k8s.v0.grafana_dashboard
charmcraft fetch-lib charms.loki_k8s.v0.loki_push_api
