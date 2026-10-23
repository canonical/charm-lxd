"""Make `src/charm.py` importable without the charm libraries fetched at build time."""

import importlib
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

# Charm libraries are fetched from Charmhub by charmcraft (see `charm-libs` in charmcraft.yaml)
# and are not vendored. Unit tests never instantiate these classes, so placeholders suffice.
_CHARM_LIB_STUBS = {
    "charms.grafana_k8s.v0.grafana_dashboard": "GrafanaDashboardProvider",
    "charms.loki_k8s.v0.loki_push_api": "LokiPushApiConsumer",
}


def _stub_charm_lib(module_name: str, class_name: str) -> None:
    try:
        importlib.import_module(module_name)
        return
    except ImportError:
        pass

    parts = module_name.split(".")
    for index in range(1, len(parts)):
        sys.modules.setdefault(".".join(parts[:index]), types.ModuleType(".".join(parts[:index])))

    module = types.ModuleType(module_name)
    setattr(module, class_name, type(class_name, (), {}))
    sys.modules[module_name] = module


for _module_name, _class_name in _CHARM_LIB_STUBS.items():
    _stub_charm_lib(_module_name, _class_name)
