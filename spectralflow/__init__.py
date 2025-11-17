"""
Compatibility layer that keeps the historical ``spectralflow`` import path
working while the implementation lives inside the ``sush`` package.

The original codebase used ``spectralflow`` as the top-level package name.
During the current refactor everything was moved under ``sush``.  A lot of
third-party scripts – and even parts of this repository – still import the
old paths (e.g. ``spectralflow.core.quantum_obfuscator``).  Rather than force
callers to update immediately we expose a thin aliasing shim that simply
re-exports the modules from ``sush``.
"""

from __future__ import annotations

import importlib
import sys
from types import ModuleType

_PRIMARY_PACKAGE = "sush"

# Public symbols mirror the ``sush`` package so ``from spectralflow import *``
# behaves the same as ``from sush import *``.
_sush_module = importlib.import_module(_PRIMARY_PACKAGE)

__all__ = getattr(_sush_module, "__all__", [])

for attr in __all__:
    globals()[attr] = getattr(_sush_module, attr)


def _alias_module(alias: str, target: str) -> ModuleType:
    """Import *target* and register it under *alias* in ``sys.modules``."""
    module = importlib.import_module(target)
    sys.modules.setdefault(alias, module)
    return module


_MODULE_ALIASES = {
    "spectralflow.client": "sush.client",
    "spectralflow.server": "sush.server",
    "spectralflow.config_manager": "sush.config_manager",
    # Core layer
    "spectralflow.core": "sush.core",
    "spectralflow.core.adaptive_cipher": "sush.core.adaptive_cipher",
    "spectralflow.core.ml_kem": "sush.core.ml_kem",
    "spectralflow.core.quantum_obfuscator": "sush.core.quantum_obfuscator",
    "spectralflow.core.traffic_morphing": "sush.core.traffic_morphing",
    # Transport layer
    "spectralflow.transport": "sush.transport",
    "spectralflow.transport.adaptive_transport": "sush.transport.adaptive_transport",
    "spectralflow.transport.metadata_channels": "sush.transport.metadata_channels",
    "spectralflow.transport.protocol_hopper": "sush.transport.protocol_hopper",
    "spectralflow.transport.steganographic_channels": "sush.transport.steganographic_channels",
    # Network layer
    "spectralflow.network": "sush.network",
    "spectralflow.network.mirror_network": "sush.network.mirror_network",
    "spectralflow.network.mirror_node": "sush.network.mirror_node",
    "spectralflow.network.node_integrity": "sush.network.node_integrity",
    "spectralflow.network.node_integrity_simple": "sush.network.node_integrity_simple",
    "spectralflow.network.onion_routing": "sush.network.onion_routing",
    # Control layer
    "spectralflow.control": "sush.control",
    "spectralflow.control.adaptive_control": "sush.control.adaptive_control",
    "spectralflow.control.censorship_detector": "sush.control.censorship_detector",
    "spectralflow.control.response_engine": "sush.control.response_engine",
    "spectralflow.control.threat_monitor": "sush.control.threat_monitor",
}

# Pre-register all aliases so ``import spectralflow.foo.bar`` works even if the
# importer only looks at ``sys.modules`` after ``import spectralflow``.
for alias, target in _MODULE_ALIASES.items():
    _alias_module(alias, target)

# Ensure the package level appears in ``sys.modules`` under the alias too.
sys.modules.setdefault("spectralflow", sys.modules[__name__])


def __getattr__(name: str):
    """
    Lazy attribute access for modules that are part of the alias map.

    This allows ``spectralflow.some_module`` to resolve at attribute-access
    time even if the consumer never performs an explicit import.
    """
    target = f"{_PRIMARY_PACKAGE}.{name}"
    alias = f"spectralflow.{name}"
    if alias in _MODULE_ALIASES:
        return sys.modules[alias]

    try:
        module = _alias_module(alias, target)
    except ModuleNotFoundError as exc:
        raise AttributeError(f"module 'spectralflow' has no attribute {name!r}") from exc
    return module


def __dir__():
    """Expose the aliased attributes to interactive tools like ``dir()``."""
    base = set(globals())
    base.update(name.split(".")[-1] for name in _MODULE_ALIASES)
    return sorted(base)






