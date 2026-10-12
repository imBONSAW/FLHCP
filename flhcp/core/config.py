"""Runtime configuration with safe defaults (JSON or YAML file)."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from flhcp.core.docs import load_document

DEFAULTS: dict[str, Any] = {
    "interface": "",
    "server_address": "127.0.0.1",
    "server_port": 6767,
    "client_port": 6768,
    "offer_timeout": 3.0,
    "ack_timeout": 3.0,
    "attempts": 2,
    "workers": 32,
    "logging": {"level": "INFO", "file": ""},
    "output": {"dir": "sessions", "formats": ["terminal"]},
}


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


class Config:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.data: dict[str, Any] = copy.deepcopy(DEFAULTS)

    def load(self) -> dict[str, Any]:
        if self.path is None or not self.path.is_file():
            self.data = copy.deepcopy(DEFAULTS)
            return self.data
        doc = load_document(self.path)
        if not isinstance(doc, dict):
            raise ValueError(f"config {self.path} must hold an object")
        self.data = _merge(copy.deepcopy(DEFAULTS), doc)
        return self.data

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node
