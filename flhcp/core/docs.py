"""YAML/JSON document loading. YAML needs PyYAML; JSON always works."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_document(path: str | Path) -> Any:
    """Load a JSON document, or YAML when PyYAML is installed."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read file: {path} ({exc})") from exc
    suffix = path.suffix.lower()
    if suffix == ".json" or (suffix not in (".yaml", ".yml") and text.lstrip().startswith(("{", "["))):
        try:
            return json.loads(text)
        except ValueError as exc:
            raise ValueError(f"invalid JSON in {path}: {exc}") from exc
    try:
        import yaml
    except ImportError:
        raise ValueError(
            f"YAML file {path} needs PyYAML (pip install pyyaml) — or use JSON instead"
        ) from None
    try:
        return yaml.safe_load(text)
    except Exception as exc:
        raise ValueError(f"invalid YAML in {path}: {exc}") from exc


def dump_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, default=str)
