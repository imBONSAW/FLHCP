"""Session storage: sessions/YYYY-MM-DD-HH-MM/{session,clients,leases}.json + events.log."""

from __future__ import annotations

import datetime as _dt
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def session_stamp() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d-%H-%M")


class Storage:
    def __init__(self, root: str | Path) -> None:
        # root IS the sessions directory (callers pass <project>/sessions);
        # subdirectories are created on demand by new_session_dir/write_json.
        self.root = Path(root)

    def new_session_dir(self, stamp: str | None = None) -> Path:
        base = self.root / (stamp or session_stamp())
        target, index = base, 2
        while target.exists():
            target = Path(f"{base}-{index}")
            index += 1
        target.mkdir(parents=True, exist_ok=True)
        (target / "events.log").write_text("", encoding="utf-8")
        return target

    def write_json(self, path: str | Path, payload: Any) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True, default=str)
                handle.write("\n")
            os.replace(tmp, path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return path

    def append_event(self, session_dir: str | Path, line: str) -> None:
        path = Path(session_dir) / "events.log"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{_dt.datetime.now().isoformat(timespec='seconds')} {line}\n")

    def list_sessions(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return sorted(p.name for p in self.root.iterdir() if p.is_dir())

    def read_json(self, path: str | Path) -> Any:
        return json.loads(Path(path).read_text(encoding="utf-8"))
