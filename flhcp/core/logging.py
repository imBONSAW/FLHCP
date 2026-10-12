"""Logging setup: console + optional rotating file."""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path


def setup_logging(level: str = "INFO", logfile: str = "") -> logging.Logger:
    logger = logging.getLogger("flhcp")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(getattr(logging, level.upper(), logging.INFO))
    console.setFormatter(logging.Formatter("%(levelname)-7s %(name)s: %(message)s"))
    logger.addHandler(console)
    if logfile:
        path = Path(logfile)
        path.parent.mkdir(parents=True, exist_ok=True)
        rotating = logging.handlers.RotatingFileHandler(
            path, maxBytes=1_048_576, backupCount=3, encoding="utf-8"
        )
        rotating.setLevel(logging.DEBUG)
        rotating.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        logger.addHandler(rotating)
    return logger
