"""Shared test helpers."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path


def temp_root(testcase: unittest.TestCase) -> Path:
    path = Path(tempfile.mkdtemp(prefix="flhcp-test-"))
    testcase.addCleanup(shutil.rmtree, path, ignore_errors=True)
    return path
