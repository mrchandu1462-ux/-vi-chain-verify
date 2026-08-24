"""
Import bridge for the Phase-B corpus.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

CORPUS_PATH = (
    Path(__file__).resolve().parent
    / "tests"
    / "phase-b"
    / "corpus.py"
)

spec = importlib.util.spec_from_file_location(
    "phase_b_corpus",
    CORPUS_PATH,
)

if spec is None or spec.loader is None:
    raise ImportError(f"Unable to load {CORPUS_PATH}")

module = importlib.util.module_from_spec(spec)
sys.modules["phase_b_corpus"] = module
spec.loader.exec_module(module)

get_vectors = module.get_vectors
