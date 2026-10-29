"""Req2Test-Bench evaluation front-end.

The execution engine is the vendored snapshot under `benchmark/`
(`engine/UPSTREAM.json` records its source).  The package is installed from a
git clone with `pip install -e .`, because the engine locates its data and
verifies its own Docker authority relative to the clone.
"""
from pathlib import Path

__version__ = "1.1.0"

#: The git clone this package runs from.
REPO_ROOT = Path(__file__).resolve().parents[1]
#: The vendored engine's root; `PYTHONPATH` entry for `import r2t`.
ENGINE_ROOT = REPO_ROOT / "benchmark"
