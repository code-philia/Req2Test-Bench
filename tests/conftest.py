"""Make the clone's `req2test` package and the vendored engine importable."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "benchmark"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
