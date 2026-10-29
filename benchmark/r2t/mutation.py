"""`r2t.mutation` is `r2t.data.mutation` (wave M5) under its old name: the
frozen, byte-pinned enumerator `r2t/py/mutate.py` imports `..mutation` in
its self-test and cannot be edited, so this one line stays."""
from .data.mutation import *  # noqa: F401,F403
