# This file stays import-free: the confined backend stages a MIRROR of this
# package (`result_ledger_v2.BACKEND_SOURCE_RUNTIME_SHARED` plus the kind's
# driver and transport, `stage_backend_source_runtime`), and the sandbox
# executes every ancestor `__init__.py` of a staged module on import.  The
# staging refuses a package `__init__` holding anything but a docstring.
# Because the staged path of a file equals its path relative to this
# directory, a staged module may live in any sub-package whose `__init__`s
# are import-free -- `core/` and `confined/` today.
