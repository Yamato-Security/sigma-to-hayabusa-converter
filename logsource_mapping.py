"""Importable alias for the converter module.

The main tool keeps its documented filename ``sigma-to-hayabusa-converter.py``,
which contains hyphens and therefore cannot be loaded with a normal ``import``
statement. This thin wrapper loads that file under an importable name so the
unit tests (``from logsource_mapping import *``) and any other consumer can use
its functions and classes.
"""
import importlib.util
import os

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "_sigma_to_hayabusa_converter",
    os.path.join(_here, "sigma-to-hayabusa-converter.py"),
)
_module = importlib.util.module_from_spec(_spec)

# The converter reads ``ignore-uuid-list.txt`` relative to the current working
# directory at import time, so load it with the repo root as the CWD. This lets
# the import succeed no matter where the tests are run from.
_prev_cwd = os.getcwd()
try:
    os.chdir(_here)
    _spec.loader.exec_module(_module)
finally:
    os.chdir(_prev_cwd)

# Re-export the converter's public names so ``from logsource_mapping import *``
# behaves as though they were defined here.
globals().update({_k: _v for _k, _v in vars(_module).items() if not _k.startswith("_")})
