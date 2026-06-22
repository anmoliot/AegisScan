"""Root conftest — ensures `backend/` is on sys.path so `app` is importable."""

import pathlib
import sys

_backend_dir = pathlib.Path(__file__).resolve().parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))
