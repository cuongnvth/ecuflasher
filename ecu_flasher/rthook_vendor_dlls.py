"""Runtime hook: đảm bảo DLL bundle được tìm thấy."""
import os
import sys
from pathlib import Path

def _add(path):
    if not path.is_dir(): return
    if hasattr(os, "add_dll_directory"):
        try: os.add_dll_directory(str(path))
        except OSError: pass
    cur = os.environ.get("PATH", "")
    s = str(path)
    if s not in cur.split(os.pathsep):
        os.environ["PATH"] = s + os.pathsep + cur

def _install():
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    else:
        base = Path(__file__).resolve().parent
    _add(base)
    for sub in ("vendor/vector", "vendor/pcan", "vendor"):
        _add(base / sub)

_install()
