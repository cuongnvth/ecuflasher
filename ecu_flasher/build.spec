# -*- mode: python ; coding: utf-8 -*-
import os
from pathlib import Path

ROOT = Path(SPECPATH)

binaries = []
for src, dst in (
    ("vendor/vector/vxlapi64.dll", "."),
    ("vendor/vector/vxlapi.dll", "."),
    ("vendor/pcan/PCANBasic.dll", "."),
    ("vendor/pcan/PCANBasic_x64.dll", "."),
):
    p = ROOT / src
    if p.is_file(): binaries.append((str(p), dst))

datas = []

hiddenimports = [
    "can.interfaces.vector",
    "can.interfaces.pcan",
    "can.interfaces.virtual",
]

excludes = [
    "numpy", "asammdf", "yaml", "scipy", "pandas", "matplotlib", "PIL", "IPython", "pytest",
    "setuptools", "pkg_resources", "pip", "wheel", "distutils", "lib2to3",
    "unittest", "doctest", "pydoc", "test", "idlelib", "turtle", "tkinter",
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
    "PySide6.QtWebChannel", "PySide6.QtWebSockets", "PySide6.QtWebView",
    "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.Qt3DInput", "PySide6.Qt3DLogic",
    "PySide6.Qt3DAnimation", "PySide6.Qt3DExtras",
    "PySide6.QtQuick", "PySide6.QtQml", "PySide6.QtQuickWidgets", "PySide6.QtQuick3D",
    "PySide6.QtQuickControls2", "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets",
    "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtGraphs",
    "PySide6.QtDesigner", "PySide6.QtHelp", "PySide6.QtUiTools",
    "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets",
    "PySide6.QtPdf", "PySide6.QtPdfWidgets",
    "PySide6.QtSql", "PySide6.QtTest",
    "PySide6.QtBluetooth", "PySide6.QtNfc", "PySide6.QtPositioning", "PySide6.QtLocation",
    "PySide6.QtSensors", "PySide6.QtSerialPort", "PySide6.QtSerialBus",
    "PySide6.QtNetwork", "PySide6.QtNetworkAuth", "PySide6.QtHttpServer",
    "PySide6.QtSvg", "PySide6.QtSvgWidgets", "PySide6.QtPrintSupport",
    "PySide6.QtXml", "PySide6.QtConcurrent", "PySide6.QtRemoteObjects",
    "PySide6.QtScxml", "PySide6.QtStateMachine", "PySide6.QtTextToSpeech",
    "PySide6.QtSpatialAudio", "PySide6.QtAxContainer", "PySide6.QtDBus",
]

a = Analysis(
    ["ecu_flasher_app.py"],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=["rthook_vendor_dlls.py"],
    excludes=excludes,
    noarchive=False,
)

_DROP_LIBS = {
    "opengl32sw", "d3dcompiler_47",
    "qt6pdf", "qt6svg", "qt6network", "qt6opengl", "qt6quick", "qt6qml",
    "qt6qmlmodels", "qt6virtualkeyboard",
}
_KEEP_PLUGINS = {
    "platforms": {"qwindows", "qoffscreen", "qxcb", "qcocoa"},
    "imageformats": set(),
    "styles": None,
}

def _stem(name):
    base = name.rsplit("/", 1)[-1].split(".")[0]
    return base[3:] if base.startswith("lib") else base

def _keep(entry):
    name = str(entry[0]).replace("\\", "/").lower()
    parts = name.split("/")
    stem = _stem(name)
    if stem in _DROP_LIBS:
        return False
    if "pyside6" in parts and "plugins" in parts:
        i = parts.index("plugins")
        if i + 2 < len(parts):
            allowed = _KEEP_PLUGINS.get(parts[i + 1], set())
            if allowed is not None and stem not in allowed:
                return False
    if name.endswith(".qm") and "translations" in parts:
        return False
    return True

def _prune(toc, label):
    kept, dropped = [], []
    for entry in toc:
        (kept if _keep(entry) else dropped).append(entry)
    saved = 0
    for entry in dropped:
        try: saved += os.path.getsize(entry[1])
        except OSError: pass
    print(f"[SIZE] {label}: pruned {len(dropped)} files, {saved / 1048576:.1f} MB")
    return kept

a.binaries = _prune(a.binaries, "binaries")
a.datas = _prune(a.datas, "datas")

pyz = PYZ(a.pure, a.zipped_data)

UPX_EXCLUDE = [
    "vcruntime*.dll", "msvcp*.dll", "ucrtbase.dll", "python3*.dll",
    "Qt6*.dll", "qwindows.dll", "pyside6*.dll", "shiboken6*.dll",
    "vxlapi*.dll", "PCANBasic*.dll",
]

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="ECUFlasher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon="NONE",
    version="version_info.txt",
)

coll = COLLECT(
    exe, a.binaries, a.datas,
    strip=False,
    upx=True,
    upx_exclude=UPX_EXCLUDE,
    name="ECUFlasher",
)
