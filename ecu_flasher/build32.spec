# -*- mode: python ; coding: utf-8 -*-
a = Analysis(
    ["seedkey_bridge.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PySide6", "cantools", "numpy", "can", "yaml", "tkinter", "IPython",
        "setuptools", "pkg_resources", "pip", "wheel", "distutils", "lib2to3",
        "unittest", "doctest", "pydoc", "test", "idlelib", "turtle", "curses",
        "ssl", "sqlite3", "xml", "http",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="ECUFlasher32",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    icon="NONE",
)

coll = COLLECT(
    exe, a.binaries, a.datas,
    strip=False,
    upx=True,
    upx_exclude=["vcruntime*.dll", "msvcp*.dll", "ucrtbase.dll", "python3*.dll"],
    name="ECUFlasher32",
)
