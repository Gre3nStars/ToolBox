# -*- mode: python ; coding: utf-8 -*-
import sys ; sys.setrecursionlimit(65534)

a = Analysis(
    ['ToolBoxMainFrame.py'],
    pathex=[],
    binaries=[],
    datas=[("resource","resource"),("utils","utils"),("widgets","widgets")],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
	excludedimports=['py', 'pytest', 'jedi', 'IPython'],
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ToolBoxMainFrame',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
