# CapShare — revocable file sharing over Wi-Fi

CapShare is a Linux desktop app that shares **selected files directly with another device on
the same Wi-Fi** using *capabilities*: one file, one recipient, a set of actions
(`READ` / `WRITE`), an optional delegation right, an optional logical expiry and a parent.
It has a real backend permission engine, real file storage, real POSIX ACL integration
and a real TCP file transfer. **No cloud, no internet.**

* Python 3, **PySide6** desktop UI, **FastAPI** backend/LAN service, **SQLite**
* Linux **`setfacl` / `getfacl`** for local operating-system permissions
* Transfers are plain HTTP over TCP between two devices on your private network

> New to this? Read [Quick start](#1-quick-start-ubuntu-vm) then
> [Two-device walkthrough](#3-two-device-wi-fi-walkthrough). Everything else is reference.

---

## 0. Quick start on Windows 10/11

Everything works on Windows **except the real Linux ACLs** (`setfacl`/`getfacl` do not exist
there; the app says so in its header and the Lab shows the simulated version). For the full
Linux-permission demo use Ubuntu (section 1).

1. Install **Python 3.12** from python.org (tick *Add python.exe to PATH*).
   (MSYS2 Python also works if its `fastapi`, `requests` and `pyside6` packages are installed.)
2. Right-click **`setup_windows.ps1` → Run with PowerShell** (once). It creates a private
   environment in `%USERPROFILE%\.capshare-venv`, installs the packages, creates the demo
   accounts and runs a self-test of the five challenges.
3. Double-click **`CapShare.bat`** to start the app and sharing service.
   Sign in as `olivia` / `capshare-demo`; the **Transfers** page shows the address and QR code.
4. *(Only if another device cannot connect)* right-click **`open_firewall_windows.ps1` → Run with
   PowerShell**. It adds one rule: TCP 8765-8775, local subnet only, Private networks only.
   Your Wi-Fi must be marked *Private* (Settings → Network & internet → Wi-Fi → network profile).
5. Run all automated checks by double-clicking **`run_checks.bat`**.

Other commands: `CapShare.bat serve` (service only), `CapShare.bat lab` (challenges in a
window), `CapShare.bat gui --client http://<ip>:8765` (client for another computer),
`CapShare.bat reset --yes` (delete all CapShare data).

---

## 1. Quick start (Ubuntu VM)

Target: Ubuntu 22.04 / 24.04 desktop (VirtualBox, VMware or bare metal).

```bash
# in the project folder
chmod +x setup_ubuntu.sh run.sh run_checks.sh scripts/acl_demo.sh
./setup_ubuntu.sh        # asks before each sudo command, creates .venv, seeds demo accounts
./run.sh                 # opens the desktop app AND starts the sharing service
./run_checks.sh          # runs all automated checks (temporary databases only)
```

What `setup_ubuntu.sh` does with `sudo` (it asks `[y/N]` before each one):

| Command | Why |
|---|---|
| `sudo apt update` | refresh the package list |
| `sudo apt install -y python3 python3-venv python3-pip acl lib…` | Python + venv, the **`acl`** package (`setfacl`, `getfacl`) and the shared libraries Qt needs to open a window |
| `sudo ufw allow from <your subnet> to any port 8765 proto tcp` *(optional)* | let other devices on **your** subnet reach the port — never the whole internet |

Nothing else runs as root. `scripts/acl_demo.sh` additionally uses `sudo useradd` / `sudo -u` /
`sudo userdel` for two throw-away users (explained at the top of that script).

**Launch variants**

```bash
./run.sh                              # sender: desktop app + service
./run.sh --client http://192.168.1.23:8765   # recipient: desktop app only, connects to the sender
./run.sh serve                        # service only (headless VM, use a browser as client)
./run.sh lab                          # run the 5 challenge scenarios in the terminal
./run.sh accounts                     # list accounts
./run.sh passwd alice                 # change a password
./run.sh reset --yes                  # wipe all CapShare data (see Reset)
```

Data lives in `~/.capshare/` (`capshare.db`, `storage/`). Override with `CAPSHARE_HOME`.

---

## 2. Demo accounts

Created on first start. **Demo credentials — change them (`./run.sh passwd <user>`) before using
CapShare on a Wi-Fi network you do not trust.**

| Username | Role | Password |
|---|---|---|
| `olivia` | owner + administrator (sample file `welcome.txt`) | `capshare-demo` |
| `alice`, `bob`, `carol`, `dave` | ordinary users / recipients | `capshare-demo` |

> **CapShare accounts are not Linux users.** A remote device logs in with a CapShare account and
> is judged by the capability engine. Only an account that the administrator explicitly **maps**
> to an existing local Linux user (Share page → *People* → *Map selected to Linux user…*) also gets
> POSIX ACL entries. A remote device never gets an operating-system account.

---

## 3. Two-device Wi-Fi walkthrough

You need two computers (or a VM and your phone/laptop) on the **same Wi-Fi/LAN**.

**A. Network prerequisites**

* Real machines: connect both to the same Wi-Fi.
* VirtualBox VM: *Settings → Network → Adapter 1 → Attached to: **Bridged Adapter*** and pick your
  Wi-Fi card. (NAT hides the VM from other devices.) VMware: *Bridged*.
* Check the VM has a LAN address: `ip -4 addr show | grep inet` → e.g. `192.168.1.23`.
* Some guest/hotspot Wi-Fi networks block device-to-device traffic ("client isolation"); use a
  normal home network or your phone's hotspot if the second device cannot connect.

**B. Device 1 — the sender**

1. `./run.sh` and sign in as **olivia** / `capshare-demo`.
2. Open **Transfers**. The *Connect a recipient device* card shows the **Wi-Fi address, port and a QR
   code**, e.g. `http://192.168.1.23:8765/` (Copy link button included).
3. Make a real test file and note its checksum:
   ```bash
   head -c 5M /dev/urandom > ~/capshare-test.bin
   sha256sum ~/capshare-test.bin
   ```
4. **Files → Add file…** → choose `capshare-test.bin`. It is copied into `~/.capshare/storage/`.
5. **Share**: file = `capshare-test.bin`, recipient = **Bob**, tick **READ** only, leave delegation
   off → **Create capability**.

**C. Device 2 — the recipient** (pick one)

* *Browser:* open `http://192.168.1.23:8765/`, sign in as **bob** / `capshare-demo`.
  The file appears with a `READ` chip. Click **Download**, then verify:
  `sha256sum ~/Downloads/capshare-test.bin` — must equal the value from step B3.
* *CapShare client (Linux):* copy the project over, run
  `./run.sh --client http://192.168.1.23:8765`, sign in as bob, **Files → Download…**.

**D. Prove the permission engine**

1. On Device 2 (bob) try **Upload new version** → refused: *"WRITE denied: the user's active
   capabilities only allow READ."* Back on Device 1, **Activity** shows the denied attempt;
   **Transfers** lists the denied transfer.
2. Device 1: **Transfers → Demo slow mode** → 100 ms → *Apply*. Device 2: start the download of the
   5 MiB file again. While it runs, Device 1: **Permission lineage** → select Bob's row →
   **Revoke selected…**. The download on Device 2 **fails mid-way** (incomplete file) and Device 1
   shows the transfer as *terminated*.
3. Honest limit: bytes Bob already downloaded before the revoke stay on Bob's device.
   Revocation cannot erase copies.

**E. Firewall (only if Device 2 cannot connect)**

```bash
sudo ufw status                                     # is ufw active?
sudo ufw allow from 192.168.1.0/24 to any port 8765 proto tcp
```
Use *your* subnet. Do **not** open the port to `Anywhere`.

---

## 4. The interface

| Page | What it does (every control calls a real backend route) |
|---|---|
| **Files** | Add a file (upload to storage), adopt a file dropped into the storage directory (admin), download, upload a new version (needs WRITE), shows owner, size, my access, expiry, **who has access**, `getfacl` output and *Retry ACL sync* |
| **Share** | Create one capability: file, authority (owner / delegate from #N / automatic), recipient, READ/WRITE, delegation allowed?, optional logical expiry. Admin: create accounts, map to a Linux user |
| **Permission lineage** | Every grant: parent, recipient, grantor, actions, delegate flag, depth, expiry, **active / revoked / expired**, reason. *Revoke* shows affected count, descendants, traversal method, elapsed ms |
| **Access check** | Pick file + user + READ/WRITE → the backend's real decision, reason, and every grant path. Also the owner's **logical clock** |
| **Transfers** | Connect info (address, port, QR), live incoming/outgoing transfers with progress, completed, terminated and **denied** attempts, demo slow mode |
| **Challenge Lab** | The five KO-13 challenges, step by step with before/after lineage, ACL operations and activity |
| **Activity** | Audit trail: grants, denied escalation attempts, access checks, transfers, expiry, revocation, cascade work |

The **browser transfer page** (`http://<ip>:8765/`) is a responsive page for recipients:
sign in, see files and your capabilities, download, upload, watch transfers.

---

## 5. KO-13 challenge walkthrough

Open **Challenge Lab** → pick **C1…C5** → *Run*. (Or `./run.sh lab`, or
`./run_checks.sh` for the assertions.) Each run uses the **real engine on a throw-away database**,
so your saved data is never touched. Linux ACL calls are *simulated* there and listed in the
*Linux ACL operations* tab; the real `setfacl` demonstration is `scripts/acl_demo.sh`.

| | Scenario | What you see |
|---|---|---|
| **C1** Delegation & cascade | O grants A delegable READ; A grants B READ. B is denied WRITE; A cannot give B WRITE (escalation, audited). O revokes A's grant. | Lineage *before* (2 active) / *after* (2 revoked); B's READ → `CAPABILITY_REVOKED` |
| **C2** Independent path | O also gives B a direct READ. Revoke only A's root. | Two lineages for B; after the revoke B still reads via the owner-issued grant; B's ACL entry is **kept** until the last path goes |
| **C3** Bounded lineage | Max **4 edges** (owner's grant = edge 1); 5th rejected `DEPTH_LIMIT`. A **130-descendant** subtree. `EXPLAIN QUERY PLAN` proves the `parent_id` index is used. Ceiling demo. | Report: affected 131, descendants 130, method, elapsed ms; oversized cascade refused with **zero changes** |
| **C4** Concurrent delegate/revoke | First the **vulnerable** check-then-insert is reproduced (an active child under a revoked parent). Then the real engine in both orders, forced with pause hooks. | Ordering 1: child created *then* cascaded. Ordering 2: creation rejected `PARENT_REVOKED`. Invariant: 0 orphans |
| **C5** Logical-clock expiry | Parent READ expires at t=10. | t=9 allowed; t=10 and t=11 denied; child expiring at 20 rejected; permanent child rejected; clock cannot go backwards. Clock/expiry/decisions shown in the UI and Activity |

You can also reproduce C5 by hand: Share → tick *Expires at logical time* = 10 → Access check →
*Set my clock* to 9, then 10.

---

## 6. Real Linux ACLs: `getfacl` and allowed/denied operations

```bash
./scripts/acl_demo.sh
```

It creates two temporary system users (`capshare_alice`, `capshare_bob`), runs a short story
with the real engine and real `setfacl`, then removes the users. For every step it prints the
`getfacl` output and the result of `cat` / append **executed as each Linux user via
`sudo -u`**, marking each ✔ or ✘ UNEXPECTED. Representative `getfacl` after "owner grants
alice READ" (paths differ on your machine):

```
# file: tmp/capshare-acl-demo-x1/home/storage/3f9c…e1.bin
user::rw-
user:capshare_alice:r--
group::---
mask::r--
other::---
```
Expected operation results: alice `cat` → **ALLOWED**, alice append → **DENIED (Permission
denied)**, bob `cat` → **DENIED** until alice delegates to bob; after the owner revokes alice,
both entries disappear (cascade) and both are denied; in the independent-path step bob's entry
**survives** the revoke of alice's root.

**Directory traversal.** An ACL on a file is useless if the user cannot *reach* it, so CapShare
also gives a mapped user `--x` (search, not list) on the storage directory and on the parent
directories the service user owns (`~/.capshare`, `~`), and removes those entries again when the
user's last file entry goes. Files are stored under random names (`<uuid>.bin`), so `--x` does
not reveal names.

### Who enforces what

| Check | Enforced by |
|---|---|
| Login, session, CSRF, size limit | **CapShare network service** |
| Capability exists, actions ⊆ parent, delegation right, depth ≤ 4, expiry, revocation cascade, independent paths | **CapShare network service** (engine, one SQLite transaction) |
| A remote device receiving/sending bytes | **CapShare network service** — only after a positive decision, re-checked every 64 KiB |
| A *local* Linux user opening/reading/writing the stored file | **Linux kernel** (mode bits + POSIX ACL + directory `x`) |
| Which Linux users have ACL entries | **CapShare** computes it (union over all valid grant paths); **the kernel** applies it |
| Reading a file already downloaded to another device | **Nobody** — outside any system's control |

---

## 7. Security measures

* Prepared (parameterised) SQL only; values are never concatenated into SQL.
* Path canonicalization: stored names are random; `Storage.resolve()` rejects `..`, separators,
  absolute paths and symlinks that leave the storage directory.
* Upload limit (default 100 MiB, `CAPSHARE_MAX_MB`); partial uploads are deleted.
* Sessions: random token in an `HttpOnly; SameSite=Strict` cookie, only its hash is stored;
  PBKDF2-SHA256 password hashes; login throttling.
* CSRF: every state-changing request needs the per-session `X-CSRF-Token` header **and** a matching
  `Origin` if one is sent.
* Safe errors: clients get a code + short message; internals go only to the server log.
* LAN only: the service binds to `127.0.0.1` and **one private (RFC 1918) address**, never
  `0.0.0.0`, and refuses clients outside private/loopback/link-local ranges. Security headers
  (CSP, `nosniff`, `X-Frame-Options`) are set. There is no TLS — see Limitations.
* Audit: successful **and** denied operations are recorded.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| Window does not open / `xcb` plugin error | `./setup_ubuntu.sh` (installs `libxcb-cursor0` etc.). Over SSH use `./run.sh serve` and a browser instead |
| Transfers page says "only reachable from this computer" | No private address found. Connect to Wi-Fi (VM: **Bridged** adapter) and restart |
| Other device times out | Same Wi-Fi? Client isolation? Firewall rule (section 3E). Test: `curl http://IP:8765/api/health` |
| Wrong address shown (VM with several adapters) | CapShare binds every private address it finds; force one with `CAPSHARE_HOST=192.168.1.23 ./run.sh` |
| Port busy | CapShare tries 8765…8775 and prints the port it used; or `CAPSHARE_PORT=9000 ./run.sh` |
| "ACL integration disabled" | `sudo apt install acl`, restart. On a filesystem without ACL support `setfacl` reports "Operation not supported" |
| "ACL INCONSISTENCY" in a revoke report | The DB revoke **did** happen and the service denies access, but `setfacl` failed so the OS entry may remain. Fix the cause, then *Files → Retry ACL sync* |
| "could not map to Linux user" | The user must already exist (`id <name>`), not be root, and not be the account running CapShare |
| Login refused after many tries | 6 failures/minute/username lock for a minute |
| `database schema … is newer` | You are running an older CapShare against a newer DB; never downgrade |

---

## 9. Limitations (read these)

* **Revocation cannot erase a copy** already downloaded by another device.
* **No TLS.** Traffic is plain HTTP on your LAN; anyone on the same network segment who can sniff
  it can read the file and the session cookie. Use a network you trust (a private hotspot), or put a
  TLS reverse proxy in front for real use.
* The logical clock is **owner-controlled and manual**; it is *not* wall-clock time.
* Linux ACLs apply only to **mapped local Linux users**; remote devices are controlled by the
  service alone. If a mapped Linux user edits the file directly (allowed by WRITE), the database size
  is refreshed from `stat` but the stored checksum is not recomputed until the next upload.
* A grant derives from exactly one parent; to give someone READ+WRITE through different paths,
  create two capabilities.
* The service runs one process with a SQLite database — intended for a demo/home network, not for
  hundreds of concurrent users.
* Demo mode: fixed demo passwords, `capshare-demo`.
* Developed and automatically tested with a simulated ACL backend plus the Windows/MSYS2 Python;
  the real-`setfacl` tests (`tests/test_acl_linux.py`, `scripts/acl_demo.sh`) run on Linux only and
  are skipped elsewhere.

---

## 10. Reset

```bash
./run.sh reset --yes          # deletes ~/.capshare (database + all managed files)
# or manually:
rm -rf ~/.capshare
```
Demo accounts and the sample file are re-created on next start. ACL entries that CapShare added
to the files disappear with the files; entries it added to `~` and `~/.capshare` are removed when the
last file entry for that user goes — if CapShare was killed mid-way, clean up with
`setfacl -R -b ~/.capshare` and, for the home directory, `setfacl -x u:<name> ~`.

---

## 11. Project layout and checks

```
capshare/            backend + shared code (see docs/ARCHITECTURE.md)
  engine.py          THE permission engine      acl.py    POSIX ACL integration
  db.py              SQLite + migrations        lab.py    KO-13 scenarios C1..C5
  api.py server.py   FastAPI routes / LAN server
  static/            responsive browser transfer page
  gui/               PySide6 desktop frontend (talks to the backend over HTTP only)
tests/               automated checks
scripts/             acl_demo.sh, acl_demo.py
setup_ubuntu.sh  run.sh  run_checks.sh  requirements.txt
```

```bash
./run_checks.sh                                  # everything
python3 -m unittest tests.test_challenges -v     # only the five challenges
python3 -m unittest discover -s tests -v         # same as run_checks.sh
```

The suite covers upload, download, access denial, delegation, escalation, revocation, expiry,
the five challenges (incl. a multi-threaded stress test of the C4 invariant), CSRF, safe errors,
size limits, path confinement, migrations, ACL bookkeeping with injected `setfacl` failures, and
(on Linux) real `getfacl` results. Every test builds its own temporary home, so **real data and the
saved demo database are never touched**.
