"""CapShare: revocable, capability-based file sharing over a local Wi-Fi network.

Layers (each in its own module, so beginners can read them one at a time):

    config.py    settings (paths, limits)
    errors.py    the exceptions the permission engine raises
    db.py        SQLite connection helpers, transactions, safe migrations
    acl.py       Linux POSIX ACL integration (setfacl / getfacl)
    engine.py    THE PERMISSION ENGINE: grants, delegation, revoke, expiry, access checks
    accounts.py  users, password hashing, login sessions, CSRF tokens
    storage.py   file storage inside the dedicated CapShare directory
    transfers.py live + historic LAN transfers, termination on revoke
    api.py       FastAPI routes (the only thing remote devices can talk to)
    server.py    app factory + LAN-only server runner
    lab.py       the five KO-13 challenge scenarios (C1..C5)
    gui/         PySide6 desktop frontend (talks to the backend over HTTP only)
"""

__version__ = "1.0.0"
