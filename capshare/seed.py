"""Demo accounts, created once on first start (or by `python -m capshare seed`).

These are DEMO credentials documented in the README. Change them with
`python -m capshare passwd <user>` before using CapShare on a network you do not trust.
"""
from __future__ import annotations

from .context import AppContext

DEMO_PASSWORD = "capshare-demo"
DEMO_USERS = [
    # username, display name, is_admin
    ("olivia", "Olivia (owner / admin)", True),
    ("alice", "Alice", False),
    ("bob", "Bob", False),
    ("carol", "Carol", False),
    ("dave", "Dave", False),
]


def seed_demo(ctx: AppContext) -> list[str]:
    """Create the demo accounts that do not exist yet. Returns the names created."""
    created = []
    for username, display, is_admin in DEMO_USERS:
        if not ctx.accounts.by_username(username):
            ctx.accounts.create_user(username, display, DEMO_PASSWORD, is_admin=is_admin)
            created.append(username)
    if created and not ctx.engine.list_files(ctx.accounts.by_username("olivia")["id"]):
        owner = ctx.accounts.by_username("olivia")
        ctx.add_file_bytes(owner["id"], "welcome.txt",
                           b"Hello from CapShare!\nThis file is stored in the CapShare directory.\n"
                           b"Share it with another device, then revoke the capability.\n" * 20)
    return created
