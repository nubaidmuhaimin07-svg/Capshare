#!/usr/bin/env python3
"""Real Linux ACL demonstration: allowed and denied file operations as mapped local users.

Run through scripts/acl_demo.sh (it creates two throw-away Linux users and cleans up).
Uses a TEMPORARY CapShare home, so your saved demo data is never touched.

What it proves
--------------
The CapShare engine decides a capability; for app accounts mapped to Linux users it then
writes POSIX ACL entries with setfacl. After that the LINUX KERNEL - not CapShare -
answers every open()/read()/write() those users make on the file.
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from capshare.acl import PosixAclBackend              # noqa: E402
from capshare.config import Config                    # noqa: E402
from capshare.context import AppContext               # noqa: E402

BOLD, GREEN, RED, DIM, END = "\033[1m", "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def run_as(linux_user: str, argv: list[str]) -> tuple[int, str]:
    proc = subprocess.run(["sudo", "-n", "-u", linux_user] + argv, capture_output=True, text=True)
    return proc.returncode, (proc.stderr or proc.stdout).strip()


def attempt(label: str, linux_user: str, argv: list[str], expect_ok: bool, results: list) -> None:
    code, text = run_as(linux_user, argv)
    ok = code == 0
    verdict = f"{GREEN}ALLOWED{END}" if ok else f"{RED}DENIED {END}"
    mark = "✔" if ok == expect_ok else "✘ UNEXPECTED"
    shown = text.splitlines()[0][:70] if (text and not ok) else ""
    print(f"   {verdict} {linux_user:<16} {' '.join(argv[:2]):<9} {DIM}{shown}{END}  {mark}")
    results.append(ok == expect_ok)


def show_acl(ctx: AppContext, path: Path, title: str) -> None:
    print(f"{BOLD}$ getfacl {path.name}{END}   {DIM}# {title}{END}")
    for line in ctx.acl.backend.getfacl_text(path).splitlines():
        if line and not line.startswith("# owner") and not line.startswith("# group"):
            print("   " + line)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alice", default="capshare_alice")
    ap.add_argument("--bob", default="capshare_bob")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="capshare-acl-demo-"))
    results: list[bool] = []
    try:
        ctx = AppContext(Config.for_testing(tmp / "home", acl_mode="on"), acl_backend=PosixAclBackend())
        if not ctx.acl.enabled:
            print("setfacl/getfacl not found. Install with: sudo apt install acl")
            return 2
        eng, acc = ctx.engine, ctx.accounts
        owner = acc.create_user("olivia", "Olivia", None)["id"]
        alice = acc.create_user("alice", "Alice", None, linux_user=args.alice)["id"]
        bob = acc.create_user("bob", "Bob", None, linux_user=args.bob)["id"]
        file = ctx.add_file_bytes(owner, "report.txt", b"quarterly numbers\n")
        path = ctx.storage.path_for(file["stored_name"])
        print(f"{BOLD}Managed file:{END} {path}")
        print(f"{DIM}App accounts alice/bob are mapped to Linux users {args.alice}/{args.bob}.{END}\n")

        print(f"{BOLD}1. Before any capability{END}")
        show_acl(ctx, path, "owner-only: mode 0600, no ACL entries")
        attempt("cat", args.alice, ["cat", str(path)], False, results)
        attempt("cat", args.bob, ["cat", str(path)], False, results)

        print(f"\n{BOLD}2. Owner grants alice a delegable READ capability{END}")
        g1 = eng.create_grant(actor_id=owner, file_id=file["id"], recipient_id=alice, actions="READ",
                              can_delegate=True)["grant"]
        show_acl(ctx, path, "CapShare ran setfacl -m u:%s:r-- ..." % args.alice)
        attempt("cat", args.alice, ["cat", str(path)], True, results)
        attempt("append", args.alice, ["sh", "-c", f"echo x >> '{path}'"], False, results)
        attempt("cat", args.bob, ["cat", str(path)], False, results)

        print(f"\n{BOLD}3. alice delegates READ to bob (capability #{g1['id']} -> child){END}")
        eng.create_grant(actor_id=alice, file_id=file["id"], recipient_id=bob, actions="READ",
                         parent_id=g1["id"])
        show_acl(ctx, path, "bob now has an entry too")
        attempt("cat", args.bob, ["cat", str(path)], True, results)

        print(f"\n{BOLD}4. Owner revokes alice's capability: cascade removes BOTH ACL entries{END}")
        rep = eng.revoke_grant(actor_id=owner, grant_id=g1["id"])
        print(f"   {DIM}affected grants: {rep['affected_grants']}, ACL ops: {rep['acl']['ops']}{END}")
        show_acl(ctx, path, "entries gone")
        attempt("cat", args.alice, ["cat", str(path)], False, results)
        attempt("cat", args.bob, ["cat", str(path)], False, results)

        print(f"\n{BOLD}5. Independent path: bob has a direct grant AND a delegated one{END}")
        g2 = eng.create_grant(actor_id=owner, file_id=file["id"], recipient_id=alice, actions="READ",
                              can_delegate=True)["grant"]
        eng.create_grant(actor_id=alice, file_id=file["id"], recipient_id=bob, actions="READ",
                         parent_id=g2["id"])
        eng.create_grant(actor_id=owner, file_id=file["id"], recipient_id=bob, actions="READ")
        rep = eng.revoke_grant(actor_id=owner, grant_id=g2["id"])
        print(f"   {DIM}revoked alice's root; ACL ops: {rep['acl']['ops']}{END}")
        show_acl(ctx, path, "bob's entry SURVIVES (a separate owner-issued path supports it)")
        attempt("cat", args.alice, ["cat", str(path)], False, results)
        attempt("cat", args.bob, ["cat", str(path)], True, results)

        print(f"\n{BOLD}Who enforces what{END}")
        print("   Linux kernel     : every open/read/write above (mode bits + POSIX ACL + directory x)")
        print("   CapShare service : who may hold which capability, delegation limits, expiry,")
        print("                      cascade, and what a REMOTE device (no Linux account) may transfer")
        good = all(results)
        print(f"\n{GREEN if good else RED}{sum(results)}/{len(results)} operations behaved as expected{END}")
        return 0 if good else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
