"""Command line entry point:  python -m capshare <command>

    gui     desktop app (also starts the sharing service unless --client URL is given)
    serve   sharing service only (no desktop window) - good for a headless VM
    seed    create the demo accounts if they do not exist
    accounts  list accounts
    passwd  change an account password
    reset   delete the database and managed files (needs --yes)
    lab     run the five challenge scenarios in the terminal
"""
from __future__ import annotations

import argparse
import getpass
import shutil
import sys
import time

from .config import Config
from .context import AppContext
from .seed import DEMO_PASSWORD, seed_demo


def _print_urls(server) -> None:
    print("\nCapShare sharing service is running.")
    print(f"  This computer : {server.local_url}/")
    for url in server.lan_urls:
        print(f"  Other devices : {url}/    <- open this on the other device (same Wi-Fi)")
    if not server.lan_urls:
        print("  (no private LAN address found - only this computer can connect)")
    print(f"  Demo logins   : olivia / alice / bob / carol / dave   password: {DEMO_PASSWORD}")
    print("  Press Ctrl+C to stop.\n")


def cmd_serve(args) -> int:
    from .server import ServerThread
    sys.stdout.reconfigure(line_buffering=True)
    cfg = Config.from_env()
    if args.port:
        cfg.port = args.port
    if args.host:
        cfg.host = args.host
    ctx = AppContext(cfg)
    if not args.no_seed:
        seed_demo(ctx)
    for line in ctx.migration_log:
        print("db:", line)
    server = ServerThread(ctx).start()
    _print_urls(server)
    st = ctx.acl.status()
    print(f"  Linux ACLs    : {st['backend']} - {st['detail']}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping...")
        server.stop()
    return 0


def cmd_gui(args) -> int:
    from .gui.app import main as gui_main
    return gui_main(client_url=args.client, port=args.port, host=args.host)


def cmd_seed(args) -> int:
    ctx = AppContext(Config.from_env())
    created = seed_demo(ctx)
    print("created:", ", ".join(created) if created else "nothing (accounts already exist)")
    return 0


def cmd_accounts(args) -> int:
    ctx = AppContext(Config.from_env())
    for u in ctx.engine.list_users(include_linux=True):
        flags = ("admin " if u["is_admin"] else "") + ("login" if u["can_login"] else "no-login")
        print(f"{u['id']:>3}  {u['username']:<14} {u['display_name']:<28} {flags}"
              f"{'  linux=' + u['linux_user'] if u['linux_user'] else ''}")
    return 0


def cmd_passwd(args) -> int:
    ctx = AppContext(Config.from_env())
    user = ctx.accounts.by_username(args.username)
    if not user:
        print("no such user", file=sys.stderr)
        return 1
    pw = getpass.getpass("new password (min 8 chars): ")
    if pw != getpass.getpass("again: "):
        print("passwords differ", file=sys.stderr)
        return 1
    ctx.accounts.set_password(user["id"], pw)
    print("password changed; existing sessions were signed out")
    return 0


def cmd_reset(args) -> int:
    cfg = Config.from_env()
    if not args.yes:
        print(f"This DELETES the CapShare database and every managed file under:\n  {cfg.home}\n"
              "Re-run with --yes to confirm.")
        return 1
    if cfg.home.exists():
        shutil.rmtree(cfg.home)
    print("CapShare data removed. It will be re-created (with demo accounts) on next start.")
    return 0


def cmd_lab(args) -> int:
    from . import lab
    failed = 0
    for key in (args.keys or lab.CHALLENGES):
        res = lab.run_challenge(key)
        print(f"\n== {res['key']} {res['title']}: {'PASS' if res['passed'] else 'FAIL'}")
        for s in res["steps"]:
            print(f"  {'ok  ' if s['ok'] else 'FAIL'} {s['n']:>2}. {s['title']}")
            print(f"        -> {s['actual']}")
        failed += 0 if res["passed"] else 1
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m capshare", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd")
    p = sub.add_parser("gui", help="desktop app")
    p.add_argument("--client", metavar="URL", help="connect to another CapShare instead of starting one")
    p.add_argument("--port", type=int)
    p.add_argument("--host", help="private LAN address to bind to")
    p.set_defaults(fn=cmd_gui)
    p = sub.add_parser("serve", help="sharing service only")
    p.add_argument("--port", type=int)
    p.add_argument("--host")
    p.add_argument("--no-seed", action="store_true")
    p.set_defaults(fn=cmd_serve)
    sub.add_parser("seed", help="create demo accounts").set_defaults(fn=cmd_seed)
    sub.add_parser("accounts", help="list accounts").set_defaults(fn=cmd_accounts)
    p = sub.add_parser("passwd", help="change a password")
    p.add_argument("username")
    p.set_defaults(fn=cmd_passwd)
    p = sub.add_parser("reset", help="delete all CapShare data")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(fn=cmd_reset)
    p = sub.add_parser("lab", help="run challenge scenarios")
    p.add_argument("keys", nargs="*", help="C1 .. C5 (default: all)")
    p.set_defaults(fn=cmd_lab)
    args = parser.parse_args(argv)
    if not getattr(args, "fn", None):
        parser.print_help()
        return 0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
