"""Central configuration.

Everything has a safe default; environment variables override for the demo:

    CAPSHARE_HOME      where the database + storage live   (default ~/.capshare)
    CAPSHARE_PORT      TCP port of the sharing service     (default 8765)
    CAPSHARE_HOST      bind to this private LAN address     (default: auto-detect)
    CAPSHARE_MAX_MB    upload size limit in MiB             (default 100)
    CAPSHARE_ACL       auto | on | off  - Linux ACL integration (default auto)
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

APP_NAME = "CapShare"
DEFAULT_PORT = 8765
MIB = 1024 * 1024


@dataclass
class Config:
    home: Path
    port: int = DEFAULT_PORT
    host: str | None = None              # None -> auto-detect a private LAN address
    max_file_bytes: int = 100 * MIB      # upload size limit
    max_delegation_edges: int = 4        # KO-13 C3: owner's grant counts as edge 1
    cascade_ceiling: int = 10_000        # safety ceiling for one revoke traversal
    session_hours: int = 12
    chunk_size: int = 64 * 1024          # transfer chunk; access is re-checked per chunk
    transfer_delay_ms: int = 0           # "slow mode" so a transfer is long enough to watch
    acl_mode: str = "auto"               # auto | on | off
    lan_only: bool = True                # refuse clients that are not on a private network
    pbkdf2_iterations: int = 200_000

    # ---- derived paths -------------------------------------------------
    @property
    def db_path(self) -> Path:
        return self.home / "capshare.db"

    @property
    def storage_dir(self) -> Path:
        """The one directory CapShare manages. Nothing outside it is ever served."""
        return self.home / "storage"

    @classmethod
    def from_env(cls) -> "Config":
        home = Path(os.environ.get("CAPSHARE_HOME", str(Path.home() / ".capshare")))
        cfg = cls(home=home)
        if os.environ.get("CAPSHARE_PORT"):
            cfg.port = int(os.environ["CAPSHARE_PORT"])
        if os.environ.get("CAPSHARE_HOST"):
            cfg.host = os.environ["CAPSHARE_HOST"]
        if os.environ.get("CAPSHARE_MAX_MB"):
            cfg.max_file_bytes = int(float(os.environ["CAPSHARE_MAX_MB"]) * MIB)
        if os.environ.get("CAPSHARE_ACL"):
            cfg.acl_mode = os.environ["CAPSHARE_ACL"].lower()
        return cfg

    @classmethod
    def for_testing(cls, home: Path, **overrides) -> "Config":
        """A throw-away configuration: tiny password cost, no real ACL calls."""
        cfg = cls(home=Path(home), pbkdf2_iterations=1_000, acl_mode="off", lan_only=False)
        for key, value in overrides.items():
            setattr(cfg, key, value)
        return cfg
