"""File storage inside the dedicated CapShare directory.

OS concept -> code
------------------
* "Confinement / path canonicalization" -> Storage.resolve(): every path is resolved
  (symlinks followed, `..` removed) and must still be inside the storage directory.
* "File permission bits"                -> files are created 0600 (owner read/write only);
  extra access for other Linux users exists *only* as POSIX ACL entries (see acl.py).
* "Resource limits"                     -> Storage.write_stream() stops at max_bytes.

The user-visible file name is only a label stored in the database. The name on disk is
a random `<uuid>.bin`, so a hostile file name can never become a path.
"""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from pathlib import Path
from typing import Callable, Iterable

from .errors import BadRequest, NotFound, TooLarge

_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f/\\:*?\"<>|]")


def safe_display_name(name: str) -> str:
    """Make a label that is safe to show and to put in Content-Disposition."""
    name = (name or "").replace("\\", "/").split("/")[-1]       # drop any directory part
    name = _BAD_CHARS.sub("_", name).strip(" .")
    if not name:
        raise BadRequest("file name is empty", code="BAD_FILE_NAME")
    return name[:120]


class Storage:
    def __init__(self, storage_dir: Path):
        self.root = Path(storage_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        self._root_real = self.root.resolve()

    # ------------------------------------------------------------------ paths
    def resolve(self, name: str) -> Path:
        """Canonicalize `name` inside the storage root, or raise.

        Rejects: absolute paths, `..` escapes, symlinks pointing outside the root.
        """
        if not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
            raise BadRequest("invalid storage path", code="BAD_PATH")
        candidate = (self._root_real / name).resolve()
        if candidate.parent != self._root_real:
            raise BadRequest("invalid storage path", code="BAD_PATH")
        return candidate

    def path_for(self, stored_name: str) -> Path:
        return self.resolve(stored_name)

    @staticmethod
    def new_stored_name() -> str:
        return uuid.uuid4().hex + ".bin"

    def temp_path(self) -> Path:
        return self.resolve(f".upload-{uuid.uuid4().hex}.part")

    # ------------------------------------------------------------------ writing
    def begin_upload(self, max_bytes: int) -> "StagedUpload":
        """Open a staged (temporary) file inside storage. See StagedUpload."""
        return StagedUpload(self, max_bytes)

    def write_stream(self, chunks: Iterable[bytes], max_bytes: int,
                     between_chunks: Callable[[int], None] | None = None) -> tuple[Path, int, str]:
        """Write chunks to a temp file inside storage; return (path, size, sha256).

        `between_chunks(bytes_so_far)` runs after every chunk: it may raise to abort.
        On any failure the partial file is deleted.
        """
        staged = self.begin_upload(max_bytes)
        try:
            for chunk in chunks:
                size = staged.write(chunk)
                if between_chunks:
                    between_chunks(size)
            return staged.finish()
        except BaseException:
            staged.abort()
            raise
    def install_new(self, tmp: Path, stored_name: str) -> Path:
        final = self.resolve(stored_name)
        os.replace(tmp, final)
        return final

    def replace_content(self, tmp: Path, stored_name: str) -> Path:
        """Atomically swap new content in. NOTE: a new inode has no ACL entries, so the
        caller must re-apply ACLs afterwards (engine.reapply_acl)."""
        final = self.resolve(stored_name)
        if not final.exists():
            raise NotFound("stored file is missing", code="STORAGE_MISSING")
        os.replace(tmp, final)
        return final

    def discard(self, tmp: Path) -> None:
        try:
            tmp.unlink()
        except OSError:
            pass

    # ------------------------------------------------------------------ reading
    def size_of(self, stored_name: str) -> int | None:
        try:
            return self.path_for(stored_name).stat().st_size
        except (OSError, BadRequest):
            return None

    def list_unmanaged(self, known: set[str]) -> list[dict]:
        """Regular files sitting in the storage dir that no database row owns yet."""
        out = []
        for entry in sorted(self._root_real.iterdir()):
            if entry.name.startswith(".") or entry.name in known:
                continue
            if entry.is_symlink() or not entry.is_file():
                continue                       # never follow links out of the sandbox
            out.append({"name": entry.name, "size": entry.stat().st_size})
        return out

    @staticmethod
    def sha256_of(path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()


class StagedUpload:
    """A partially written upload. Nothing is visible to anyone until the caller
    installs it (Storage.install_new / replace_content) after a final authority check."""

    def __init__(self, storage: Storage, max_bytes: int):
        self.storage = storage
        self.max_bytes = max_bytes
        self.path = storage.temp_path()
        self.size = 0
        self._digest = hashlib.sha256()
        # O_EXCL: never reuse or follow an existing path; 0600: owner only.
        self._fd = os.fdopen(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")

    def write(self, chunk: bytes) -> int:
        self.size += len(chunk)
        if self.size > self.max_bytes:
            raise TooLarge(f"file is larger than the {self.max_bytes // (1024 * 1024)} MiB limit")
        self._fd.write(chunk)
        self._digest.update(chunk)
        return self.size

    def finish(self) -> tuple[Path, int, str]:
        self._fd.close()
        return self.path, self.size, self._digest.hexdigest()

    def abort(self) -> None:
        try:
            self._fd.close()
        except OSError:
            pass
        self.storage.discard(self.path)
