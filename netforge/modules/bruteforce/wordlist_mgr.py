"""Wordlist manager — locate, download, and merge wordlists."""

from __future__ import annotations

import atexit
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

log = logging.getLogger("forge.netforge.wordlist_mgr")

_SYSTEM_WORDLISTS = [
    Path("/usr/share/wordlists/rockyou.txt"),
    Path("/usr/share/wordlists/rockyou.txt.gz"),
    Path(
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
    ),
    Path("/usr/share/seclists/Passwords/Common-Credentials/best1050.txt"),
    Path("/usr/share/wordlists/fasttrack.txt"),
]
_EMBEDDED_PASSWORDS = [
    "password",
    "123456",
    "password1",
    "12345678",
    "qwerty",
    "abc123",
    "letmein",
    "monkey",
    "1111111",
    "dragon",
    "master",
    "pass",
    "admin",
    "welcome",
    "login",
    "P@ssword",
    "P@ssw0rd",
    "Password1",
    "Summer2024!",
    "Winter2024!",
    "Company123!",
    "changeme",
]
_TEMPORARY_WORDLISTS: set[Path] = set()


def _cleanup_temporary_wordlists() -> None:
    for path in tuple(_TEMPORARY_WORDLISTS):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        finally:
            _TEMPORARY_WORDLISTS.discard(path)


atexit.register(_cleanup_temporary_wordlists)


def release_temporary_wordlist(path: Path) -> bool:
    """Remove an auto-generated wordlist at the end of its consuming operation."""

    if path not in _TEMPORARY_WORDLISTS:
        return False
    try:
        path.unlink(missing_ok=True)
    finally:
        _TEMPORARY_WORDLISTS.discard(path)
    return True


def _write_embedded_wordlist(output_path: Path | None) -> Path:
    content = ("\n".join(_EMBEDDED_PASSWORDS) + "\n").encode("utf-8")
    if output_path is None:
        descriptor, raw_path = tempfile.mkstemp(
            prefix="forge-wordlist-",
            suffix=".txt",
        )
        destination = Path(raw_path)
        _TEMPORARY_WORDLISTS.add(destination)
    else:
        destination = output_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(destination, flags, 0o600)

    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
        os.chmod(destination, 0o600)
    except BaseException:
        destination.unlink(missing_ok=True)
        _TEMPORARY_WORDLISTS.discard(destination)
        raise
    return destination


def find_wordlist(min_size_kb: int = 100) -> Path | None:
    for p in _SYSTEM_WORDLISTS:
        if p.exists() and p.stat().st_size >= min_size_kb * 1024:
            return p
    return None


def get_or_create_wordlist(output_path: Path | None = None) -> Path:
    found = find_wordlist()
    if found:
        log.info("Using system wordlist: %s", found)
        return found

    # Unzip rockyou if gzipped version exists
    gz = Path("/usr/share/wordlists/rockyou.txt.gz")
    if gz.exists():
        import gzip

        target = gz.with_suffix("")
        log.info("Decompressing rockyou.txt.gz...")
        with gzip.open(gz) as f_in, open(target, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        return target

    # Fall back to an exclusive private file. Auto-generated files use a
    # collision-resistant name and are removed during normal interpreter exit.
    dest = _write_embedded_wordlist(output_path)
    log.warning("No system wordlist found — using minimal embedded list: %s", dest)
    return dest


def merge_wordlists(paths: list[Path], output: Path, dedupe: bool = True) -> Path:
    seen: set[str] = set()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", errors="ignore") as out:
        for p in paths:
            if not p.exists():
                continue
            with p.open(encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.rstrip("\n")
                    if dedupe:
                        if word not in seen:
                            seen.add(word)
                            out.write(word + "\n")
                    else:
                        out.write(word + "\n")
    log.info("Merged %d wordlists → %s (%d unique)", len(paths), output, len(seen))
    return output
