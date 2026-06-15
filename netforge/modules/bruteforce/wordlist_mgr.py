"""Wordlist manager — locate, download, and merge wordlists."""
from __future__ import annotations

import logging
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

log = logging.getLogger("forge.netforge.wordlist_mgr")

_SYSTEM_WORDLISTS = [
    Path("/usr/share/wordlists/rockyou.txt"),
    Path("/usr/share/wordlists/rockyou.txt.gz"),
    Path("/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"),
    Path("/usr/share/seclists/Passwords/Common-Credentials/best1050.txt"),
    Path("/usr/share/wordlists/fasttrack.txt"),
]
_EMBEDDED_PASSWORDS = [
    "password", "123456", "password1", "12345678", "qwerty", "abc123",
    "letmein", "monkey", "1111111", "dragon", "master", "pass", "admin",
    "welcome", "login", "P@ssword", "P@ssw0rd", "Password1", "Summer2024!",
    "Winter2024!", "Company123!", "changeme",
]


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

    # Fall back to embedded minimal list
    dest = output_path or (Path("/tmp/forge_wordlist.txt"))
    dest.write_text("\n".join(_EMBEDDED_PASSWORDS))
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
