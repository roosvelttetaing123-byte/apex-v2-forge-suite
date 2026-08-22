from __future__ import annotations

import os
import socket
from urllib.parse import urlparse
from urllib.request import urlopen

import pytest


def _lab_urls() -> list[tuple[str, str]]:
    return [
        ("dvwa", os.environ.get("FORGE_LAB_DVWA_URL", "")),
        ("webgoat", os.environ.get("FORGE_LAB_WEBGOAT_URL", "")),
    ]


@pytest.mark.parametrize("name,url", _lab_urls())
def test_opt_in_web_lab_is_reachable(name: str, url: str) -> None:
    if not url:
        pytest.skip(f"set FORGE_LAB_{name.upper()}_URL to enable this lab test")
    parsed = urlparse(url)
    assert parsed.scheme in {"http", "https"}
    assert parsed.hostname
    with urlopen(url, timeout=5) as resp:
        assert 200 <= resp.status < 500


def test_opt_in_metasploitable_host_is_reachable() -> None:
    host = os.environ.get("FORGE_LAB_METASPLOITABLE_HOST", "")
    if not host:
        pytest.skip("set FORGE_LAB_METASPLOITABLE_HOST to enable this lab test")
    port = int(os.environ.get("FORGE_LAB_METASPLOITABLE_PORT", "22"))
    with socket.create_connection((host, port), timeout=5):
        pass
