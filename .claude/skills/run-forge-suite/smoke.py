#!/usr/bin/env python3
"""Forge Suite smoke driver.

Verifies the CLI, intel pipeline, and dashboard API all respond correctly.
Run from the forge-suite/ root:

    python3 .claude/skills/run-forge-suite/smoke.py [--dashboard-port PORT]

Exit 0 = all checks passed.  Exit 1 = at least one check failed.
"""
import argparse
import json
import os
import signal
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]  # forge-suite/
ENV = {**os.environ, "PYTHONUTF8": "1"}
FORGE = str(ROOT / "forge.py")

PASS = "[+]"
FAIL = "[!]"
INFO = "[*]"

errors = []


def run(cmd, *, timeout=15, check=True):
    result = subprocess.run(
        [sys.executable] + cmd,
        capture_output=True,
        text=True,
        env=ENV,
        cwd=str(ROOT),
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd!r}\n{result.stderr}")
    return result


def check(label, ok, detail=""):
    sym = PASS if ok else FAIL
    print(f"  {sym} {label}", f"({detail})" if detail else "")
    if not ok:
        errors.append(label)


# ── 1. CLI help ──────────────────────────────────────────────────────────
def test_cli_help():
    print(f"\n{INFO} CLI smoke")
    r = run([FORGE, "--help"], check=False)
    check("forge.py --help exits 0", r.returncode == 0)
    check("banner present", "Forge Suite" in r.stdout)
    check("scan frameworks listed", all(k in r.stdout for k in ("net", "web", "ad", "ai")))
    check("platform commands listed",
          all(k in r.stdout for k in ("dashboard", "intel", "payload")))


# ── 2. Intel pipeline ────────────────────────────────────────────────────
def test_intel():
    print(f"\n{INFO} Intel pipeline")
    r = run([FORGE, "intel", "status"], check=False)
    check("intel status exits 0", r.returncode == 0)
    check("intel status shows table", "FORGE INTEL PIPELINE" in r.stdout)
    for source in ("cve", "exploits", "nuclei", "techniques"):
        check(f"intel status includes '{source}'", source in r.stdout)

    r2 = run([FORGE, "intel", "search", "test_query"], check=False)
    check("intel search runs without crash", r2.returncode in (0, 1))


# ── 3. Framework imports ─────────────────────────────────────────────────
def test_imports():
    print(f"\n{INFO} Framework imports")
    for fw in ("netforge.netforge", "webforge.webforge", "adforge.adforge", "aiforge.aiforge"):
        r = run(["-c", f"import {fw}; print('ok')"], check=False)
        check(f"{fw} importable", "ok" in r.stdout, r.stderr[:80] if r.returncode else "")


# ── 4. Dashboard API ─────────────────────────────────────────────────────
def test_dashboard(port: int):
    print(f"\n{INFO} Dashboard API (port {port})")

    proc = subprocess.Popen(
        [sys.executable, FORGE, "dashboard", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=ENV,
        cwd=str(ROOT),
    )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    base = f"https://127.0.0.1:{port}"

    # Wait for server ready (up to 12s)
    started = False
    for _ in range(24):
        time.sleep(0.5)
        try:
            urllib.request.urlopen(f"{base}/openapi.json", context=ctx, timeout=2)
            started = True
            break
        except Exception:
            continue

    if not started:
        check("dashboard starts", False, "timed out after 12s")
        proc.terminate()
        return

    check("dashboard starts", True)

    try:
        # Login
        login_data = json.dumps({"username": "operator", "password": "forge2026"}).encode()
        req = urllib.request.Request(
            f"{base}/api/v1/auth/login",
            data=login_data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            token_body = json.loads(resp.read())
        token = token_body.get("token", "")
        check("login returns token", bool(token), token[:30] if token else "empty")

        headers = {"Authorization": f"Bearer {token}"}

        # /api/v1/state
        req = urllib.request.Request(f"{base}/api/v1/state", headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            state = json.loads(resp.read())
        check("/api/v1/state returns framework", state.get("framework") == "forge")
        check("/api/v1/state has scan_status", "scan_status" in state)

        # /api/v1/findings
        req = urllib.request.Request(f"{base}/api/v1/findings?page=1&limit=5", headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            findings = json.loads(resp.read())
        check("/api/v1/findings responds", "findings" in findings)

        # /api/v1/metrics
        req = urllib.request.Request(f"{base}/api/v1/metrics", headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            metrics = json.loads(resp.read())
        check("/api/v1/metrics has elapsed", "elapsed" in metrics)

        # /api/v1/kill-chain
        req = urllib.request.Request(f"{base}/api/v1/kill-chain", headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            kc = json.loads(resp.read())
        check("/api/v1/kill-chain has phases", "phases" in kc)

    except Exception as exc:
        check("dashboard API calls", False, str(exc)[:120])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ── main ─────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Forge Suite smoke driver")
    ap.add_argument("--dashboard-port", type=int, default=19337,
                    help="Port for the test dashboard (default: 19337)")
    ap.add_argument("--skip-dashboard", action="store_true",
                    help="Skip dashboard API tests")
    args = ap.parse_args()

    print(f"\n{'='*60}")
    print(f"  Forge Suite Smoke Test — {ROOT}")
    print(f"{'='*60}")

    test_cli_help()
    test_intel()
    test_imports()

    if not args.skip_dashboard:
        test_dashboard(args.dashboard_port)

    print(f"\n{'='*60}")
    if errors:
        print(f"  {FAIL} {len(errors)} check(s) FAILED: {', '.join(errors)}")
        return 1
    else:
        print(f"  {PASS} All checks passed.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
