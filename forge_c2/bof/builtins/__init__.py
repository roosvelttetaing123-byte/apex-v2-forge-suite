"""Built-in BOFs — Python implementations.

These provide the same functionality as compiled C BOFs but run natively
in Python. Each BOF class follows the standard pattern:

    class MyBof(BuiltinBOF):
        NAME = "mybof"
        DESCRIPTION = "What it does"
        def execute(self, args: BeaconDataParser, api: BeaconAPI) -> None:
            api.BeaconPrintf(0, "output here")

On Windows targets with real beacons, these would be compiled C .o files.
The Python versions provide identical output formatting for operator experience.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
import os
import platform
import re
import socket
import struct
import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

log = logging.getLogger("forge.c2.bof.builtins")


class BuiltinBOF(ABC):
    """Base class for built-in BOFs."""

    NAME: str = ""
    DESCRIPTION: str = ""
    HELP: str = ""

    @abstractmethod
    def execute(self, args: list[str], output: list[str]) -> int:
        """Execute the BOF.

        Args:
            args: Command-line arguments.
            output: List to append output lines to.

        Returns:
            Exit code (0 = success).
        """
        ...

    def _run_cmd(self, cmd: list[str], output: list[str]) -> int:
        """Run a system command and capture output."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.stdout:
                output.append(result.stdout)
            if result.stderr:
                output.append(f"[stderr] {result.stderr}")
            return result.returncode
        except FileNotFoundError:
            output.append(f"[!] Command not found: {cmd[0]}")
            return 1
        except subprocess.TimeoutExpired:
            output.append(f"[!] Command timed out: {' '.join(cmd)}")
            return 1
        except Exception as e:
            output.append(f"[!] Error running {cmd[0]}: {e}")
            return 1


# ══════════════════════════════════════════════════════════════════════
# 10 BUILT-IN BOFS
# ══════════════════════════════════════════════════════════════════════

class WhoamiBOF(BuiltinBOF):
    """whoami — Current user, groups, and privileges."""
    NAME = "whoami"
    DESCRIPTION = "Current user identity, groups, and privileges"
    HELP = "Usage: bof whoami"

    def execute(self, args: list[str], output: list[str]) -> int:
        output.append("═══ whoami ═══\n")

        if sys.platform == "win32":
            self._run_cmd(["whoami", "/all"], output)
        else:
            # User info
            import pwd
            import grp
            user = pwd.getpwuid(os.getuid())
            output.append(f"User:     {user.pw_name} (uid={user.pw_uid})")
            output.append(f"Home:     {user.pw_dir}")
            output.append(f"Shell:    {user.pw_shell}")
            output.append(f"Hostname: {socket.gethostname()}")
            output.append(f"Euid:     {os.geteuid()}")
            output.append(f"Root:     {'YES' if os.geteuid() == 0 else 'no'}\n")

            # Groups
            groups = os.getgroups()
            group_names = []
            for gid in groups:
                try:
                    group_names.append(f"{grp.getgrgid(gid).gr_name}({gid})")
                except KeyError:
                    group_names.append(f"?({gid})")
            output.append(f"Groups:   {', '.join(group_names)}")

        return 0


class NetstatBOF(BuiltinBOF):
    """netstat — Active network connections and listeners."""
    NAME = "netstat"
    DESCRIPTION = "Active network connections and listening ports"
    HELP = "Usage: bof netstat [-t tcp] [-u udp] [-l listening]"

    def execute(self, args: list[str], output: list[str]) -> int:
        output.append("═══ netstat ═══\n")

        if sys.platform == "win32":
            self._run_cmd(["netstat", "-anob"], output)
        else:
            # Parse /proc/net/tcp and /proc/net/udp
            output.append(f"{'Proto':<8} {'Local Address':<25} {'Remote Address':<25} {'State':<15} {'PID/Program'}")
            output.append("─" * 85)

            for proto, proc_file in [("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"),
                                      ("udp", "/proc/net/udp"), ("udp6", "/proc/net/udp6")]:
                try:
                    with open(proc_file) as f:
                        lines = f.readlines()[1:]  # Skip header
                    for line in lines[:50]:  # Limit output
                        parts = line.split()
                        if len(parts) < 4:
                            continue
                        local = self._decode_addr(parts[1], "6" in proto)
                        remote = self._decode_addr(parts[2], "6" in proto)
                        state = self._tcp_state(int(parts[3], 16)) if "tcp" in proto else "UNCONN"
                        output.append(f"{proto:<8} {local:<25} {remote:<25} {state:<15}")
                except FileNotFoundError:
                    pass

            # Also show listeners via ss if available
            self._run_cmd(["ss", "-tlnp"], output)

        return 0

    @staticmethod
    def _decode_addr(hex_addr: str, ipv6: bool = False) -> str:
        """Decode /proc/net address format."""
        try:
            ip_hex, port_hex = hex_addr.split(":")
            port = int(port_hex, 16)
            if ipv6:
                ip = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(ip_hex))
            else:
                ip_int = int(ip_hex, 16)
                ip = socket.inet_ntoa(struct.pack("<I", ip_int))
            return f"{ip}:{port}"
        except Exception:
            return hex_addr

    @staticmethod
    def _tcp_state(state: int) -> str:
        """Convert TCP state integer to name."""
        states = {
            1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
            5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
            9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING",
        }
        return states.get(state, f"UNKNOWN({state})")


class PsBOF(BuiltinBOF):
    """ps — Process listing with details."""
    NAME = "ps"
    DESCRIPTION = "Running processes with PID, user, and command"
    HELP = "Usage: bof ps"

    def execute(self, args: list[str], output: list[str]) -> int:
        output.append("═══ Process List ═══\n")

        if sys.platform == "win32":
            self._run_cmd(["tasklist", "/V", "/FO", "CSV"], output)
        else:
            output.append(f"{'PID':<8} {'PPID':<8} {'USER':<15} {'RSS(KB)':<10} {'CMD'}")
            output.append("─" * 80)

            proc_dirs = sorted(
                [d for d in Path("/proc").iterdir() if d.name.isdigit()],
                key=lambda d: int(d.name),
            )
            for proc_dir in proc_dirs[:200]:  # Limit
                try:
                    status = (proc_dir / "status").read_text()
                    cmdline = (proc_dir / "cmdline").read_text().replace("\x00", " ").strip()

                    pid = proc_dir.name
                    ppid = ""
                    user = ""
                    rss = ""

                    for line in status.split("\n"):
                        if line.startswith("PPid:"):
                            ppid = line.split(":")[1].strip()
                        elif line.startswith("Uid:"):
                            uid = line.split(":")[1].strip().split()[0]
                            try:
                                import pwd
                                user = pwd.getpwuid(int(uid)).pw_name
                            except (KeyError, ImportError):
                                user = uid
                        elif line.startswith("VmRSS:"):
                            rss = line.split(":")[1].strip().split()[0]

                    if not cmdline:
                        cmdline = f"[{status.split(chr(10))[0].split(':')[1].strip()}]"

                    output.append(f"{pid:<8} {ppid:<8} {user:<15} {rss:<10} {cmdline[:60]}")
                except (PermissionError, FileNotFoundError, OSError):
                    continue

        return 0


class LsBOF(BuiltinBOF):
    """ls — Directory listing with permissions and sizes."""
    NAME = "ls"
    DESCRIPTION = "Directory listing with permissions, sizes, and timestamps"
    HELP = "Usage: bof ls [path]"

    def execute(self, args: list[str], output: list[str]) -> int:
        target = args[0] if args else "."
        target_path = Path(target)

        if not target_path.exists():
            output.append(f"[!] Path not found: {target}")
            return 1

        output.append(f"═══ ls {target_path.resolve()} ═══\n")

        if target_path.is_file():
            self._format_entry(target_path, output)
            return 0

        output.append(f"{'Perms':<12} {'Size':<10} {'Modified':<20} {'Name'}")
        output.append("─" * 70)

        entries = sorted(target_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        for entry in entries[:200]:
            self._format_entry(entry, output)

        return 0

    @staticmethod
    def _format_entry(path: Path, output: list[str]) -> None:
        """Format a single directory entry."""
        try:
            stat = path.stat()
            perms = oct(stat.st_mode)[-4:]
            size = stat.st_size if path.is_file() else 0
            from datetime import datetime
            mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
            name = path.name + ("/" if path.is_dir() else "")
            size_str = f"{size:>8}" if size else "     DIR"
            output.append(f"{perms:<12} {size_str:<10} {mtime:<20} {name}")
        except (PermissionError, OSError) as e:
            output.append(f"{'????':<12} {'?':<10} {'?':<20} {path.name} ({e})")


class RegQueryBOF(BuiltinBOF):
    """reg_query — Windows registry query (or Linux config equivalent)."""
    NAME = "reg_query"
    DESCRIPTION = "Query registry keys (Windows) or system config (Linux)"
    HELP = "Usage: bof reg_query [key_path]"

    def execute(self, args: list[str], output: list[str]) -> int:
        output.append("═══ Registry / Config Query ═══\n")

        if sys.platform == "win32":
            key = args[0] if args else r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            self._run_cmd(["reg", "query", key], output)
        else:
            # Linux equivalent: system configuration
            configs = {
                "OS Release": "/etc/os-release",
                "Hostname": "/etc/hostname",
                "Hosts": "/etc/hosts",
                "Resolv": "/etc/resolv.conf",
                "NSSwitch": "/etc/nsswitch.conf",
                "Sysctl (net)": None,  # dynamic
            }

            target = args[0] if args else None

            if target and Path(target).exists():
                output.append(f"[{target}]")
                try:
                    output.append(Path(target).read_text()[:4096])
                except PermissionError:
                    output.append("[!] Permission denied")
                return 0

            for label, path in configs.items():
                if path and Path(path).exists():
                    output.append(f"\n[{label}] ({path})")
                    try:
                        content = Path(path).read_text().strip()
                        output.append(content[:1024])
                    except PermissionError:
                        output.append("  [!] Permission denied")

            # Sysctl networking
            output.append("\n[Sysctl - Network]")
            for param in ["net.ipv4.ip_forward", "net.ipv4.conf.all.proxy_arp",
                          "net.ipv6.conf.all.disable_ipv6"]:
                try:
                    val = Path(f"/proc/sys/{param.replace('.', '/')}").read_text().strip()
                    output.append(f"  {param} = {val}")
                except (FileNotFoundError, PermissionError):
                    pass

        return 0


class ScQueryBOF(BuiltinBOF):
    """sc_query — Windows services or Linux systemd units."""
    NAME = "sc_query"
    DESCRIPTION = "Running services and their status"
    HELP = "Usage: bof sc_query [service_name]"

    def execute(self, args: list[str], output: list[str]) -> int:
        output.append("═══ Services ═══\n")

        if sys.platform == "win32":
            if args:
                self._run_cmd(["sc", "query", args[0]], output)
            else:
                self._run_cmd(["sc", "query", "state=", "all"], output)
        else:
            if args:
                self._run_cmd(["systemctl", "status", args[0]], output)
            else:
                output.append(f"{'UNIT':<40} {'STATE':<12} {'SUB':<12} {'DESCRIPTION'}")
                output.append("─" * 90)
                self._run_cmd(["systemctl", "list-units", "--type=service", "--no-pager", "--plain"], output)

        return 0


class ArpBOF(BuiltinBOF):
    """arp — ARP table (neighbor cache)."""
    NAME = "arp"
    DESCRIPTION = "ARP table / neighbor cache"
    HELP = "Usage: bof arp"

    def execute(self, args: list[str], output: list[str]) -> int:
        output.append("═══ ARP Table ═══\n")

        if sys.platform == "win32":
            self._run_cmd(["arp", "-a"], output)
        else:
            # Read /proc/net/arp
            output.append(f"{'IP Address':<18} {'HW Address':<20} {'Flags':<8} {'Interface'}")
            output.append("─" * 60)
            try:
                with open("/proc/net/arp") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 6:
                            ip, _, flags, mac, _, iface = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                            output.append(f"{ip:<18} {mac:<20} {flags:<8} {iface}")
            except FileNotFoundError:
                self._run_cmd(["ip", "neigh", "show"], output)

        return 0


class IpconfigBOF(BuiltinBOF):
    """ipconfig — Network interface configuration."""
    NAME = "ipconfig"
    DESCRIPTION = "Network interface configuration and addresses"
    HELP = "Usage: bof ipconfig"

    def execute(self, args: list[str], output: list[str]) -> int:
        output.append("═══ Network Interfaces ═══\n")

        if sys.platform == "win32":
            self._run_cmd(["ipconfig", "/all"], output)
        else:
            self._run_cmd(["ip", "-c", "addr", "show"], output)
            output.append("\n═══ Routes ═══\n")
            self._run_cmd(["ip", "-c", "route", "show"], output)
            output.append("\n═══ DNS ═══\n")
            try:
                output.append(Path("/etc/resolv.conf").read_text())
            except (FileNotFoundError, PermissionError):
                output.append("[!] Cannot read /etc/resolv.conf")

        return 0


class EnvBOF(BuiltinBOF):
    """env — Environment variables (filtered for interesting ones)."""
    NAME = "env"
    DESCRIPTION = "Environment variables (highlights sensitive values)"
    HELP = "Usage: bof env [filter]"

    # Patterns that indicate juicy env vars
    INTERESTING = re.compile(
        r"(KEY|TOKEN|SECRET|PASS|CRED|AUTH|API|AWS|AZURE|GCP|DB|DATABASE|CONN|"
        r"LDAP|SMTP|SSH|PROXY|HOME|USER|PATH|SHELL|TERM|DISPLAY|SESSION|KUBE|"
        r"DOCKER|REDIS|MONGO|MYSQL|POSTGRES|ORACLE|ELASTIC)",
        re.IGNORECASE,
    )

    def execute(self, args: list[str], output: list[str]) -> int:
        output.append("═══ Environment Variables ═══\n")

        filter_str = args[0].lower() if args else None
        env = dict(os.environ)

        # Sort: interesting vars first, then alphabetical
        interesting = {}
        normal = {}
        for k, v in sorted(env.items()):
            if filter_str and filter_str not in k.lower() and filter_str not in v.lower():
                continue
            if self.INTERESTING.search(k):
                interesting[k] = v
            else:
                normal[k] = v

        if interesting:
            output.append("── Interesting ──")
            for k, v in interesting.items():
                # Mask potential secrets
                display = v if len(v) < 5 else v[:3] + "***" + v[-2:]
                if any(x in k.upper() for x in ["PASS", "SECRET", "KEY", "TOKEN", "CRED"]):
                    display = "***REDACTED***"
                output.append(f"  🔑 {k}={display}")

        output.append(f"\n── All ({len(normal)} vars) ──")
        for k, v in list(normal.items())[:50]:
            output.append(f"  {k}={v[:80]}")
        if len(normal) > 50:
            output.append(f"  ... and {len(normal) - 50} more")

        return 0


class TasklistBOF(BuiltinBOF):
    """tasklist — Focused process listing for red team (security tools, RDP, admins)."""
    NAME = "tasklist"
    DESCRIPTION = "Process listing focused on security tools, remote sessions, and admin processes"
    HELP = "Usage: bof tasklist"

    # Known security tool process names
    SECURITY_PROCS = {
        # EDR/AV
        "MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "SenseCncProxy.exe",
        "csfalconservice.exe", "CSFalconContainer.exe",
        "cb.exe", "carbonblack.exe", "CbDefense.exe", "RepMgr.exe",
        "SentinelAgent.exe", "SentinelServiceHost.exe", "SentinelStaticEngine.exe",
        "CylanceSvc.exe", "CylanceUI.exe",
        "cortex", "paloaltonetworks",
        "elastic-agent", "elastic-endpoint",
        "ossec", "wazuh",
        # Sysmon / logging
        "Sysmon.exe", "Sysmon64.exe",
        "winlogbeat.exe", "filebeat.exe", "auditbeat.exe",
        # AV
        "avp.exe", "kavtray.exe",  # Kaspersky
        "bdagent.exe", "vsserv.exe",  # Bitdefender
        "savservice.exe",  # Sophos
        "avguard.exe", "avscan.exe",  # Avira
        "egui.exe", "ekrn.exe",  # ESET
        "clamav", "clamd", "freshclam",
    }

    def execute(self, args: list[str], output: list[str]) -> int:
        output.append("═══ Tasklist (Security Focus) ═══\n")

        if sys.platform == "win32":
            self._run_cmd(["tasklist", "/V", "/FO", "CSV"], output)
            return 0

        # Linux: scan /proc for security-relevant processes
        output.append("── Security Tools ──")
        found_security = []
        found_other = []

        for proc_dir in sorted(Path("/proc").iterdir(), key=lambda d: d.name):
            if not proc_dir.name.isdigit():
                continue
            try:
                cmdline = (proc_dir / "cmdline").read_text().replace("\x00", " ").strip()
                comm = (proc_dir / "comm").read_text().strip()
                pid = proc_dir.name

                is_security = any(
                    sec.lower() in comm.lower() or sec.lower() in cmdline.lower()
                    for sec in self.SECURITY_PROCS
                )
                if is_security:
                    found_security.append(f"  ⚠️  PID {pid:<8} {comm:<25} {cmdline[:50]}")
                else:
                    found_other.append((pid, comm, cmdline))
            except (PermissionError, FileNotFoundError, OSError):
                continue

        if found_security:
            for line in found_security:
                output.append(line)
        else:
            output.append("  ✅ No known security tools detected")

        output.append(f"\n── All processes ({len(found_other)} total) ──")
        output.append(f"{'PID':<8} {'NAME':<25} {'CMDLINE'}")
        output.append("─" * 70)
        for pid, comm, cmdline in found_other[:100]:
            output.append(f"{pid:<8} {comm:<25} {cmdline[:50]}")

        return 0


# ══════════════════════════════════════════════════════════════════════
# REGISTRY — all built-in BOFs
# ══════════════════════════════════════════════════════════════════════

BUILTIN_BOFS: dict[str, type[BuiltinBOF]] = {
    "whoami":    WhoamiBOF,
    "netstat":   NetstatBOF,
    "ps":        PsBOF,
    "ls":        LsBOF,
    "reg_query": RegQueryBOF,
    "sc_query":  ScQueryBOF,
    "arp":       ArpBOF,
    "ipconfig":  IpconfigBOF,
    "env":       EnvBOF,
    "tasklist":  TasklistBOF,
}


def run_builtin_bof(name: str, args: list[str] | None = None) -> tuple[int, str]:
    """Execute a built-in BOF by name.

    Returns:
        (exit_code, output_string)
    """
    bof_class = BUILTIN_BOFS.get(name)
    if bof_class is None:
        return 1, f"[!] Unknown built-in BOF: {name}. Available: {', '.join(BUILTIN_BOFS.keys())}"

    bof = bof_class()
    output: list[str] = []
    exit_code = bof.execute(args or [], output)
    return exit_code, "\n".join(output)


def list_builtin_bofs() -> list[dict[str, str]]:
    """List all available built-in BOFs."""
    return [
        {"name": name, "description": cls.DESCRIPTION, "help": cls.HELP}
        for name, cls in BUILTIN_BOFS.items()
    ]
