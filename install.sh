#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  Forge Suite v5 APEX — Full Install + Dependency Verification        ║
# ║  FOR AUTHORIZED PENETRATION TESTING ENGAGEMENTS ONLY                 ║
# ╚══════════════════════════════════════════════════════════════════════╝
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
MAGENTA='\033[0;35m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[!]${NC} $*"; }
die()     { err "$*"; exit 1; }
section() { echo -e "\n${MAGENTA}${BOLD}── $* ──${NC}"; }

FORGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIRS=("webforge/results" "netforge/results" "adforge/results" "aiforge/results")

echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
   ██████╗ ██████╗ ██████╗  ██████╗ ███████╗    ███████╗██╗   ██╗██╗████████╗███████╗
   ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝    ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
   █████╗  ██║   ██║██████╔╝██║  ███╗█████╗      ███████╗██║   ██║██║   ██║   █████╗
   ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝      ╚════██║██║   ██║██║   ██║   ██╔══╝
   ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗    ███████║╚██████╔╝██║   ██║   ███████╗
   ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝

                   v5.0.0 APEX — Enterprise Offensive Security Platform
                      FOR AUTHORIZED PENETRATION TESTING ONLY
BANNER
echo -e "${NC}"

MISSING=()
OPTIONAL_MISSING=()

# ══════════════════════════════════════════════════════════════════════
# PYTHON VERSION CHECK
# ══════════════════════════════════════════════════════════════════════
section "Python Environment"

PYTHON=$(command -v python3 2>/dev/null || true)
[[ -z "$PYTHON" ]] && die "Python 3 not found. Install: apt-get install -y python3 python3-pip python3-venv"

PY_VER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")

[[ "$PY_MAJOR" -lt 3 || ("$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 10) ]] && \
  die "Python 3.10+ required. Found: $PY_VER"
ok "Python $PY_VER ✓"

# ── Virtual environment (optional but recommended) ────────────────────
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  if [[ ! -d "${FORGE_DIR}/.venv" ]]; then
    info "Creating virtual environment (.venv)..."
    $PYTHON -m venv "${FORGE_DIR}/.venv" 2>/dev/null || warn "venv creation failed — using system Python"
  fi
  if [[ -f "${FORGE_DIR}/.venv/bin/activate" ]]; then
    info "Activating virtual environment..."
    source "${FORGE_DIR}/.venv/bin/activate"
    ok "Virtual environment active ✓"
  fi
fi

# ══════════════════════════════════════════════════════════════════════
# PYTHON DEPENDENCIES
# ══════════════════════════════════════════════════════════════════════
section "Python Dependencies"

info "Upgrading pip..."
pip3 install -q --upgrade pip 2>/dev/null || warn "pip upgrade failed"

info "Installing requirements.txt..."
pip3 install -q -r "${FORGE_DIR}/requirements.txt" && \
  ok "Core Python packages installed ✓" || \
  warn "Some packages failed — check errors above"

# Verify critical imports
info "Verifying critical imports..."
CRITICAL_PKGS=(
  "fastapi:Dashboard backend"
  "uvicorn:Dashboard server"
  "rich:Terminal UI"
  "cryptography:C2 crypto"
  "aiohttp:Async HTTP"
  "jinja2:Templating"
  "pydantic:Data validation"
)

for entry in "${CRITICAL_PKGS[@]}"; do
  pkg="${entry%%:*}"
  desc="${entry#*:}"
  if $PYTHON -c "import $pkg" 2>/dev/null; then
    ok "$pkg ($desc) ✓"
  else
    err "$pkg ($desc) ✗ — CRITICAL"
    MISSING+=("$pkg")
  fi
done

# ══════════════════════════════════════════════════════════════════════
# EXTERNAL TOOLS
# ══════════════════════════════════════════════════════════════════════
section "External Tools"

check_tool() {
  local tool="$1" install_cmd="$2" required="${3:-true}"
  if command -v "$tool" &>/dev/null; then
    ok "$tool ✓"
  else
    if [[ "$required" == "true" ]]; then
      warn "$tool NOT FOUND — install: $install_cmd"
      MISSING+=("$tool")
    else
      info "$tool not found (optional) — install: $install_cmd"
      OPTIONAL_MISSING+=("$tool")
    fi
  fi
}

# Required tools
check_tool nmap               "apt-get install -y nmap"
check_tool hydra              "apt-get install -y hydra"
check_tool smbclient          "apt-get install -y smbclient"

# Recommended tools
check_tool nuclei             "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" false
check_tool impacket-secretsdump "pip3 install impacket" false
check_tool testssl.sh         "apt-get install -y testssl.sh OR git clone https://github.com/drwetter/testssl.sh" false
check_tool crackmapexec       "pip3 install crackmapexec" false
check_tool evil-winrm         "gem install evil-winrm" false
check_tool chisel             "go install github.com/jpillora/chisel@latest" false
check_tool ligolo-ng          "Download from https://github.com/nicocha30/ligolo-ng/releases" false

# ── Browser detection ─────────────────────────────────────────────────
info "Detecting available browsers..."
BROWSER_FOUND=false
for b in google-chrome google-chrome-stable chromium chromium-browser firefox firefox-esr; do
  if command -v "$b" &>/dev/null; then
    ok "Browser found: $b ✓"
    BROWSER_FOUND=true
    break
  fi
done
if [[ "$BROWSER_FOUND" == false ]]; then
  warn "No browser found — screenshots disabled until installed"
  warn "Install: apt-get install -y chromium"
  OPTIONAL_MISSING+=("chromium")
fi

# ── Docker detection ─────────────────────────────────────────────────
info "Detecting Docker..."
if command -v docker &>/dev/null; then
  DOCKER_VER=$(docker --version 2>/dev/null | head -1)
  ok "Docker found: $DOCKER_VER ✓"
  if command -v "docker" &>/dev/null && docker compose version &>/dev/null 2>&1; then
    ok "Docker Compose available ✓"
  fi
else
  info "Docker not found (optional) — needed only for containerized deployment"
  OPTIONAL_MISSING+=("docker")
fi

# ══════════════════════════════════════════════════════════════════════
# INTERNET CONNECTIVITY
# ══════════════════════════════════════════════════════════════════════
section "Network Connectivity"

INTERNET=false
for host in "8.8.8.8" "1.1.1.1"; do
  if nc -z -w 2 "$host" 53 2>/dev/null; then
    INTERNET=true
    ok "Internet reachable ✓"
    break
  fi
done
if [[ "$INTERNET" == false ]]; then
  warn "No internet detected — all frameworks will run in OFFLINE mode"
  warn "Some features (CVE DB updates, nuclei templates) require internet on first run"
  read -rp "  Continue in offline mode? (yes/no): " offline_ans
  [[ "$offline_ans" != "yes" ]] && { warn "Exiting. Connect to internet and re-run install.sh"; exit 0; }
fi

# ══════════════════════════════════════════════════════════════════════
# INTEL DATABASE SEED
# ══════════════════════════════════════════════════════════════════════
section "Intelligence Pipeline"

# Try v5 intel engine first, fall back to legacy cve_import
if [[ "$INTERNET" == true ]]; then
  if $PYTHON -c "from common.intel.intel_engine import IntelEngine" 2>/dev/null; then
    info "Seeding intel database via IntelEngine (NVD + MITRE ATT&CK)..."
    $PYTHON -c "
from common.intel.intel_engine import IntelEngine
engine = IntelEngine()
engine.sync(sources=['cve', 'techniques'])
print('  [+] Intel database seeded')
" 2>/dev/null && ok "Intel database seeded ✓" || warn "Intel seed failed — run 'python3 forge.py intel sync --all' later"
  elif [[ -f "${FORGE_DIR}/netforge/data/cve_import.py" ]]; then
    info "Seeding CVE database from NVD (legacy, may take a minute)..."
    $PYTHON "${FORGE_DIR}/netforge/data/cve_import.py" --init-only 2>/dev/null && \
      ok "CVE database seeded ✓" || warn "CVE seed failed — run 'make update-cve-db' later"
  fi
else
  info "Skipping intel seed (offline mode)"
  info "Run 'python3 forge.py intel sync --all' when connected"
fi

# ══════════════════════════════════════════════════════════════════════
# DIRECTORY STRUCTURE
# ══════════════════════════════════════════════════════════════════════
section "Directory Setup"

for d in "${RESULTS_DIRS[@]}"; do
  mkdir -p "${FORGE_DIR}/${d}"
done
mkdir -p "${FORGE_DIR}/data"          # Intel DB storage
mkdir -p "${FORGE_DIR}/forge_c2/data" # C2 state persistence
ok "Results and data directories ready ✓"

# ══════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"

if [[ ${#MISSING[@]} -eq 0 ]]; then
  echo -e "${GREEN}${BOLD}  ✓ All critical dependencies satisfied. Forge Suite v5 APEX ready.${NC}"
else
  echo -e "${RED}${BOLD}  ✗ Missing critical dependencies:${NC}"
  for m in "${MISSING[@]}"; do
    echo -e "${RED}    - $m${NC}"
  done
fi

if [[ ${#OPTIONAL_MISSING[@]} -gt 0 ]]; then
  echo -e "${YELLOW}${BOLD}  ⚠ Optional tools not found (some modules may have reduced functionality):${NC}"
  for m in "${OPTIONAL_MISSING[@]}"; do
    echo -e "${YELLOW}    - $m${NC}"
  done
fi

echo -e "${BOLD}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}${CYAN}── Quick Start ──${NC}"
echo ""
echo -e "  ${BOLD}Scan:${NC}"
echo -e "    python3 forge.py net --target 10.0.0.0/24 --mode internal"
echo -e "    python3 forge.py web --target https://example.com --dashboard"
echo -e "    python3 forge.py web --targets targets.txt --parallel 5"
echo -e "    python3 forge.py ad  --dc 10.0.0.1 --domain CORP.LOCAL --mode auth"
echo -e "    python3 forge.py ai  --target https://api.openai.com/v1/chat/completions"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}"
echo -e "    python3 forge.py dashboard                    ${DIM}# Web UI at https://localhost:1337${NC}"
echo -e "    python3 forge.py dashboard --tui              ${DIM}# Rich terminal TUI${NC}"
echo ""
echo -e "  ${BOLD}C2 Framework:${NC}"
echo -e "    python3 forge.py c2 server --port 8443        ${DIM}# Start team server${NC}"
echo -e "    python3 forge.py c2 connect --server host:8443 ${DIM}# Connect as operator${NC}"
echo ""
echo -e "  ${BOLD}Intelligence:${NC}"
echo -e "    python3 forge.py intel sync --all             ${DIM}# Sync NVD + ExploitDB + Nuclei + ATT&CK${NC}"
echo -e "    python3 forge.py intel search \"Apache 2.4\"    ${DIM}# Search local intel${NC}"
echo ""
echo -e "  ${BOLD}Docker:${NC}"
echo -e "    docker compose up -d                          ${DIM}# Dashboard + C2 in containers${NC}"
echo -e "    docker compose run forge-scan forge.py net --target 10.0.0.0/24"
echo ""
echo -e "  ${BOLD}Default Credentials:${NC}"
echo -e "    Dashboard: operator / forge2026"
echo -e "    C2 Server: admin / (set via FORGE_C2_ADMIN_PW env var)"
echo ""
