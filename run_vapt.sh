#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Forge Suite v5 APEX — Demo Launcher
#  Starts the live dashboard, runs a full WebForge VAPT, opens browser.
#
#  Usage:
#    ./run_vapt.sh                          # scan default target
#    ./run_vapt.sh https://target.com/      # scan specific target
#    ./run_vapt.sh --help                   # show help
# ─────────────────────────────────────────────────────────────────────────────

FORGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-https://francotech.gov.kh/}"
DASHBOARD_PORT=1337
LOG_DIR="${FORGE_DIR}/logs"
VENV="${FORGE_DIR}/.venv/bin/activate"

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
info()    { echo -e "${CYAN}  [*]${NC} $*"; }
ok()      { echo -e "${GREEN}  [+]${NC} $*"; }
warn()    { echo -e "${YELLOW}  [!]${NC} $*"; }
die()     { echo -e "${RED}  [✗]${NC} $*"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}  ── $* ──${NC}"; }

# ── help ─────────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    echo ""
    echo "  Usage: $(basename "$0") [TARGET_URL]"
    echo ""
    echo "  Examples:"
    echo "    $(basename "$0")                              # default target"
    echo "    $(basename "$0") https://target.example.com/ # custom target"
    echo ""
    echo "  Environment:"
    echo "    DASHBOARD_PORT  Port for the War Room dashboard (default: 1337)"
    echo ""
    exit 0
fi

# ── banner ───────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
  ███████╗ ██████╗ ██████╗  ██████╗ ███████╗    ██╗   ██╗ █████╗ ██████╗ ████████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝    ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝
  █████╗  ██║   ██║██████╔╝██║  ███╗█████╗      ██║   ██║███████║██████╔╝   ██║
  ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝      ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║
  ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗     ╚████╔╝ ██║  ██║██║        ██║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝      ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝
BANNER
echo -e "${NC}"
echo -e "  ${DIM}Web Application Vulnerability Assessment Platform${NC}"
echo -e "  ${DIM}─────────────────────────────────────────────────${NC}"
echo ""

# ── pre-flight ───────────────────────────────────────────────────────────────
section "PRE-FLIGHT CHECK"

[[ -f "${FORGE_DIR}/forge.py" ]] || die "forge.py not found — is this the Forge Suite directory?"

# Activate virtualenv if present (optional — system Python works too)
if [[ -f "$VENV" ]]; then
    source "$VENV"
    ok "Virtual environment activated"
else
    warn "No .venv found — using system Python (run install.sh to set up)"
fi

# Verify Python + forge dependencies
python3 -c "import fastapi, uvicorn, aiohttp" 2>/dev/null \
    && ok "Python dependencies OK" \
    || warn "Some Python dependencies missing — scan may skip modules"

mkdir -p "$LOG_DIR"
DASHBOARD_LOG="${LOG_DIR}/dashboard.log"
VAPT_LOG="${LOG_DIR}/vapt_$(date +%Y%m%d_%H%M%S).log"
SCAN_START=$(date +%s)

echo ""
echo -e "  ${BOLD}Target    :${NC}  ${CYAN}${TARGET}${NC}"
echo -e "  ${BOLD}Dashboard :${NC}  ${CYAN}https://localhost:${DASHBOARD_PORT}${NC}"
echo -e "  ${BOLD}Logs      :${NC}  ${DIM}${VAPT_LOG}${NC}"
echo ""

# ── clean up stale processes ──────────────────────────────────────────────────
section "CLEANUP"

if ss -tlnp 2>/dev/null | grep -q ":${DASHBOARD_PORT} "; then
    warn "Port ${DASHBOARD_PORT} in use — stopping old dashboard..."
    fuser -k "${DASHBOARD_PORT}/tcp" 2>/dev/null || true
    sleep 2
fi

pkill -f "forge.py dashboard" 2>/dev/null || true
pkill -f "forge.py web"       2>/dev/null || true
pkill -f "webforge.py"        2>/dev/null || true
sleep 1
ok "Environment clean"

# ── start dashboard ──────────────────────────────────────────────────────────
section "WAR ROOM DASHBOARD"

info "Starting dashboard on https://localhost:${DASHBOARD_PORT} ..."
python3 "${FORGE_DIR}/forge.py" dashboard \
    --port "${DASHBOARD_PORT}" \
    --no-auth \
    > "$DASHBOARD_LOG" 2>&1 &
DASH_PID=$!

# Wait for dashboard to be ready (up to 20s)
TRIES=0
until ss -tlnp 2>/dev/null | grep -q ":${DASHBOARD_PORT} " || [[ $TRIES -ge 20 ]]; do
    printf "\r  ${CYAN}[*]${NC} Waiting for dashboard... %ds" "$TRIES"
    sleep 1
    TRIES=$((TRIES + 1))
done
echo ""

if ss -tlnp 2>/dev/null | grep -q ":${DASHBOARD_PORT} "; then
    ok "Dashboard running  (PID ${DASH_PID})"
    ok "URL: https://localhost:${DASHBOARD_PORT}"
else
    warn "Dashboard did not start in time — check ${DASHBOARD_LOG}"
fi

# Open browser
for browser in google-chrome google-chrome-stable chromium chromium-browser firefox firefox-esr xdg-open; do
    if command -v "$browser" &>/dev/null; then
        info "Opening in ${browser}..."
        "$browser" --no-sandbox "https://localhost:${DASHBOARD_PORT}" &>/dev/null &
        break
    fi
done

# ── run VAPT ─────────────────────────────────────────────────────────────────
section "VAPT SCAN"

echo ""
echo -e "  ${BOLD}${YELLOW}  Target: ${TARGET}${NC}"
echo -e "  ${DIM}  Live results visible at https://localhost:${DASHBOARD_PORT}${NC}"
echo ""
echo -e "  ${DIM}────────────────────────────────────────────────────────────────${NC}"
echo ""

python3 "${FORGE_DIR}/forge.py" web \
    --target "${TARGET}" \
    --auto-confirm \
    2>&1 | tee "$VAPT_LOG"

VAPT_EXIT=${PIPESTATUS[0]}
SCAN_END=$(date +%s)
SCAN_DURATION=$(( SCAN_END - SCAN_START ))
SCAN_MM=$(( SCAN_DURATION / 60 ))
SCAN_SS=$(( SCAN_DURATION % 60 ))

# ── results summary ──────────────────────────────────────────────────────────
echo ""
echo -e "  ${DIM}────────────────────────────────────────────────────────────────${NC}"
section "SCAN SUMMARY"
echo ""

# Find latest engagement directory (most recently created)
REPORT_DIR=$(ls -dt "${FORGE_DIR}/webforge/results/engagement_"* 2>/dev/null | head -1)
REPORT_HTML="${REPORT_DIR}/report.html"
REPORT_PDF="${REPORT_DIR}/report.pdf"
REPORT_DB="${REPORT_DIR}/webforge.db"

# Pull finding counts — try dashboard API first, fall back to SQLite DB
_get_counts() {
    local json
    json=$(curl -sk --max-time 3 "https://localhost:${DASHBOARD_PORT}/api/v1/state" 2>/dev/null)
    if python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(len(d.get('findings',[])))" "$json" &>/dev/null 2>&1; then
        python3 - "$json" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
f = d.get("findings", [])
print(len(f))
print(sum(1 for x in f if x["severity"]=="Critical"))
print(sum(1 for x in f if x["severity"]=="High"))
print(sum(1 for x in f if x["severity"]=="Medium"))
print(sum(1 for x in f if x["severity"]=="Low"))
print(sum(1 for x in f if x["severity"]=="Informational"))
PY
    elif [[ -f "$REPORT_DB" ]]; then
        python3 - "$REPORT_DB" <<'PY'
import sqlite3, sys
try:
    c = sqlite3.connect(sys.argv[1]).execute("SELECT severity FROM findings")
    rows = [r[0] for r in c.fetchall()]
    print(len(rows))
    print(sum(1 for s in rows if s=="Critical"))
    print(sum(1 for s in rows if s=="High"))
    print(sum(1 for s in rows if s=="Medium"))
    print(sum(1 for s in rows if s=="Low"))
    print(sum(1 for s in rows if s=="Informational"))
except:
    print("0\n0\n0\n0\n0\n0")
PY
    else
        echo "0"; echo "0"; echo "0"; echo "0"; echo "0"; echo "0"
    fi
}

COUNTS=$(_get_counts)
TOTAL=$(   echo "$COUNTS" | sed -n '1p')
CRITICAL=$(echo "$COUNTS" | sed -n '2p')
HIGH=$(    echo "$COUNTS" | sed -n '3p')
MEDIUM=$(  echo "$COUNTS" | sed -n '4p')
LOW=$(     echo "$COUNTS" | sed -n '5p')
INFO=$(    echo "$COUNTS" | sed -n '6p')

if [[ $VAPT_EXIT -eq 0 ]]; then
    ok "Scan completed successfully"
elif [[ $VAPT_EXIT -eq 143 || $VAPT_EXIT -eq 130 ]]; then
    warn "Scan interrupted"
else
    warn "Scan exited with code ${VAPT_EXIT}"
fi
echo ""
echo -e "  ${BOLD}Duration  :${NC}  ${SCAN_MM}m ${SCAN_SS}s"
echo -e "  ${BOLD}Target    :${NC}  ${TARGET}"
echo ""
echo -e "  ${BOLD}Findings  :${NC}  ${BOLD}${TOTAL} total${NC}"
[[ "$CRITICAL" != "0" ]] && echo -e "             ${RED}  Critical : ${CRITICAL}${NC}"
[[ "$HIGH" != "0" ]]     && echo -e "             ${YELLOW}  High     : ${HIGH}${NC}"
[[ "$MEDIUM" != "0" ]]   && echo -e "             ${CYAN}  Medium   : ${MEDIUM}${NC}"
[[ "$LOW" != "0" ]]      && echo -e "             ${GREEN}  Low      : ${LOW}${NC}"
[[ "$INFO" != "0" ]]     && echo -e "             ${DIM}  Info     : ${INFO}${NC}"
echo ""

if [[ -f "$REPORT_HTML" ]]; then
    ok "HTML Report : ${REPORT_HTML}"
fi
if [[ -f "$REPORT_PDF" ]]; then
    ok "PDF Report  : ${REPORT_PDF}"
fi

echo ""
echo -e "  ${BOLD}Dashboard :${NC}  https://localhost:${DASHBOARD_PORT}"
echo -e "  ${DIM}           (Press Ctrl+C to stop the dashboard)${NC}"
echo ""
echo -e "  ${DIM}────────────────────────────────────────────────────────────────${NC}"
echo ""

# Open report in browser if available
if [[ -f "$REPORT_HTML" ]]; then
    for browser in google-chrome google-chrome-stable chromium chromium-browser firefox firefox-esr; do
        if command -v "$browser" &>/dev/null; then
            info "Opening HTML report in ${browser}..."
            "$browser" --no-sandbox "file://${REPORT_HTML}" &>/dev/null &
            break
        fi
    done
fi

# Keep dashboard alive
if kill -0 "$DASH_PID" 2>/dev/null; then
    trap "echo ''; info 'Stopping dashboard...'; kill $DASH_PID 2>/dev/null; exit 0" INT TERM
    wait "$DASH_PID"
fi
