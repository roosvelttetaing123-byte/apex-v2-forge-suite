#!/usr/bin/env bash
# Reproducible local dependency installation for Forge Suite.
# Network access is limited to the Python and npm package registries selected by
# those clients; this script performs no public-IP probes or intelligence sync.
set -euo pipefail
umask 077

readonly FORGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly VERSION_FILE="${FORGE_DIR}/VERSION"
readonly PYTHON_LOCK="${FORGE_DIR}/requirements.lock"
readonly FRONTEND_DIR="${FORGE_DIR}/apex-ui"
readonly VENV_DIR="${FORGE_DIR}/.venv"
readonly EXPECTED_PYTHON_VERSION="3.13.9"
readonly EXPECTED_NODE_VERSION="20.19.5"
readonly EXPECTED_NPM_VERSION="10.8.2"

fail() {
  printf 'forge install: ERROR: %s\n' "$*" >&2
  exit 1
}

status() {
  printf 'forge install: %s\n' "$*"
}

[[ -r "${VERSION_FILE}" ]] || fail "canonical VERSION file is missing"
[[ -r "${PYTHON_LOCK}" ]] || fail "requirements.lock is missing"
[[ -r "${FRONTEND_DIR}/package-lock.json" ]] || fail "apex-ui/package-lock.json is missing"

FORGE_VERSION="$(tr -d '\r\n' < "${VERSION_FILE}")"
[[ "${FORGE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || fail "VERSION must contain one semantic version"
status "installing Forge Suite ${FORGE_VERSION}"

python_bin="${FORGE_PYTHON:-$(command -v python3 || true)}"
[[ -n "${python_bin}" && -x "${python_bin}" ]] || fail "python3 was not found"
python_version="$("${python_bin}" -c 'import platform; print(platform.python_version())')"
[[ "${python_version}" == "${EXPECTED_PYTHON_VERSION}" ]] \
  || fail "CPython ${EXPECTED_PYTHON_VERSION} is required; found ${python_version}"

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  [[ ! -e "${VENV_DIR}" ]] \
    || fail "${VENV_DIR} exists but is not a usable virtual environment"
  status "creating isolated Python environment"
  "${python_bin}" -m venv "${VENV_DIR}"
fi

venv_python_version="$("${VENV_DIR}/bin/python" -c 'import platform; print(platform.python_version())')"
[[ "${venv_python_version}" == "${EXPECTED_PYTHON_VERSION}" ]] \
  || fail ".venv uses CPython ${venv_python_version}; ${EXPECTED_PYTHON_VERSION} is required"

status "installing the hash-locked Python dependency graph"
PIP_DISABLE_PIP_VERSION_CHECK=1 \
PIP_NO_INPUT=1 \
PIP_PROGRESS_BAR=off \
  "${VENV_DIR}/bin/python" -m pip install \
    --no-cache-dir \
    --require-hashes \
    --requirement "${PYTHON_LOCK}"
"${VENV_DIR}/bin/python" -m pip check
"${VENV_DIR}/bin/python" -c \
  'import aiohttp, cryptography, fastapi, jinja2, pydantic, rich, uvicorn'

node_bin="$(command -v node || true)"
npm_bin="$(command -v npm || true)"
[[ -n "${node_bin}" && -x "${node_bin}" ]] || fail "Node.js 20 was not found"
[[ -n "${npm_bin}" && -x "${npm_bin}" ]] || fail "npm was not found"
node_version="$("${node_bin}" -p 'process.versions.node')"
[[ "${node_version}" == "${EXPECTED_NODE_VERSION}" ]] \
  || fail "Node.js ${EXPECTED_NODE_VERSION} is required; found ${node_version}"
npm_version="$("${npm_bin}" --version)"
[[ "${npm_version}" == "${EXPECTED_NPM_VERSION}" ]] \
  || fail "npm ${EXPECTED_NPM_VERSION} is required; found ${npm_version}"

status "installing and verifying the npm lock graph"
(
  cd "${FRONTEND_DIR}"
  "${npm_bin}" ci --ignore-scripts --no-audit --no-fund
  "${npm_bin}" run typecheck
  "${npm_bin}" run build
)

for runtime_dir in \
  webforge/results \
  netforge/results \
  adforge/results \
  aiforge/results \
  results \
  data; do
  mkdir -p "${FORGE_DIR}/${runtime_dir}"
  chmod 700 "${FORGE_DIR}/${runtime_dir}"
done

if command -v nuclei >/dev/null 2>&1; then
  status "Nuclei status: operator-provided binary detected on PATH (not managed by Forge)"
else
  status "Nuclei status: omitted; provide a separately pinned binary only if required"
fi

status "complete; no credentials were generated and no .env file was written"
status "run commands with ${VENV_DIR}/bin/python or activate ${VENV_DIR}/bin/activate"
