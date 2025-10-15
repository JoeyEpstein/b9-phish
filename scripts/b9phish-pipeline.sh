#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

CREDENTIALS_PATH="${B9_CREDENTIALS_PATH:-${REPO_ROOT}/credentials.json}"
TOKEN_PATH="${B9_TOKEN_PATH:-${REPO_ROOT}/token.json}"
OUTPUT_DIR="${B9_OUTPUT_DIR:-${REPO_ROOT}/outputs}"
REPORT_PATH="${B9_REPORT_PATH:-${OUTPUT_DIR}/report.html}"
SCAN_SINCE="${B9_SINCE:-1d}"
SCAN_MAX="${B9_MAX:-200}"
SCAN_QUERY="${B9_QUERY:-}"
FULL_BODY="${B9_FULL_BODY:-false}"
INCLUDE_SPAM="${B9_INCLUDE_SPAM:-true}"
APPLY_LABELS="${B9_APPLY_LABELS:-true}"
HIGH_LABEL="${B9_HIGH_LABEL:-B9-Phish/High}"
REVIEW_LABEL="${B9_REVIEW_LABEL:-B9-Phish/Review}"
ALERT_FILE="${B9_ALERT_FILE:-${OUTPUT_DIR}/alerts.json}"

if [[ -d "${REPO_ROOT}/.venv" && -f "${REPO_ROOT}/.venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "${REPO_ROOT}/.venv/bin/activate"
fi

if command -v b9 >/dev/null 2>&1; then
  B9_CMD=(b9)
elif [[ -x "${REPO_ROOT}/.venv/bin/b9" ]]; then
  B9_CMD=("${REPO_ROOT}/.venv/bin/b9")
else
  B9_CMD=(python3 -m b9phish.cli)
fi

run_b9() {
  "${B9_CMD[@]}" "$@"
}

log "Starting B9-Phish pipeline"

if [[ ! -f "${CREDENTIALS_PATH}" ]]; then
  echo "ls: ${CREDENTIALS_PATH}: No such file or directory" >&2
  echo ">>> credentials.json missing — download an OAuth Client ID (Desktop) and place it here" >&2
  echo "[b9-phish] credentials.json missing in ${REPO_ROOT}" >&2
  exit 1
fi

if [[ ! -f "${TOKEN_PATH}" ]]; then
  echo ">>> token.json missing — run 'b9 init --creds ${CREDENTIALS_PATH}'" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

SCAN_ARGS=(scan --since "${SCAN_SINCE}" --max "${SCAN_MAX}" --out "${OUTPUT_DIR}")
if [[ -n "${SCAN_QUERY}" ]]; then
  SCAN_ARGS+=(--query "${SCAN_QUERY}")
fi
if [[ "${FULL_BODY}" == "true" ]]; then
  SCAN_ARGS+=(--full-body)
fi
if [[ "${INCLUDE_SPAM}" == "true" ]]; then
  SCAN_ARGS+=(--include-spam)
fi

log "Running: b9 ${SCAN_ARGS[*]}"
run_b9 "${SCAN_ARGS[@]}"

log "Building report at ${REPORT_PATH}"
run_b9 report --out "${REPORT_PATH}"

if [[ "${APPLY_LABELS}" == "true" ]]; then
  log "Applying labels using ${ALERT_FILE}"
  run_b9 label --from-file "${ALERT_FILE}" --high "${HIGH_LABEL}" --review "${REVIEW_LABEL}"
fi

log "B9-Phish pipeline complete"
