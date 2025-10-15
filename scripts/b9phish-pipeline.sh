#!/bin/zsh
set -euo pipefail

REPO="/Users/joeyepstein/Desktop/b9-phish"
PYBIN="$REPO/.venv/bin/python"
export PYTHONPATH="$REPO/src"

cd "$REPO"

# Guardrails: creds & token
if [ ! -f "$REPO/credentials.json" ]; then
  echo "[b9-phish] credentials.json missing in $REPO" >&2
  exit 1
fi
if [ ! -f "$REPO/token.json" ]; then
  echo "[b9-phish] token.json missing. Run: $PYBIN -m b9phish.gmail_auth" >&2
  exit 1
fi

# Pipeline
$PYBIN -m b9phish.fetch    --query '(in:inbox OR in:spam) newer_than:2d' --out .tmp/fetch.ndjson
$PYBIN -m b9phish.parse    --in .tmp/fetch.ndjson    --out .tmp/parsed.ndjson
$PYBIN -m b9phish.features --in .tmp/parsed.ndjson   --out .tmp/features.ndjson
$PYBIN -m b9phish.rules    --in .tmp/features.ndjson --out .tmp/scored.ndjson
$PYBIN -m b9phish.outputs alerts --in .tmp/scored.ndjson --out outputs/alerts.json

# Label based on outputs/alerts.json
$PYBIN -m b9phish.label_all \
  --alerts outputs/alerts.json \
  --pass-label 'All Clear' \
  --review-label 'Proceed with Caution' \
  --high-label 'Danger! Danger!'
