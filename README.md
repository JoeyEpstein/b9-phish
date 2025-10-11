# B9-Phish — “Danger, Will Robinson!” for your inbox

**Privacy-first Gmail triage** with deterministic rules + short, clear explanations.

> ✨ TL;DR: Run locally. Headers only by default. Label suspicious mail. Export JSON/CSV/Markdown for analysts.

---

## Quickstart (5 minutes)

### 1) Install
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### 2) Create a Google OAuth Desktop Client
- Go to Google Cloud Console → APIs & Services → Credentials → **Create Credentials → OAuth client ID**.
- Application type: **Desktop**.
- Download the `credentials.json` and put it in the repo root (gitignored).

### 3) Initialize
```bash
b9 init --creds ./credentials.json --scopes readonly
```
This starts a local OAuth flow and creates `token.json` locally.

### 4) Try a scan (sample EMLs)
```bash
b9 scan --eml-dir ./examples/sample_emls --out ./outputs
```
This parses two synthetic emails and writes `alerts.json`, `alerts.csv`, and `notes/*.md`.

### 5) Optional: Scan Gmail headers
```bash
b9 scan --since 7d --max 50 --out ./outputs
```
> Requires `token.json`. Defaults to **headers-only**. Use `--full-body on` to opt in to full content parsing.

### 6) Optional: Apply labels in Gmail
```bash
b9 label --high "B9-Phish/High" --review "B9-Phish/Review"
```
> You must re-run `b9 init --scopes modify` once to grant `gmail.modify` and `gmail.labels`.

### 7) Build an HTML report
```bash
b9 report --out ./outputs/report.html
```

---

## What it does

- Extracts features from Gmail **Authentication-Results**, addresses, URLs, and attachments.
- Runs transparent **YAML-configured rules** to compute a score and severity (`High`, `Review`, `Pass`).
- Writes **JSON/CSV/Markdown** (and optional HTML) and can **apply Gmail labels** (`B9-Phish/High`, `B9-Phish/Review`).

## What it **does not** do

- Auto-delete, auto-forward, or auto-archive emails.
- Send your mail to a remote server without your explicit opt-in.
- Replace your judgment—B9-Phish is a **helper**, not an inbox cop.

---

## CLI Overview

```
b9 init    # OAuth + token handling; optional label creation
b9 scan    # Fetch → extract features → rules → outputs
b9 report  # Build a static HTML report
b9 label   # Apply Gmail labels based on last scan results
b9 rules   # List rules and weights or explain one rule
```

Run `b9 --help` and `b9 <cmd> --help` for details.

---

## Configuration

- Rules live in `rules/default.yml` (editable).
- `.env` toggles: `B9_LLM_ENABLED=false` (default), `B9_OUTPUT_DIR`, `B9_HEADERS_ONLY=true`.
- Allow/deny lists are part of the YAML file under `allowlists`.

---

## Development

```bash
pytest -q
```

---

## License

MIT
