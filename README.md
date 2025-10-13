# B9-Phish — “Danger, Will Robinson!” for your inbox

> **One-liner:** A privacy-first, open-source Gmail triage tool that uses **deterministic rules** to flag likely phishing and then adds a **clear, 3-bullet LLM explanation** (opt-in). Run locally, label in Gmail, export analyst-ready evidence.

---

## Why B9-Phish?

The B-9 Robot from *Lost in Space* is the original “Danger, Will Robinson!” alarm. B9-Phish is that—**polite, fast, and explainable**. It doesn’t “do AI” to you; it helps you **see the danger and decide**.

---

## Features

- **Rules, not magic.** SPF/DKIM/DMARC, sender/domain mismatches, deceptive links, dangerous attachments, and more.
- **Transparent scoring.** Every alert shows **which rules fired** and the final **score** → `High`, `Review`, or `Pass`.
- **Inbox-native workflow.** Optional **Gmail labels**: `B9-Phish/High`, `B9-Phish/Review`.
- **Analyst-ready outputs.** `alerts.json`, `alerts.csv`, per-message Markdown notes, and an HTML **report**.
- **Privacy by default.** Headers + safe snippets by default; full-body scanning is **opt-in** and local.
- **LLM explainer (opt-in).** Three clear bullets (model sees **features only** unless you enable raw text).
- **Approachable OSS.** Clean CLI, small codebase, editable YAML rules, and tests.

---

## Quickstart (5 minutes)

### Requirements
- macOS (tested), Python **3.11+**
- Git + (optional) GitHub CLI `gh`

### Install
```bash
# from inside the project
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python -m pip install -e .
pytest -q   # should pass
