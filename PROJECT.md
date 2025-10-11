# B9-Phish — “Danger, Will Robinson!” for your inbox

**One-liner:** A privacy-first, open-source Gmail triage tool that uses **deterministic rules** to flag likely phishing and then adds a **clear, 3-bullet LLM explanation**. Run locally, label in Gmail, export analyst-ready evidence.

---

## 1) Goals (what “winning” looks like)

1. **Catch the bad stuff without drama**

   * High recall on common phish tactics (spoofing, look-alikes, attachment traps).
   * No “magic”—every alert includes **transparent reasons**.

2. **Privacy by default**

   * Process **headers + safe snippets** locally.
   * LLM sees **features only**, not raw email content (opt-in to send raw text if the user wants—off by default).

3. **Operationally useful**

   * Apply **Gmail labels** so triage happens right in the inbox.
   * Export **JSON/CSV** + Markdown notes; optional **HTML dashboard** for reports.
   * KQL-ready CSV to hunt the same indicators elsewhere.

4. **Approachable open source**

   * Simple **local CLI**: users bring their own Google OAuth credentials.
   * Clean architecture, tests, and a plug-in system for new rules.

---

## 2) Deliverables (you’ll ship these)

* **Repo**: `b9-phish` (MIT or Apache-2.0 license)
* **CLI tool**: `b9` with subcommands (`init`, `scan`, `report`, `label`, `serve`)
* **Outputs**: `alerts.json`, `alerts.csv`, `notes/MSGID.md`, optional `report.html`
* **Gmail labeling** (optional): create/apply `B9-Phish/High`, `B9-Phish/Review`
* **Docs**:

  * `README.md` (5-min quickstart, OAuth setup)
  * `PRIVACY.md` (what leaves the machine: by default, nothing)
  * `SECURITY.md` (reporting vulns; scope)
  * `PROJECT.md` (this spec)
* **Tests**: unit tests for parsers/rules; fixtures for known attacks
* **Examples**: synthetic `.eml` files for safe demo
* **Apps Script mini-labeler (optional)**: for users who want in-Gmail automation without Python

---

## 3) Architecture (privacy-first)

```
Gmail API/EML/IMAP   -->   FETCH (headers + safe snippet) --> FEATURE EXTRACTORS
                                                              |  SPF/DKIM/DMARC
                                                              |  URL heuristics
                                                              |  sender anomalies
                                                              |  attachments
                            RULES ENGINE --------------> verdict (score, reasons, indicators)
                                   |
                                   +--> LLM EXPLAINER (features-in) --> 3-bullet rationale
                                   |
                                   +--> OUTPUTS (JSON/CSV/MD/HTML), optional GMAIL LABELS
```

* **Data sources**: Gmail API (primary), folder of `.eml` files (secondary), generic IMAP (later).
* **Storage**: local `./outputs` (JSON/CSV/MD), optional tiny SQLite cache for dedup & state.
* **No network exfiltration** (except Gmail API + optional LLM endpoint if the user turns it on).

---

## 4) Features & functions (implementable checklist)
[...spec condensed: full version kept in user message...]
