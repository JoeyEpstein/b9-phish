# 🛡️ B9-Phish

> **"Danger, Will Robinson!"** — Your personal phishing detection system that actually explains what it finds.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://github.com/JoeyEpstein/b9-phish/workflows/CI/badge.svg)](https://github.com/JoeyEpstein/b9-phish/actions)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**B9-Phish** is a privacy-first, open-source phishing detection system that runs locally on your machine to protect your Gmail inbox. Unlike cloud-based solutions that read your emails, B9-Phish analyzes authentication headers and metadata *without ever sending your email content anywhere*.

---

## 🎯 Why This Exists

In 2025, phishing attacks have become sophisticated enough to fool even technical users. Multi-factor authentication prompts, QR code delivery, OAuth consent tricks, and AI-generated social engineering are the new normal. Meanwhile, enterprise security tools cost thousands and small businesses, families, and individuals are left vulnerable.

**I built B9-Phish because everyone deserves enterprise-grade email security — for free.**

This tool is designed for:
- 👨‍👩‍👧‍👦 **Families** protecting elderly relatives from scams
- 💼 **Small businesses** without security budgets
- 🔒 **Privacy-conscious individuals** who don't want cloud services reading their emails
- 🛠️ **Security practitioners** learning modern phishing detection techniques
- 🎓 **Students and researchers** studying email security

---

## ✨ What Makes B9-Phish Different

### 🔐 Privacy First
- **Headers-only mode by default** — never sends email bodies anywhere
- **100% local processing** — your emails never leave your machine
- **No telemetry** — zero tracking, zero phone-home
- **OAuth with minimal scopes** — read-only by default
- **Open source** — audit every line of code yourself

### 🎯 Explainable Detection
Every alert includes:
- ✅ **Transparent scoring** — see exactly which rules triggered
- 📊 **Severity levels** — Danger, Review, or Safe
- 📝 **Plain English explanations** — no security jargon
- 🔍 **Actionable indicators** — domains, URLs, authentication failures

### 🚀 Production Ready
- 15+ detection signals covering 2025 attack patterns
- Tested on real Gmail traffic with <1% false positive target
- Multiple output formats: JSON, CSV, HTML reports, Markdown notes
- Gmail label automation for inbox triage
- Comprehensive test coverage with pytest
- CI/CD via GitHub Actions

---

## 🔍 Detection Capabilities

B9-Phish catches modern phishing techniques:

| Category | Detections |
|----------|-----------|
| **Authentication** | SPF failures, DKIM failures, DMARC policy violations, ARC chain breaks |
| **Domain Abuse** | Punycode/IDN homographs, suspicious TLDs (.zip, .top, .xyz), IP literals in URLs |
| **Sender Anomalies** | Display name vs domain mismatches, Reply-To spoofing, Return-Path mismatches, Message-ID domain conflicts |
| **URL Tricks** | Shortener services (bit.ly, t.co), redirect chains, non-standard ports, deceptive brand keywords |
| **Attachments** | Dangerous extensions (.html, .lnk, .iso, macro docs), SVG/HTML masquerading as PDFs |
| **Social Engineering** | Urgency keywords, password reset baits, verification demands, gift card requests |
| **2025 Tactics** | QR code phishing, OAuth consent abuse, thread hijacking, Unicode obfuscation (RLO, zero-width) |
| **Optional** | VirusTotal URL/domain reputation (opt-in, sends URLs only) |

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites

- **macOS, Linux, or Windows** (tested on macOS)
- **Python 3.11 or newer**
- **Gmail account** (personal or Google Workspace)

### 1. Install

```bash
# Clone the repository
git clone https://github.com/JoeyEpstein/b9-phish.git
cd b9-phish

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

# Verify installation
b9 version
```

### 2. Set Up Gmail API

**Why?** B9-Phish uses the official Gmail API (not IMAP) for secure, read-only access to your headers.

#### Step 2a: Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (e.g., "B9-Phish-Personal")
3. Enable the **Gmail API**:
   - Search for "Gmail API" in the API Library
   - Click "Enable"

#### Step 2b: Create OAuth Credentials

1. Navigate to **APIs & Services → Credentials**
2. Click **+ CREATE CREDENTIALS → OAuth client ID**
3. Configure the consent screen if prompted:
   - User Type: **External** (for personal accounts)
   - App name: `B9-Phish`
   - User support email: your email
   - Developer contact: your email
   - Save and Continue (leave scopes empty for now)
4. Back in Credentials:
   - Application type: **Desktop app**
   - Name: `B9-Phish Desktop`
   - Click **Create**
5. **Download the JSON file** as `credentials.json`
6. Move `credentials.json` to the `b9-phish` directory

**Important:** If your app is in "Testing" mode, add your Gmail address under "Test users" in the OAuth consent screen.

#### Step 2c: Authorize B9-Phish

```bash
# Initialize with read-only access (safe to start)
b9 init --creds ./credentials.json --scopes readonly

# This will:
# 1. Open your browser
# 2. Ask you to sign in to Google
# 3. Show permission request (Gmail read-only)
# 4. Redirect back with authorization
# 5. Save token.json locally
```

✅ **You're ready!** B9-Phish can now read your Gmail headers.

### 3. Run Your First Scan

```bash
# Scan the last 2 days of mail (up to 50 messages)
b9 scan --since 2d --max 50 --out ./outputs

# Generate HTML report
b9 report --out ./outputs/report.html

# Open the report
open ./outputs/report.html  # macOS
# xdg-open ./outputs/report.html  # Linux
# start ./outputs/report.html  # Windows
```

> Tip: add `--include-spam` to pull messages from Gmail's Spam/Trash folders when you plan to label everything automatically.

**What you'll see:**
- 🔴 **High-risk messages** (red) — likely phishing
- 🟠 **Review needed** (orange) — suspicious patterns
- 🟢 **Safe** (green) — passed all checks

---

## 📖 Complete Usage Guide

### Basic Commands

```bash
# Show version
b9 version

# List all detection rules and weights
b9 rules --list

# Explain a specific rule
b9 rules --explain SPF_FAIL

# Scan recent mail
b9 scan --since 7d --max 100 --out ./outputs

# Scan inbox + spam
b9 scan --since 7d --max 100 --out ./outputs --include-spam

# Scan with custom Gmail query
b9 scan --query "from:paypal.com OR from:amazon.com" --out ./outputs

# Generate report
b9 report --out ./outputs/report.html
```

### Privacy Modes

**Headers-only (default):**
```bash
# Analyzes authentication headers + subject + snippet only
b9 scan --since 3d --out ./outputs
```

**Full-body (opt-in for URL/attachment analysis):**
```bash
# Processes full email bodies to extract URLs and attachments
b9 scan --since 3d --full-body --out ./outputs
```

### Gmail Label Automation

Apply labels automatically to organize detected threats in your inbox:

```bash
# First, re-authorize with modify scope
rm token.json
b9 init --creds ./credentials.json --scopes modify --create-labels

# Scan and label
b9 scan --since 7d --out ./outputs --include-spam
b9 label --high "🚨 Phishing/Danger" --review "⚠️ Phishing/Review"
```

Labels are color-coded:
- 🔴 **Danger** — Red background, white text
- 🟠 **Review** — Orange background, black text

### VirusTotal Integration (Optional)

Send URLs (not email content) to VirusTotal for reputation checks:

```bash
# 1. Get a free VirusTotal API key at https://www.virustotal.com/
# 2. Set environment variables
export B9_VT_ENABLED=true
export VT_API_KEY='your_api_key_here'

# 3. Scan with full body to extract URLs
b9 scan --since 3d --full-body --out ./outputs

# 4. Post-process with VT checks (adds VT_MALICIOUS_URL rule)
python -m b9phish.vt_apply --alerts ./outputs/alerts.json --rules rules/default.yml --weight 45

# 5. Rebuild report
b9 report --out ./outputs/report.html
```

### Continuous Monitoring

Run B9-Phish automatically every 5 minutes:

```bash
# Create monitoring script
cat > monitor.sh << 'EOF'
#!/bin/bash
while true; do
  b9 scan --since 5m --max 100 --full-body --out ./outputs
  b9 label --high "🚨 Phishing/Danger" --review "⚠️ Phishing/Review"
  sleep 300  # 5 minutes
done
EOF

chmod +x monitor.sh
./monitor.sh
```

Or use `cron` (macOS/Linux):
```bash
# Run every 15 minutes
*/15 * * * * cd /path/to/b9-phish && .venv/bin/b9 scan --since 15m --out ./outputs --include-spam && .venv/bin/b9 label
```

---

## 📊 Understanding the Outputs

### Directory Structure

```
outputs/
├── alerts.json          # Machine-readable results
├── alerts.csv           # Spreadsheet-friendly export
├── report.html          # Interactive HTML dashboard
└── notes/
    ├── <msgid1>.md      # Per-message analysis
    └── <msgid2>.md
```

### JSON Format

```json
{
  "id": "18f8a1b2c3d4e5f6",
  "date": "Tue, 14 Oct 2025 10:23:45 -0700",
  "from": "security@micr0soft.com",
  "subject": "Verify your account immediately",
  "score": 85,
  "severity": "High",
  "rule_hits": [
    "SPF_FAIL",
    "DISPLAY_NAME_IMPERSONATION",
    "URGENCY_BAIT",
    "IDN_OR_SUSPICIOUS_TLD"
  ],
  "indicators": {
    "domains": ["micr0soft.com", "login-verify.xyz"],
    "urls": ["https://login-verify.xyz/account"]
  },
  "note_file": "notes/18f8a1b2c3d4e5f6.md"
}
```

### Severity Thresholds (Configurable)

| Score | Severity | Meaning |
|-------|----------|---------|
| ≥ 60  | **Danger** | Very likely phishing — do not click anything |
| 35-59 | **Review** | Suspicious patterns — verify sender before acting |
| < 35  | **Pass** | No significant threats detected |

Edit thresholds in `rules/default.yml`:
```yaml
thresholds:
  high: 60    # Danger threshold
  review: 35  # Review threshold
```

---

## 🔧 Customization & Tuning

### Adjust Rule Weights

All detection rules and weights are in `rules/default.yml`:

```yaml
weights:
  SPF_FAIL: 35
  DKIM_FAIL_OR_NODMARC: 25
  DISPLAY_NAME_IMPERSONATION: 20
  DANGEROUS_ATTACHMENT: 40
  URGENCY_BAIT: 15
  # ... more rules
```

**To tune:**
1. Run scans on your inbox
2. Review false positives/negatives in `alerts.json`
3. Adjust weights (increase to catch more, decrease to reduce noise)
4. Re-run: `b9 scan --since 7d --out ./outputs`

### Add Trusted Senders

Reduce false positives from legitimate but complex senders:

```yaml
allowlists:
  domains:
    - github.com
    - google.com
    - yourcompany.com
  senders:
    - noreply@trusted-vendor.com
```

### Create Custom Rules

Rules are defined in `src/b9phish/rules.py`. Example:

```python
def score(self, features: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    hits = []
    
    # Your custom rule
    if "urgent" in features.get("subject", "").lower():
        score += self._w("CUSTOM_URGENCY")
        hits.append("CUSTOM_URGENCY")
    
    # ... rest of scoring logic
```

Add weight to `rules/default.yml`:
```yaml
weights:
  CUSTOM_URGENCY: 20
```

---

## 🧪 Development & Testing

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/b9phish --cov-report=html

# Run specific test file
pytest tests/test_rules.py -v
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint
flake8 src/ tests/

# Or use pre-commit hooks
pre-commit install
pre-commit run --all-files
```

### Test with Sample Emails

```bash
# Scan the included .eml examples (no Gmail needed)
b9 scan --eml-dir ./examples/sample_emls --out ./test_outputs
b9 report --out ./test_outputs/report.html
```

### Automate Daily Scans (macOS launchd example)

Want B9-Phish to run on a schedule? Use the provided `scripts/b9phish-pipeline.sh` wrapper with `launchd` on macOS:

```bash
# Copy the launch agent template to your user LaunchAgents folder
cp scripts/com.b9phish.pipeline.plist ~/Library/LaunchAgents/

# Load (or reload) the job
launchctl unload ~/Library/LaunchAgents/com.b9phish.pipeline.plist 2>/dev/null || true
launchctl load ~/Library/LaunchAgents/com.b9phish.pipeline.plist
```

Edit the template first to point `ProgramArguments` and `WorkingDirectory` at your local clone (replace `USERNAME/path/to`). Adjust `StartInterval` or use `StartCalendarInterval` for specific times of day.

The pipeline script will:

- Ensure `credentials.json` and `token.json` exist before running
- Activate `.venv` automatically when present
- Run `b9 scan` (default: last 1 day, max 200 messages, includes Spam/Trash)
- Build the HTML report (`outputs/report.html`)
- Optionally apply Gmail labels when `B9_APPLY_LABELS=true`

Customize behaviour with environment variables inside the plist (or before calling the script):

| Variable | Purpose | Default |
| --- | --- | --- |
| `B9_SINCE` | Gmail `--since` window | `1d` |
| `B9_MAX` | `--max` messages per scan | `200` |
| `B9_QUERY` | Additional Gmail query filter | *(empty)* |
| `B9_FULL_BODY` | Set to `true` to include full bodies | `false` |
| `B9_INCLUDE_SPAM` | Include Gmail Spam/Trash during scans | `true` |
| `B9_OUTPUT_DIR` | Output directory | `./outputs` |
| `B9_REPORT_PATH` | Report destination | `./outputs/report.html` |
| `B9_APPLY_LABELS` | `true` to run `b9 label` | `true` |
| `B9_HIGH_LABEL` / `B9_REVIEW_LABEL` | Gmail label names | `B9-Phish/High`, `B9-Phish/Review` |

> ℹ️ The script exits early with a helpful message if `credentials.json` or `token.json` are missing, preventing launchd from looping endlessly.

---

## 🗺️ Roadmap

### ✅ v0.1.0 (Current)
- Core rule engine with 15+ signals
- Gmail API integration
- Privacy-first headers-only mode
- Multi-format outputs
- Label automation
- VirusTotal integration

### 🚧 v0.2.0 (Planned)
- [ ] Machine learning feature extraction (still explainable)
- [ ] IMAP support (non-Gmail providers)
- [ ] Real-time watcher daemon
- [ ] Browser extension for link preview
- [ ] Mobile app (view reports on phone)

### 💭 Future Ideas
- Sender reputation database (privacy-preserving)
- Image OCR for QR code detection
- LLM-based semantic analysis (opt-in, features-only)
- Multi-language support
- Desktop GUI

**Want to contribute?** See [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 🤝 Contributing

Contributions welcome! Areas where help is needed:

- **Rules & signatures** — New phishing patterns you've seen
- **Testing** — Run on diverse mailboxes, report false positives/negatives
- **Integrations** — Outlook, Proton Mail, etc.
- **Documentation** — Tutorials, translations, guides
- **Code quality** — Refactoring, performance improvements

**Process:**
1. Fork the repo
2. Create a feature branch (`git checkout -b feature/new-rule`)
3. Write tests for your changes
4. Ensure `pytest` and linters pass
5. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 🛡️ Security & Privacy

### Data Handling

**What B9-Phish accesses:**
- Email headers (From, To, Subject, Authentication-Results, etc.)
- Message snippet (first ~200 characters, provided by Gmail API)
- Full body text (only if you use `--full-body` flag)

**What B9-Phish never does:**
- ❌ Send your emails to external services
- ❌ Store emails in a database
- ❌ Phone home with telemetry
- ❌ Share data with third parties

**Optional external calls:**
- **VirusTotal:** If enabled, sends URLs only (not email content)
- **Gmail API:** Direct connection to your Google account (OAuth2)

### Security Considerations

**Credentials storage:**
- `credentials.json` — OAuth client credentials (gitignored)
- `token.json` — Your access token (gitignored, revocable anytime)

**Revoke access:**
- Visit [Google Account Permissions](https://myaccount.google.com/permissions)
- Remove B9-Phish access
- Delete `token.json` locally

**Report vulnerabilities:**
- See [SECURITY.md](SECURITY.md)
- Responsible disclosure: email security contact (see repo)
- Do not open public issues for exploits

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

**What this means:**
- ✅ Use commercially or personally
- ✅ Modify and distribute
- ✅ Private use
- ❌ No warranty (use at your own risk)
- ⚠️ Must include original license and copyright

---

## 🙏 Acknowledgments

**Inspired by:**
- The B-9 Robot from *Lost in Space* ("Danger, Will Robinson!")
- Modern phishing victims who deserve better protection
- The open-source security community

**Built with:**
- [Google Gmail API](https://developers.google.com/gmail/api)
- [Typer](https://typer.tiangolo.com/) — Beautiful CLI framework
- [Rich](https://rich.readthedocs.io/) — Terminal formatting
- [pytest](https://pytest.org/) — Testing framework
- [VirusTotal](https://www.virustotal.com/) — Optional URL reputation

**Special thanks:**
- Everyone who's been phished and shared their story
- Security researchers documenting modern attack techniques
- The Python community for excellent tooling

---

## 📞 Contact & Support

**Questions?** Open a [GitHub Discussion](https://github.com/JoeyEpstein/b9-phish/discussions)

**Bugs?** File a [GitHub Issue](https://github.com/JoeyEpstein/b9-phish/issues)

**Want updates?** Star ⭐ and Watch 👀 this repo

**Professional inquiries:** See [GitHub profile](https://github.com/JoeyEpstein)

---

## 📈 Star History

If B9-Phish helped you or someone you care about, please consider:
- ⭐ **Star this repo** — helps others discover it
- 🐦 **Share on social media** — spread the word about free security tools
- 💡 **Suggest improvements** — your feedback makes it better
- 🤝 **Contribute code** — join the mission

**Together, we can make phishing attacks a lot less profitable.**

---

<p align="center">
  <strong>Made with ❤️ for a safer internet</strong><br>
  <sub>© 2025 Joey Epstein • MIT License</sub>
</p>
