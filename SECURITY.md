# SECURITY

If you discover a security issue, please open a security advisory or email the maintainers.
Scope for responsible disclosure includes the CLI, rules engine, output writers, and OAuth flow.

**Threat model (high level):**
- Data at rest lives under `./outputs` (JSON/CSV/MD). Treat that directory as sensitive.
- No auto-deletion, forwarding, or archival of emails; B9-Phish is advisory by default.
- Labels are applied only if you run `b9 label` with `gmail.modify` scope.
