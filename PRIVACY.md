# PRIVACY

B9-Phish is privacy-first by design.

- **Default mode** processes only Gmail **headers** and the safe **snippet** locally.
- **No raw bodies** are sent to any external service.
- The LLM explainer (if enabled) receives **features only** (auth results, domains, rule hits), not full text.
- No telemetry leaves your machine.
- Outputs are written under `./outputs` by default; you can change or disable this with CLI flags.
- OAuth `token.json` is stored locally; revoke access any time via your Google Account.
