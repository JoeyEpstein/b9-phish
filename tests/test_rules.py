from b9phish.rules import RuleEngine


def test_rules_scoring():
    engine = RuleEngine.from_yaml("rules/default.yml")
    features = {
        "auth": {"spf": "fail", "dkim": "none", "dmarc": "none"},
        "addresses": {
            "from": {"domain": "micr0soft.com", "name": "Microsoft Account"},
            "reply_to": {"domain": "micr0soft.com"},
            "return_path": {"domain": "evil.biz"},
        },
        "url_signals": [
            {"deceptive_keywords": True, "punycode": False, "suspicious_tld": True}
        ],
        "flags": {"urgency_bait": True},
        "attachments": {"dangerous_ext": []},
        "indicators": {"domains": ["micr0soft.com"]},
        "urls": [{"raw": "https://security-micr0soft-login.com/login"}],
    }
    verdict = engine.score(features)
    assert verdict["severity"] in ("Review", "High")
    assert verdict["score"] >= engine.thresholds["review"]
