from typing import Dict, Any, List
import yaml

class RuleEngine:
    def __init__(self, weights: Dict[str,int], thresholds: Dict[str,int], allowlists: Dict[str, list]):
        self.weights = weights
        self.thresholds = thresholds
        self.allowlists = allowlists

    @classmethod
    def from_yaml(cls, path: str):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(weights=data["weights"], thresholds=data["thresholds"], allowlists=data.get("allowlists",{}))

    def score(self, features: Dict[str,Any]) -> Dict[str,Any]:
        score = 0
        hits: List[str] = []
        reasons: List[str] = []

        auth = features["auth"]
        addrs = features["addresses"]
        url_signals = features["url_signals"]
        flags = features["flags"]

        # R1 SPF fail
        if auth.get("spf") == "fail":
            score += self.weights["SPF_FAIL"]; hits.append("SPF_FAIL"); reasons.append("SPF authentication failed.")

        # R2 DKIM fail or missing & DMARC not enforced
        if (auth.get("dkim") in ("fail","none")) and (auth.get("dmarc") in ("none","neutral")):
            score += self.weights["DKIM_FAIL_OR_NODMARC"]; hits.append("DKIM_FAIL_OR_NODMARC"); reasons.append("DKIM failed or missing and DMARC not enforced.")

        # R3 From/Reply-To mismatch (not allowlisted)
        fd, rd = addrs["from"]["domain"], addrs["reply_to"]["domain"]
        if fd and rd and fd != rd and rd not in self.allowlists.get("domains", []):
            score += self.weights["FROM_REPLYTO_MISMATCH"]; hits.append("FROM_REPLYTO_MISMATCH"); reasons.append(f"From domain ({fd}) differs from Reply-To ({rd}).")

        # R4 URL text ≠ URL host – not available without HTML anchors; use deceptive keywords / misc
        if any(s["deceptive_keywords"] for s in url_signals):
            score += self.weights["LINK_MISMATCH"]; hits.append("LINK_MISMATCH"); reasons.append("Link host contains brand + action keywords (potential deception).")

        # R5 Punycode or suspicious TLD
        if any(s["punycode"] or s["suspicious_tld"] for s in url_signals):
            score += self.weights["IDN_OR_SUSPICIOUS_TLD"]; hits.append("IDN_OR_SUSPICIOUS_TLD"); reasons.append("Internationalized domain or suspicious TLD detected.")

        # R6 Display-name impersonation (heuristic)
        if features["url_signals"] and features.get("addresses"):
            if features.get("addresses",{}).get("from",{}).get("name") and features.get("addresses",{}).get("from",{}).get("domain"):
                # Simple heuristic: name mentions a brand while domain is unrelated
                name = features["addresses"]["from"]["name"].lower()
                dom = features["addresses"]["from"]["domain"].lower()
                if (("microsoft" in name or "google" in name or "amazon" in name) and (not any(b in dom for b in ("microsoft","google","amazon")))):
                    score += self.weights["DISPLAY_NAME_IMPERSONATION"]; hits.append("DISPLAY_NAME_IMPERSONATION"); reasons.append("Display name references a brand but domain is unrelated.")

        # R7 Dangerous attachment types – not available in headers-only path; reserved for EML/full body
        # (Handled when attachments array includes matching ext)
        for att in features.get("attachments",{}).get("dangerous_ext", []):
            score += self.weights["DANGEROUS_ATTACHMENT"]; hits.append("DANGEROUS_ATTACHMENT"); reasons.append(f"Dangerous attachment type: {att}"); break

        # R8 Urgency bait
        if flags.get("urgency_bait"):
            score += self.weights["URGENCY_BAIT"]; hits.append("URGENCY_BAIT"); reasons.append("Subject contains urgency or security-reset phrasing.")

        # R9 New domain – placeholder: requires local cache; skip in v0.1

        # R10 Return-Path mismatch
        if addrs["return_path"]["domain"] and addrs["from"]["domain"] and addrs["return_path"]["domain"] != addrs["from"]["domain"]:
            score += self.weights["RETURN_PATH_MISMATCH"]; hits.append("RETURN_PATH_MISMATCH"); reasons.append("Return-Path domain differs from From domain.")

        severity = "High" if score >= self.thresholds["high"] else ("Review" if score >= self.thresholds["review"] else "Pass")
        return {"score": score, "severity": severity, "rule_hits": hits, "reasons": reasons}

    def describe_rule(self, rid: str) -> str:
        d = {
            "SPF_FAIL": "SPF result is 'fail'.",
            "DKIM_FAIL_OR_NODMARC": "DKIM failed or missing AND DMARC is not enforced.",
            "FROM_REPLYTO_MISMATCH": "From domain differs from Reply-To domain (not on allowlist).",
            "LINK_MISMATCH": "Deceptive link: brand+action keywords in host or anchor/host mismatch.",
            "IDN_OR_SUSPICIOUS_TLD": "Punycode/IDN or TLD frequently abused by phishers.",
            "DISPLAY_NAME_IMPERSONATION": "Display name claims a brand while domain is unrelated.",
            "DANGEROUS_ATTACHMENT": "Attachment types commonly used for credential theft/malware.",
            "URGENCY_BAIT": "Subject contains urgency/verification/reset bait.",
            "NEW_DOMAIN_LOCAL": "Domain not seen locally in the last 90d (future: cache-based).",
            "RETURN_PATH_MISMATCH": "Return-Path domain does not match From domain."
        }
        w = self.weights.get(rid, 0)
        return f"{rid} (weight {w}): {d.get(rid,'No description available')}"
