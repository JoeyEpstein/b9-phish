import re
from email.utils import parseaddr
from typing import Dict


def headers_to_dict(headers_list):
    """Gmail returns list of {'name':..., 'value':...} maps; normalize to dict."""
    if isinstance(headers_list, dict):
        return headers_list
    out = {}
    for h in headers_list:
        out[h.get("name", "")] = h.get("value", "")
    return out


def parse_authentication_results(value: str) -> Dict[str, str]:
    """Parse a rough subset of Authentication-Results header results for SPF/DKIM/DMARC."""
    if not value:
        return {"spf": "none", "dkim": "none", "dmarc": "none"}
    v = value.lower()

    def pick(token):
        m = re.search(rf"{token}=(pass|fail|softfail|neutral|none|policy)", v)
        return m.group(1) if m else "none"

    return {"spf": pick("spf"), "dkim": pick("dkim"), "dmarc": pick("dmarc")}


def extract_addresses(headers: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    def addr(k):
        name, email_addr = parseaddr(headers.get(k, ""))
        return {
            "name": name,
            "email": email_addr,
            "domain": email_addr.split("@")[-1].lower() if "@" in email_addr else "",
        }

    return {
        "from": addr("From"),
        "reply_to": addr("Reply-To"),
        "return_path": {
            "name": "",
            "email": headers.get("Return-Path", "").strip("<>"),
            "domain": (
                headers.get("Return-Path", "").strip("<>").split("@")[-1].lower()
                if "@" in headers.get("Return-Path", "")
                else ""
            ),
        },
        "sender": addr("Sender"),
        "message_id": headers.get("Message-ID", ""),
    }


def extract_text_from_payload(payload) -> str:
    """Walk a Gmail or email.message payload and collect visible text."""
    import email
    from bs4 import BeautifulSoup

    if hasattr(payload, "is_multipart"):
        pass
    else:
        email.message_from_string("")
    parts = []

    def walk(p):
        if hasattr(p, "is_multipart") and p.is_multipart():
            for part in p.get_payload():
                walk(part)
        else:
            ctype = p.get_content_type() if hasattr(p, "get_content_type") else ""
            payload = p.get_payload(decode=True) if hasattr(p, "get_payload") else None
            if not payload:
                return
            try:
                text = payload.decode(
                    p.get_content_charset() or "utf-8", errors="ignore"
                )
            except Exception:
                text = payload.decode("utf-8", errors="ignore")
            if ctype == "text/plain":
                parts.append(text)
            elif ctype == "text/html":
                soup = BeautifulSoup(text, "lxml")
                parts.append(soup.get_text(" ", strip=True))

    walk(payload)
    return "\n".join(parts)[:20000]  # cap
