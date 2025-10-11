import re
from typing import Dict, Any, List
from urllib.parse import urlparse

from .parse import parse_authentication_results, extract_addresses
from .utils import extract_domains, has_punycode, suspicious_tld, split_host

DANGEROUS_EXT = {
    ".html", ".htm", ".shtml", ".lnk", ".iso", ".img", ".docm", ".xlsm", ".pptm",
    ".js", ".vbs", ".cmd", ".bat", ".scr", ".ps1", ".wsf", ".jar", ".rar", ".7z", ".zip"
}

SHORTENER_HOSTS = {
    "bit.ly", "t.co", "lnkd.in", "lnk.bio", "tinyurl.com", "goo.gl",
    "rebrand.ly", "bl.ink", "buff.ly", "shorturl.at", "s.id"
}


def extract_features_from_gmail(meta: Dict[str, Any], headers_only: bool = True) -> Dict[str, Any]:
    headers = meta["headers"]
    snippet = meta.get("snippet", "")
    text = meta.get("text", "") if not headers_only else ""
    return _extract_common(headers, content=(text or snippet))


def extract_features_from_eml(rec: Dict[str, Any], headers_only: bool = True) -> Dict[str, Any]:
    headers = rec["headers"]
    text = "" if headers_only else rec.get("text", "")
    snippet = rec.get("snippet", "")
    return _extract_common(headers, content=(text or snippet))


def _extract_common(headers: Dict[str, str], content: str) -> Dict[str, Any]:
    auth = parse_authentication_results(headers.get("Authentication-Results", ""))
    addrs = extract_addresses(headers)
    urls = extract_urls(content or "")
    url_signals = [url_heuristics(u) for u in urls]
    sender_sig = sender_anomaly(headers, addrs)

    subject = headers.get("Subject", "")
    urgency = bool(re.search(r"\b(urgent|verify immediately|password|suspend|expired|reset|action required)\b", subject, re.I))
    unicode_abuse = bool(re.search(r"[\u202E\u200B\u200C\u200D]", subject))  # RLO / ZW* chars

    seen_domains = list(set(extract_domains(content)))

    attach_sig = {"dangerous_ext": []}  # placeholder; filled when parsing attachments

    return {
        "auth": auth,
        "addresses": addrs,
        "urls": [{"raw": u} for u in urls],
        "url_signals": url_signals,
        "sender_signals": sender_sig,
        "attachments": attach_sig,
        "flags": {
            "urgency_bait": urgency,
            "unicode_abuse": unicode_abuse,
        },
        "indicators": {
            "domains": list(set([addrs["from"]["domain"], addrs["reply_to"]["domain"], addrs["return_path"]["domain"]] + seen_domains))
        },
    }


def extract_urls(text: str) -> List[str]:
    patt = re.compile(r'https?://[^\s)>\"]+', re.I)
    return patt.findall(text)


def url_heuristics(url: str) -> Dict[str, Any]:
    host = split_host(url)
    u = urlparse(url)
    port = (u.netloc.split(":", 1)[1] if ":" in u.netloc else "")
    non_std_port = bool(port and port not in ("80", "443"))
    return {
        "url": url,
        "punycode": has_punycode(host),
        "suspicious_tld": suspicious_tld(host),
        "ip_literal": bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)),
        "long_subdomain": host.count(".") >= 3,
        "deceptive_keywords": bool(re.search(r"(microsoft|google|amazon|okta|docusign)[^/]{0,20}(support|secure|verify|login|authorize)", host, re.I)),
        "shortener": (host in SHORTENER_HOSTS),
        "odd_protocol": (u.scheme in ("data", "file", "javascript")),
        "non_std_port": non_std_port,
    }


def sender_anomaly(headers: Dict[str, str], addrs: Dict[str, Any]) -> Dict[str, Any]:
    from_name = addrs["from"]["name"]
    from_domain = addrs["from"]["domain"]
    reply_domain = addrs["reply_to"]["domain"]
    return_path_domain = addrs["return_path"]["domain"]
    msgid = headers.get("Message-ID", "")
    msgid_domain = msgid.split("@")[-1].strip(">") if "@" in msgid else ""

    display_impersonation = bool(from_name and from_domain and (from_name.lower() not in from_domain.lower()))

    return {
        "from_reply_mismatch": (from_domain and reply_domain and from_domain != reply_domain),
        "returnpath_mismatch": (from_domain and return_path_domain and from_domain != return_path_domain),
        "messageid_mismatch": (from_domain and msgid_domain and (from_domain not in msgid_domain)),
        "display_name_impersonation": display_impersonation,
    }
