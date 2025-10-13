import re
import tldextract
from urllib.parse import urlparse

SUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "gq",
    "work",
    "country",
    "link",
    "click",
    "support",
    "online",
    "shop",
}


def domain_from_email(addr: str) -> str:
    return addr.split("@")[-1].lower() if "@" in addr else ""


def extract_domains(text: str):
    patt = re.compile(r"https?://([^/\s]+)", re.I)
    return [m.lower() for m in patt.findall(text)]


def has_punycode(host: str) -> bool:
    return "xn--" in host


def suspicious_tld(host: str) -> bool:
    ext = tldextract.extract(host)
    return ext.suffix.split(".")[-1] in SUS_TLDS if ext.suffix else False


def split_host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""
