import os
import time
import base64
import requests
from typing import Dict
from typing import List

API_KEY = os.getenv("VT_API_KEY", "")
ENABLED = os.getenv("B9_VT_ENABLED", "false").lower() == "true" and bool(API_KEY)


def _url_id(u: str) -> str:
    return base64.urlsafe_b64encode(u.encode()).decode().rstrip("=")


def check_urls(urls: List[str]) -> Dict[str, dict]:
    """Return {url: {harmless, malicious, suspicious, undetected}} for each URL.
    No-op (empty dict) if VT is disabled or no API key set."""
    if not ENABLED or not API_KEY:
        return {}
    headers = {"x-apikey": API_KEY}
    out: Dict[str, dict] = {}
    seen = set()
    for url in urls or []:
        if not url or url in seen:
            continue
        seen.add(url)
        try:
            uid = _url_id(url)
            r = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{uid}",
                headers=headers,
                timeout=12,
            )
            if r.status_code == 404:
                # submit for analysis and poll briefly
                sub = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=12,
                )
                sub.raise_for_status()
                analysis_id = sub.json()["data"]["id"]
                time.sleep(3)
                a = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                    timeout=12,
                ).json()
                stats = a["data"]["attributes"].get("stats", {})
            else:
                r.raise_for_status()
                data = r.json()
                stats = data["data"]["attributes"].get("last_analysis_stats", {})
            out[url] = {
                "harmless": int(stats.get("harmless", 0)),
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "undetected": int(stats.get("undetected", 0)),
            }
        except Exception as e:
            out[url] = {"error": str(e)}
    return out
