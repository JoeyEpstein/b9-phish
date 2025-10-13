import json
import argparse
import yaml
from typing import List
from .vt import check_urls


def _load_thresholds(rules_yml: str):
    y = yaml.safe_load(open(rules_yml))
    thr = y.get("thresholds", {})
    return int(thr.get("high", 60)), int(thr.get("review", 35))


def _export_csv(alerts: List[dict], csv_path: str):
    import csv

    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "id",
                "date",
                "from",
                "subject",
                "severity",
                "score",
                "rule_hits",
                "domains",
                "urls",
            ]
        )
        for a in alerts:
            doms = ",".join(a.get("indicators", {}).get("domains", []))
            urls = ",".join(a.get("indicators", {}).get("urls", []))
            w.writerow(
                [
                    a["id"],
                    a["date"],
                    a["from"],
                    a["subject"],
                    a["severity"],
                    a["score"],
                    "|".join(a.get("rule_hits", [])),
                    doms,
                    urls,
                ]
            )


def main():
    ap = argparse.ArgumentParser(description="Apply VirusTotal scoring to alerts.json")
    ap.add_argument("--alerts", default="outputs/alerts.json")
    ap.add_argument("--rules", default="rules/default.yml")
    ap.add_argument(
        "--weight", type=int, default=45, help="Score added if any URL is flagged"
    )
    ap.add_argument("--csv-out", default="outputs/alerts.csv")
    args = ap.parse_args()

    alerts = json.load(open(args.alerts))
    # Gather all URLs from alerts
    all_urls = []
    for a in alerts:
        all_urls.extend(a.get("indicators", {}).get("urls", []))
    all_urls = list(dict.fromkeys(all_urls))  # dedupe

    vt = check_urls(all_urls)
    high_thr, rev_thr = _load_thresholds(args.rules)

    changed = 0
    for a in alerts:
        urls = a.get("indicators", {}).get("urls", [])
        flagged = False
        for u in urls:
            stats = vt.get(u) or {}
            if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                flagged = True
                break
        if flagged:
            if "VT_MALICIOUS_URL" not in a.get("rule_hits", []):
                a.setdefault("rule_hits", []).append("VT_MALICIOUS_URL")
            a["score"] = int(a.get("score", 0)) + args.weight
            # recompute severity
            score = a["score"]
            if score >= high_thr:
                a["severity"] = "High"
            elif score >= rev_thr:
                a["severity"] = "Review"
            else:
                a["severity"] = "Pass"
            changed += 1

    json.dump(alerts, open(args.alerts, "w"), indent=2)
    _export_csv(alerts, args.csv_out)
    print(
        f"VT applied to {changed} messages. Updated {args.alerts} and {args.csv_out}."
    )


if __name__ == "__main__":
    main()
