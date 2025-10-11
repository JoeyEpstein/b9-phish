from typing import List, Dict, Any
from .gmail_auth import _find_label_id, ensure_labels

def apply_labels_for_results(service, alerts: List[Dict[str,Any]], high_label: str, review_label: str):
    lid_high = _find_label_id(service, high_label)
    lid_review = _find_label_id(service, review_label)
    if lid_high is None or lid_review is None:
        ensure_labels(service, high_label, review_label)
        lid_high = _find_label_id(service, high_label)
        lid_review = _find_label_id(service, review_label)
    for a in alerts:
        mid = a["id"]
        if a.get("severity") == "High":
            body = {"addLabelIds": [lid_high]}
            service.users().messages().modify(userId="me", id=mid, body=body).execute()
        elif a.get("severity") == "Review":
            body = {"addLabelIds": [lid_review]}
            service.users().messages().modify(userId="me", id=mid, body=body).execute()
