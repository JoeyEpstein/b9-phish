import json
from typing import Dict, List
import typer
from googleapiclient.errors import HttpError
from .gmail_auth import build_gmail_service


def _get_or_create_label(svc, name: str) -> str:
    labels = svc.users().labels().list(userId="me").execute().get("labels", [])
    for L in labels:
        if L.get("name") == name:
            return L["id"]
    body = {
        "name": name,
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show",
    }
    return svc.users().labels().create(userId="me", body=body).execute()["id"]


def _get_all_b9_label_ids(svc) -> List[str]:
    """Get all label IDs that are B9-Phish related."""
    labels = svc.users().labels().list(userId="me").execute().get("labels", [])
    b9_ids = []
    for L in labels:
        name = L.get("name", "")
        # Match any label with B9-Phish, Danger, Proceed, All Clear, etc.
        if any(
            keyword in name
            for keyword in [
                "B9-Phish",
                "Danger",
                "Proceed with Caution",
                "All Clear",
                "High",
                "Review",
            ]
        ):
            b9_ids.append(L["id"])
    return b9_ids


def main(
    pass_label: str = typer.Option("All Clear", "--pass-label"),
    review_label: str = typer.Option("Proceed with Caution", "--review-label"),
    high_label: str = typer.Option("Danger! Danger!", "--high-label"),
    alerts_path: str = typer.Option("outputs/alerts.json", "--alerts"),
    creds: str = typer.Option("./credentials.json", "--creds"),
):
    """
    Apply a label to EVERY message in alerts.json based on severity.
    Removes ALL old B9-Phish labels first, then applies ONE new label.
    Creates labels if missing. Requires --scopes modify during init.
    """
    svc = build_gmail_service(creds_path=creds, scopes="modify")

    # Get all B9-Phish related label IDs to remove
    all_b9_labels = _get_all_b9_label_ids(svc)

    # Get/create the three labels we want
    ids: Dict[str, str] = {
        "Pass": _get_or_create_label(svc, pass_label),
        "Review": _get_or_create_label(svc, review_label),
        "High": _get_or_create_label(svc, high_label),
    }

    alerts = json.load(open(alerts_path))
    n = 0
    for a in alerts:
        msg_id = a.get("id")
        sev = a.get("severity")
        lab_id = ids.get(sev)
        if not msg_id or not lab_id:
            continue
        try:
            # Remove all B9-Phish labels EXCEPT the one we're adding
            labels_to_remove = [lid for lid in all_b9_labels if lid != lab_id]

            # Build request body
            body = {}
            if labels_to_remove:
                body["removeLabelIds"] = labels_to_remove
            body["addLabelIds"] = [lab_id]

            svc.users().messages().modify(userId="me", id=msg_id, body=body).execute()
            n += 1
        except HttpError as e:
            print(f"warn: label failed for {msg_id}: {e}")

    print(f"Applied labels to {n} messages (removed old labels first).")


if __name__ == "__main__":
    typer.run(main)
