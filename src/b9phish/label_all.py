import json
from typing import Dict
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


def main(
    pass_label: str = typer.Option("All Clear", "--pass-label"),
    review_label: str = typer.Option("Proceed with Caution", "--review-label"),
    high_label: str = typer.Option("Danger! Danger!", "--high-label"),
    alerts_path: str = typer.Option("outputs/alerts.json", "--alerts"),
    creds: str = typer.Option("./credentials.json", "--creds"),
):
    """
    Apply a label to EVERY message in alerts.json based on severity.
    Creates labels if missing. Requires --scopes modify during init.
    """
    svc = build_gmail_service(creds_path=creds, scopes="modify")
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
            svc.users().messages().modify(
                userId="me", id=msg_id, body={"addLabelIds": [lab_id]}
            ).execute()
            n += 1
        except HttpError as e:
            print(f"warn: label failed for {msg_id}: {e}")
    print(f"Applied labels to {n} messages.")


if __name__ == "__main__":
    typer.run(main)
