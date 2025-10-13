import os
from typing import Optional
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

SCOPES_MAP = {
    "readonly": ["https://www.googleapis.com/auth/gmail.readonly"],
    "modify": [
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.labels",
    ],
}


def build_gmail_service(creds_path: Optional[str] = None, scopes: str = "readonly"):
    """Build a Gmail API service using local token.json and credentials.json."""
    token_file = "token.json"
    if scopes not in SCOPES_MAP:
        raise ValueError("scopes must be 'readonly' or 'modify'")
    creds = None
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES_MAP[scopes])
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            creds_json = creds_path or "credentials.json"
            flow = InstalledAppFlow.from_client_secrets_file(
                creds_json, SCOPES_MAP[scopes]
            )
            creds = flow.run_local_server(port=0)
        with open(token_file, "w", encoding="utf-8") as token:
            token.write(creds.to_json())
    service = build("gmail", "v1", credentials=creds)
    return service


def _find_label_id(service, name: str):
    res = service.users().labels().list(userId="me").execute()
    for lab in res.get("labels", []):
        if lab["name"] == name:
            return lab["id"]
    return None


def ensure_labels(service, high_label: str, review_label: str):
    """Create labels if they do not exist."""
    for label in (high_label, review_label):
        if _find_label_id(service, label) is None:
            body = {
                "name": label,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            }
            service.users().labels().create(userId="me", body=body).execute()
