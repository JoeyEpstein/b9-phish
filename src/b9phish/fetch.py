import os
import email
from typing import List, Dict, Optional
from .parse import headers_to_dict, extract_text_from_payload


def list_messages(
    service,
    query: Optional[str] = None,
    since: Optional[str] = None,
    max_results: int = 100,
    include_spam_trash: bool = False,
) -> List[str]:
    """Return list of message IDs using Gmail search."""
    if max_results <= 0:
        return []

    q = query or ""
    if since and since.endswith("d") and since[:-1].isdigit():
        q = (q + f" newer_than:{since}").strip()

    def _list_request(page_token: Optional[str] = None, page_size: Optional[int] = None):
        kwargs = {
            "userId": "me",
            "q": q or None,
            "maxResults": min(page_size or max_results, 500),
        }
        if page_token:
            kwargs["pageToken"] = page_token
        if include_spam_trash:
            kwargs["includeSpamTrash"] = True
        return service.users().messages().list(**kwargs)

    ids: List[str] = []
    request = _list_request()

    while request is not None and len(ids) < max_results:
        res = request.execute()
        for msg in res.get("messages", []):
            ids.append(msg["id"])
            if len(ids) >= max_results:
                break

        next_token = res.get("nextPageToken")
        if not next_token or len(ids) >= max_results:
            break

        remaining = max_results - len(ids)
        request = _list_request(page_token=next_token, page_size=remaining)

    return ids


def get_message_metadata(service, msg_id: str, full_body: bool = False) -> Dict:
    """Fetch a Gmail message with metadata (headers) and snippet; optionally include body text."""
    fmt = "full" if full_body else "metadata"
    metadata_headers = [
        "From",
        "Reply-To",
        "Return-Path",
        "Sender",
        "Subject",
        "Date",
        "Message-ID",
        "Authentication-Results",
        "In-Reply-To",
        "References",
    ]
    res = (
        service.users()
        .messages()
        .get(userId="me", id=msg_id, format=fmt, metadataHeaders=metadata_headers)
        .execute()
    )
    headers = headers_to_dict(res.get("payload", {}).get("headers", []))
    snippet = res.get("snippet", "")
    text = ""
    if full_body and res.get("payload"):
        text = extract_text_from_payload(res["payload"])
    return {
        "id": res["id"],
        "threadId": res.get("threadId"),
        "headers": headers,
        "snippet": snippet,
        "text": text,
        "summary": {
            "date": headers.get("Date", ""),
            "from": headers.get("From", ""),
            "subject": headers.get("Subject", ""),
        },
    }


def scan_eml_dir(eml_dir: str, include_body: bool = False):
    """Yield dicts like get_message_metadata but from .eml files in a directory."""
    for name in sorted(os.listdir(eml_dir)):
        if not name.lower().endswith(".eml"):
            continue
        path = os.path.join(eml_dir, name)
        with open(path, "rb") as f:
            msg = email.message_from_bytes(f.read())
        headers = {k: v for (k, v) in msg.items()}
        snippet = msg.get("Subject", "")
        text = ""
        if include_body:
            # Best-effort extract
            text = extract_text_from_payload(msg)
        yield {
            "id": os.path.splitext(name)[0],
            "headers": headers,
            "snippet": snippet,
            "text": text,
            "summary": {
                "date": headers.get("Date", ""),
                "from": headers.get("From", ""),
                "subject": headers.get("Subject", ""),
            },
        }
