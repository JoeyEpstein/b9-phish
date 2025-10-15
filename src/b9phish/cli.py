import json
import os
import typer
from rich import print, box
from rich.table import Table
from typing import Optional
from . import __version__
from .gmail_auth import build_gmail_service
from .labeler import ensure_labels, apply_labels_for_results
from .fetch import list_messages, get_message_metadata, scan_eml_dir
from .features import extract_features_from_gmail, extract_features_from_eml
from .rules import RuleEngine
from .outputs import OutputManager, build_html_report

app = typer.Typer(add_completion=False, help="B9-Phish CLI")


@app.command()
def version():
    """Show version."""
    print(f"[bold]b9-phish[/] v{__version__}")


@app.command()
def init(
    creds: str = typer.Option(
        ..., "--creds", help="Path to Google OAuth credentials.json"
    ),
    scopes: str = typer.Option("readonly", "--scopes", help="readonly|modify"),
    create_labels: bool = typer.Option(
        False, "--create-labels", help="Create default labels"
    ),
):
    """Run OAuth flow and optionally create labels."""
    svc = build_gmail_service(creds_path=creds, scopes=scopes)
    print("[green]OAuth complete.[/] Token stored as token.json.")
    if create_labels:
        ensure_labels(svc, high_label="B9-Phish/High", review_label="B9-Phish/Review")
        print("[green]Labels ensured.[/]")


@app.command()
def rules(
    list: bool = typer.Option(False, "--list"),
    explain: Optional[str] = typer.Option(
        None, "--explain", help="Rule ID to describe"
    ),
):
    """List rules or show an explanation for one."""
    engine = RuleEngine.from_yaml("rules/default.yml")
    if list:
        table = Table(title="Rules", box=box.SIMPLE_HEAVY)
        table.add_column("Rule")
        table.add_column("Weight", justify="right")
        for rid, w in engine.weights.items():
            table.add_row(rid, str(w))
        print(table)
        return
    if explain:
        print(engine.describe_rule(explain))
        return
    print("Use --list or --explain <RULE_ID>")


@app.command()
def scan(
    since: Optional[str] = typer.Option(None, "--since", help="e.g. 7d or 30d"),
    query: Optional[str] = typer.Option(
        None, "--query", help='Gmail search query, e.g. "from:paypal.com"'
    ),
    max: int = typer.Option(100, "--max", help="Max Gmail messages"),
    full_body: Optional[bool] = typer.Option(
        None, "--full-body", help="on/off; default off"
    ),
    out: str = typer.Option("./outputs", "--out"),
    eml_dir: Optional[str] = typer.Option(
        None, "--eml-dir", help="Scan a folder of .eml files instead of Gmail"
    ),
):
    """Fetch messages → features → rules → outputs."""
    os.makedirs(out, exist_ok=True)
    engine = RuleEngine.from_yaml("rules/default.yml")
    outputs = OutputManager(out)

    results = []

    headers_only = os.getenv("B9_HEADERS_ONLY", "true").lower() in ("1", "true", "yes")

    if eml_dir:
        for rec in scan_eml_dir(eml_dir, include_body=(full_body or False)):
            features = extract_features_from_eml(rec, headers_only=headers_only)
            verdict = engine.score(features)
            result = outputs.record_result(rec["id"], rec["summary"], verdict, features)
            results.append(result)
    else:
        # Gmail path
        try:
            svc = build_gmail_service()
        except Exception as e:
            print(f"[red]Gmail not initialized:[/] {e}")
            raise typer.Exit(code=2)
        ids = list_messages(svc, query=query, since=since, max_results=max)
        for mid in ids:
            meta = get_message_metadata(svc, mid, full_body=(full_body or False))
            features = extract_features_from_gmail(meta, headers_only=headers_only)
            verdict = engine.score(features)
            result = outputs.record_result(
                meta["id"], meta["summary"], verdict, features
            )
            results.append(result)

    outputs.finalize()
    print(f"[green]Scan complete.[/] Wrote [bold]{len(results)}[/] results into: {out}")


@app.command()
def report(out: str = typer.Option("./outputs/report.html", "--out")):
    """Build an HTML report from the latest alerts.json/csv."""
    build_html_report(out)
    print(f"[green]Report written:[/] {out}")


@app.command()
def label(
    high: str = typer.Option("B9-Phish/High", "--high"),
    review: str = typer.Option("B9-Phish/Review", "--review"),
    from_file: str = typer.Option("./outputs/alerts.json", "--from-file"),
):
    """Apply labels to messages flagged in the last scan (requires gmail.modify)."""
    try:
        svc = build_gmail_service(scopes="modify")
    except Exception as e:
        print(f"[red]Gmail not initialized with modify scope:[/] {e}")
        raise typer.Exit(code=2)
    with open(from_file, "r", encoding="utf-8") as f:
        alerts = json.load(f)
    apply_labels_for_results(svc, alerts, high_label=high, review_label=review)
    print("[green]Labeling complete.[/]")


def main():
    app()


if __name__ == "__main__":
    main()
