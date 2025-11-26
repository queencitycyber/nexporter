"""
NEXPORTER - Export & Explore Nessus Professional Scan Data with VulnCheck KEV + Nuclei Intelligence

Features:
- Export scans from Nessus Professional
- Import CSV scan exports
- VulnCheck KEV integration for vulnerability intelligence
- Nuclei templates integration for scanner template coverage
- Initial access vulnerability classification
- Exploit database (XDB) linking
- Combined exploitability view (KEV OR nuclei template)
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path

import requests
import rich_click as click
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from sqlserve import Sqlserve

FORMAT = "%(message)s"
logging.basicConfig(
    level="INFO", format=FORMAT, datefmt="[%X]", handlers=[RichHandler(rich_tracebacks=True)]
)
log = logging.getLogger("nexporter")
console = Console()

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = True
click.rich_click.STYLE_ERRORS_SUGGESTION = "magenta italic"
click.rich_click.ERRORS_SUGGESTION = "Try running the '--help' flag for more information."


@click.group()
@click.option("--db", "-d", default="nexporter.db", show_default=True, help="Path to nexporter SQLite database.")
@click.option("--debug/--no-debug", default=False, help="Enable debug mode.")
@click.version_option(version="0.3.0", prog_name="nexporter")
@click.pass_context
def cli(ctx, db, debug):
    """
    NEXPORTER - Export & Explore Nessus Professional Scan Data with VulnCheck KEV + Nuclei Intelligence

    Commands:
      export    - Export scans from Nessus Professional
      import    - Import CSV files into the database
      kev       - VulnCheck KEV operations (sync, lookup, enrich)
      nuclei    - Nuclei templates operations (sync, lookup, enrich)
      serve     - Start Datasette web interface
      query     - Query enriched findings
    """
    ctx.ensure_object(dict)
    ctx.obj["db"] = db
    ctx.obj["debug"] = debug
    if debug:
        logging.getLogger("nexporter").setLevel(logging.DEBUG)


@cli.command()
@click.option("--target", "-t", required=True, default="https://127.0.0.1:8834", show_default=True, help="Nessus server URL.")
@click.option("--username", "-u", required=True, envvar="NESSUS_USER", help="Nessus username.")
@click.option("--password", "-p", prompt=True, hide_input=True, required=True, envvar="NESSUS_PASS", help="Nessus password.")
@click.option("--output", "-o", type=click.Path(resolve_path=True, file_okay=False), default="scans", show_default=True, help="Output directory.")
@click.pass_context
def export(ctx, target, username, password, output):
    """Export scans from Nessus Professional server."""

    def authenticate():
        login_url = f"{target}/session"
        resp = requests.post(login_url, data={"username": username, "password": password}, verify=False)
        token_data = resp.json()

        if resp.status_code == 200:
            token = {"X-Cookie": "token=" + token_data["token"]}
            console.print("[green]Authentication successful[/green]")
            return token
        else:
            console.print(f"[red]Authentication failed: {resp.status_code}[/red]")
            raise click.Abort()

    token = authenticate()

    if not os.path.exists(output):
        os.makedirs(output)

    def list_scans():
        target_url = f"{target}/scans"
        resp = requests.get(target_url, headers=token, verify=False)
        return resp.json().get("scans", [])

    def get_scan_details(scan):
        scan_id = scan["id"]
        target_url = f"{target}/scans/{scan_id}"
        try:
            resp = requests.get(target_url, headers=token, verify=False, timeout=10)
            return {
                "id": scan_id,
                "name": scan["name"],
                "status": resp.json()["info"]["status"],
            }
        except (requests.exceptions.Timeout, KeyError):
            return None

    def download_scan(scan):
        if scan is None or scan.get("status") != "completed":
            return

        scan_id = scan["id"]
        scan_name = scan["name"]
        target_url = f"{target}/scans/{scan_id}/export"

        export_resp = requests.post(target_url, headers=token, json={"format": "csv"}, verify=False).json()
        export_attempts = 0

        while export_attempts < 5:
            status_url = f"{target}/tokens/{export_resp['token']}/status"
            status_resp = requests.get(status_url, headers=token, verify=False)

            if status_resp.json()["status"] == "ready":
                download_url = f"{target}/tokens/{export_resp['token']}/download"
                export_file_name = f"{scan_name}_{datetime.now().strftime('%d%m%Y')}.csv".replace(" ", "_")
                export_file_path = os.path.join(output, export_file_name)

                downloaded = requests.get(download_url, headers=token, verify=False)
                with open(export_file_path, "wb") as f:
                    f.write(downloaded.content)
                console.print(f"[green]Downloaded: {export_file_name}[/green]")
                return
            export_attempts += 1

        console.print(f"[yellow]Failed to export: {scan_name}[/yellow]")

    console.print("Listing scans...")
    scans = list_scans()
    console.print(f"Found {len(scans)} scans")

    for scan in scans:
        details = get_scan_details(scan)
        if details:
            download_scan(details)


@cli.command("import")
@click.argument("files", nargs=-1, type=click.Path(exists=True, resolve_path=True))
@click.option("--directory", "-d", type=click.Path(exists=True, resolve_path=True, file_okay=False), help="Import all CSVs from directory.")
@click.pass_context
def import_csv(ctx, files, directory):
    """Import Nessus CSV exports into the database."""
    import subprocess

    db_path = ctx.obj["db"]
    file_list = list(files)

    if directory:
        csv_files = list(Path(directory).glob("*.csv"))
        file_list.extend([str(f) for f in csv_files])

    if not file_list:
        console.print("[yellow]No CSV files specified[/yellow]")
        return

    console.print(f"Importing {len(file_list)} file(s) into {db_path}...")

    command = ["sqlitebiter", "-o", db_path, "file"] + file_list
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode == 0:
        console.print(f"[green]Successfully imported {len(file_list)} file(s)[/green]")
    else:
        console.print(f"[red]Import failed: {result.stderr}[/red]")


@cli.group()
def kev():
    """VulnCheck KEV operations."""
    pass


@kev.command("sync")
@click.option("--force", "-f", is_flag=True, help="Force sync even if recently synced.")
@click.option("--api-key", envvar="VULNCHECK_API_KEY", help="VulnCheck API key.")
@click.pass_context
def kev_sync(ctx, force, api_key):
    """Sync VulnCheck KEV database locally."""
    from vulncheck import VulnCheckKEV

    db_path = ctx.obj["db"]

    try:
        vc = VulnCheckKEV(db_path, api_key=api_key)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        console.print("[yellow]Set VULNCHECK_API_KEY environment variable or use --api-key[/yellow]")
        raise click.Abort()

    console.print("Syncing VulnCheck KEV database...")
    result = vc.sync_kev(force=force)

    if result["status"] == "success":
        console.print(f"[green]Sync complete![/green]")
        console.print(f"  Inserted: {result['inserted']}")
        console.print(f"  Updated: {result['updated']}")
        console.print(f"  XDB Links: {result['xdb_links']}")
        console.print(f"  Exploitation Sources: {result['exploitation_sources']}")
    elif result["status"] == "skipped":
        console.print(f"[yellow]Sync skipped - last sync: {result['last_sync']}[/yellow]")
        console.print("Use --force to sync anyway")
    else:
        console.print(f"[red]Sync failed: {result.get('error')}[/red]")


@kev.command("status")
@click.pass_context
def kev_status(ctx):
    """Show KEV database status and statistics."""
    from vulncheck import VulnCheckKEV

    db_path = ctx.obj["db"]

    try:
        vc = VulnCheckKEV(db_path, api_key=os.environ.get("VULNCHECK_API_KEY", "placeholder"))
    except Exception:
        pass

    # Direct query even without API key
    import sqlite3

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check if KEV tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulncheck_kev'")
    if not cursor.fetchone():
        console.print("[yellow]KEV database not initialized. Run 'nexporter kev sync' first.[/yellow]")
        conn.close()
        return

    cursor.execute("SELECT COUNT(*) FROM vulncheck_kev")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM vulncheck_kev WHERE is_initial_access = 1")
    initial_access = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM vulncheck_kev WHERE known_ransomware_use IS NOT NULL AND known_ransomware_use <> ''")
    ransomware = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM vulncheck_kev WHERE cisa_date_added IS NOT NULL")
    in_cisa = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM vulncheck_xdb")
    xdb_count = cursor.fetchone()[0]

    cursor.execute("SELECT last_sync FROM vulncheck_sync_metadata WHERE sync_type = 'kev' ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    last_sync = row[0] if row else "Never"

    conn.close()

    table = Table(title="VulnCheck KEV Database Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total KEV Entries", str(total))
    table.add_row("Initial Access Vulnerabilities", str(initial_access))
    table.add_row("Ransomware Associated", str(ransomware))
    table.add_row("In CISA KEV", str(in_cisa))
    table.add_row("VulnCheck Only (not in CISA)", str(total - in_cisa))
    table.add_row("XDB Exploit Links", str(xdb_count))
    table.add_row("Last Sync", last_sync)

    console.print(table)


@kev.command("lookup")
@click.argument("cve")
@click.option("--api-key", envvar="VULNCHECK_API_KEY", help="VulnCheck API key.")
@click.pass_context
def kev_lookup(ctx, cve, api_key):
    """Look up a specific CVE in the KEV database."""
    from vulncheck import VulnCheckKEV

    db_path = ctx.obj["db"]

    try:
        vc = VulnCheckKEV(db_path, api_key=api_key or "placeholder")
    except ValueError:
        pass

    # Try direct lookup without API key validation
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM vulncheck_kev WHERE cve = ?", (cve,))
    row = cursor.fetchone()

    if not row:
        console.print(f"[yellow]{cve} not found in KEV database[/yellow]")
        conn.close()
        return

    result = dict(row)

    # Get XDB links
    cursor.execute("SELECT * FROM vulncheck_xdb WHERE cve = ?", (cve,))
    xdb_links = [dict(r) for r in cursor.fetchall()]

    conn.close()

    table = Table(title=f"KEV Entry: {cve}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("CVE", result["cve"])
    table.add_row("Vendor", result.get("vendor_project") or "N/A")
    table.add_row("Product", result.get("product") or "N/A")
    table.add_row("Vulnerability Name", result.get("vulnerability_name") or "N/A")
    table.add_row("Initial Access", "[green]YES[/green]" if result.get("is_initial_access") else "[dim]No[/dim]")
    table.add_row("Ransomware Use", result.get("known_ransomware_use") or "Unknown")
    table.add_row("Exploit Type", result.get("exploit_type") or "N/A")
    table.add_row("CISA Date Added", result.get("cisa_date_added") or "Not in CISA KEV")
    table.add_row("VulnCheck Date Added", result.get("vulncheck_date_added") or "N/A")

    console.print(table)

    if xdb_links:
        xdb_table = Table(title="Exploit Database (XDB) Links")
        xdb_table.add_column("Type", style="cyan")
        xdb_table.add_column("URL", style="blue")

        for xdb in xdb_links:
            xdb_table.add_row(xdb.get("exploit_type") or "Unknown", xdb.get("xdb_url") or "N/A")

        console.print(xdb_table)


@kev.command("enrich")
@click.option("--table", "-t", help="Specific table to enrich (default: all).")
@click.option("--api-key", envvar="VULNCHECK_API_KEY", help="VulnCheck API key.")
@click.pass_context
def kev_enrich(ctx, table, api_key):
    """Enrich Nessus findings with VulnCheck KEV intelligence."""
    from vulncheck import VulnCheckKEV

    db_path = ctx.obj["db"]

    try:
        vc = VulnCheckKEV(db_path, api_key=api_key or "placeholder")
    except ValueError:
        console.print("[yellow]Warning: No API key provided, using existing local KEV data[/yellow]")

    # Check if KEV data exists
    import sqlite3

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vulncheck_kev")
    count = cursor.fetchone()[0]
    conn.close()

    if count == 0:
        console.print("[red]KEV database is empty. Run 'nexporter kev sync' first.[/red]")
        raise click.Abort()

    console.print("Enriching Nessus findings with VulnCheck KEV data...")

    # Use vulncheck module
    vc = VulnCheckKEV.__new__(VulnCheckKEV)
    vc.db_path = db_path
    vc.api_key = "placeholder"

    result = vc.enrich_nessus_findings(table_name=table)

    console.print(f"[green]Enrichment complete![/green]")
    console.print(f"  Tables processed: {result['tables_processed']}")
    console.print(f"  Findings enriched: {result['findings_enriched']}")
    console.print(f"  KEV matches: {result['kev_matches']}")
    console.print(f"  Initial access matches: {result['initial_access_matches']}")


# =============================================================================
# Nuclei Templates Commands
# =============================================================================

@cli.group()
def nuclei():
    """Nuclei templates operations."""
    pass


@nuclei.command("sync")
@click.option("--templates-path", "-p", type=click.Path(exists=True, resolve_path=True, file_okay=False),
              help="Path to nuclei-templates directory (default: ~/nuclei-templates).")
@click.pass_context
def nuclei_sync(ctx, templates_path):
    """Sync nuclei templates CVE database from local directory."""
    from nuclei_templates import NucleiTemplates

    db_path = ctx.obj["db"]

    nt = NucleiTemplates(db_path, templates_path=templates_path)

    console.print(f"Syncing nuclei templates from {nt.templates_path}...")
    result = nt.sync_templates()

    if result["status"] == "success":
        console.print(f"[green]Sync complete![/green]")
        console.print(f"  Total CVE templates: {result['total_templates']}")
        console.print(f"  Inserted: {result['inserted']}")
        console.print(f"  Updated: {result['updated']}")
    else:
        console.print(f"[red]Sync failed: {result.get('error')}[/red]")
        if result.get("hint"):
            console.print(f"[yellow]{result['hint']}[/yellow]")


@nuclei.command("status")
@click.pass_context
def nuclei_status(ctx):
    """Show nuclei templates database status and statistics."""
    import sqlite3

    db_path = ctx.obj["db"]

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check if nuclei tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nuclei_cve_templates'")
    if not cursor.fetchone():
        console.print("[yellow]Nuclei templates database not initialized. Run 'nexporter nuclei sync' first.[/yellow]")
        conn.close()
        return

    cursor.execute("SELECT COUNT(*) FROM nuclei_cve_templates")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT severity, COUNT(*) FROM nuclei_cve_templates GROUP BY severity ORDER BY COUNT(*) DESC")
    by_severity = cursor.fetchall()

    cursor.execute(
        "SELECT last_sync, templates_path FROM nuclei_sync_metadata WHERE sync_type = 'templates' ORDER BY id DESC LIMIT 1"
    )
    row = cursor.fetchone()
    last_sync = row[0] if row else "Never"
    templates_path = row[1] if row else "N/A"

    conn.close()

    table = Table(title="Nuclei Templates Database Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total CVE Templates", str(total))
    table.add_row("Templates Path", templates_path)
    table.add_row("Last Sync", last_sync)

    console.print(table)

    if by_severity:
        sev_table = Table(title="Templates by Severity")
        sev_table.add_column("Severity", style="cyan")
        sev_table.add_column("Count", style="green")

        for sev, count in by_severity:
            sev_table.add_row(sev or "unknown", str(count))

        console.print(sev_table)


@nuclei.command("lookup")
@click.argument("cve")
@click.pass_context
def nuclei_lookup(ctx, cve):
    """Look up a specific CVE in the nuclei templates database."""
    import sqlite3

    db_path = ctx.obj["db"]

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM nuclei_cve_templates WHERE cve = ?", (cve,))
    row = cursor.fetchone()

    if not row:
        console.print(f"[yellow]{cve} not found in nuclei templates database[/yellow]")
        conn.close()
        return

    result = dict(row)
    conn.close()

    table = Table(title=f"Nuclei Template: {cve}")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("CVE", result["cve"])
    table.add_row("Template Name", result.get("template_name") or "N/A")
    table.add_row("Severity", result.get("severity") or "N/A")
    table.add_row("CVSS Score", result.get("cvss_score") or "N/A")
    table.add_row("File Path", result.get("file_path") or "N/A")
    table.add_row("Description", (result.get("description") or "N/A")[:200])

    console.print(table)


@nuclei.command("enrich")
@click.option("--table", "-t", help="Specific table to enrich (default: all).")
@click.option("--templates-path", "-p", type=click.Path(exists=True, resolve_path=True, file_okay=False),
              help="Path to nuclei-templates directory.")
@click.pass_context
def nuclei_enrich(ctx, table, templates_path):
    """Enrich Nessus findings with nuclei template availability."""
    from nuclei_templates import NucleiTemplates
    import sqlite3

    db_path = ctx.obj["db"]

    # Check if nuclei data exists
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nuclei_cve_templates'")
    if not cursor.fetchone():
        conn.close()
        console.print("[red]Nuclei templates database not initialized. Run 'nexporter nuclei sync' first.[/red]")
        raise click.Abort()

    cursor.execute("SELECT COUNT(*) FROM nuclei_cve_templates")
    count = cursor.fetchone()[0]
    conn.close()

    if count == 0:
        console.print("[red]Nuclei templates database is empty. Run 'nexporter nuclei sync' first.[/red]")
        raise click.Abort()

    console.print("Enriching Nessus findings with nuclei template data...")

    nt = NucleiTemplates(db_path, templates_path=templates_path)
    result = nt.enrich_nessus_findings(table_name=table)

    console.print(f"[green]Enrichment complete![/green]")
    console.print(f"  Tables processed: {result['tables_processed']}")
    console.print(f"  Findings enriched: {result['findings_enriched']}")
    console.print(f"  Nuclei template matches: {result['nuclei_matches']}")


@cli.command()
@click.option("--kev-only", "-k", is_flag=True, help="Only show findings in KEV.")
@click.option("--initial-access", "-i", is_flag=True, help="Only show initial access vulnerabilities.")
@click.option("--table", "-t", help="Query specific table.")
@click.option("--format", "-f", type=click.Choice(["table", "json", "csv"]), default="table", help="Output format.")
@click.pass_context
def query(ctx, kev_only, initial_access, table, format):
    """Query enriched Nessus findings."""
    import sqlite3

    db_path = ctx.obj["db"]

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get tables to query
    if table:
        tables = [table]
    else:
        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type='table'
            AND name NOT LIKE 'vulncheck_%'
            AND name NOT LIKE '_source_info_%'
            AND name NOT LIKE 'sqlite_%'
        """)
        tables = [row[0] for row in cursor.fetchall()]

    results = []
    for tbl in tables:
        # Check if table has been enriched
        cursor.execute(f"PRAGMA table_info([{tbl}])")
        columns = [row[1] for row in cursor.fetchall()]

        if "vulncheck_kev" not in columns:
            if not kev_only and not initial_access:
                # Return unenriched data
                cursor.execute(f"SELECT CVE, Name, Risk, Host, Port, Protocol FROM [{tbl}] WHERE CVE IS NOT NULL AND CVE <> '' ORDER BY CASE Risk WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END")
                for row in cursor.fetchall():
                    result = dict(row)
                    result["_table"] = tbl
                    result["vulncheck_kev"] = None
                    result["vulncheck_initial_access"] = None
                    results.append(result)
            continue

        where_clauses = ["CVE IS NOT NULL", "CVE <> ''"]
        if kev_only:
            where_clauses.append("vulncheck_kev = 1")
        if initial_access:
            where_clauses.append("vulncheck_initial_access = 1")

        where_sql = " AND ".join(where_clauses)

        cursor.execute(f"""
            SELECT CVE, Name, Risk, Host, Port, Protocol,
                   vulncheck_kev, vulncheck_initial_access,
                   vulncheck_xdb_urls, vulncheck_ransomware,
                   vulncheck_exploit_type
            FROM [{tbl}]
            WHERE {where_sql}
            ORDER BY
                vulncheck_initial_access DESC,
                vulncheck_kev DESC,
                CASE Risk
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END
        """)

        for row in cursor.fetchall():
            result = dict(row)
            result["_table"] = tbl
            results.append(result)

    conn.close()

    if not results:
        console.print("[yellow]No matching findings found[/yellow]")
        return

    if format == "json":
        console.print(json.dumps(results, indent=2))
    elif format == "csv":
        import csv
        import sys

        if results:
            writer = csv.DictWriter(sys.stdout, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    else:
        output = Table(title=f"Findings ({len(results)} results)")
        output.add_column("CVE", style="cyan")
        output.add_column("Name", style="white", max_width=40)
        output.add_column("Risk", style="yellow")
        output.add_column("Host", style="green")
        output.add_column("KEV", style="red")
        output.add_column("Initial Access", style="magenta")

        for r in results[:50]:  # Limit display
            kev_status = "[green]✓[/green]" if r.get("vulncheck_kev") == 1 else "[dim]-[/dim]"
            ia_status = "[red]★[/red]" if r.get("vulncheck_initial_access") == 1 else "[dim]-[/dim]"
            output.add_row(
                r.get("CVE") or "N/A",
                (r.get("Name") or "N/A")[:40],
                r.get("Risk") or "N/A",
                r.get("Host") or "N/A",
                kev_status,
                ia_status,
            )

        console.print(output)

        if len(results) > 50:
            console.print(f"[dim]Showing 50 of {len(results)} results. Use --format json for full output.[/dim]")


@cli.command()
@click.option("--port", "-p", default=8001, help="Port to serve on.")
@click.pass_context
def serve(ctx, port):
    """Start Datasette web interface for data exploration."""
    import subprocess

    db_path = ctx.obj["db"]
    script_dir = Path(__file__).parent
    metadata_path = script_dir / "metadata.yml"

    if not os.path.exists(db_path):
        console.print(f"[red]Database not found: {db_path}[/red]")
        console.print("Run 'nexporter import' first to create the database.")
        raise click.Abort()

    # Create the findings_with_exploits view if it doesn't exist
    _ensure_views(db_path)

    console.print(f"Starting Datasette server for {db_path}...")
    console.print(f"[green]Open http://localhost:{port} in your browser[/green]")
    console.print("[cyan]Tip: Start with the 'exploitable_vulnerabilities' view for enriched data[/cyan]")

    cmd = ["datasette", "serve", db_path, "-p", str(port)]
    if metadata_path.exists():
        cmd.extend(["-m", str(metadata_path)])

    subprocess.run(cmd)


def _ensure_views(db_path: str):
    """Create SQL views for better data exploration with KEV and nuclei enrichment."""
    import sqlite3

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get all Nessus tables (not vulncheck, nuclei, or system tables)
    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='table'
        AND name NOT LIKE 'vulncheck_%'
        AND name NOT LIKE 'nuclei_%'
        AND name NOT LIKE '_source_info_%'
        AND name NOT LIKE 'sqlite_%'
    """)
    nessus_tables = [row[0] for row in cursor.fetchall()]

    valid_tables = []

    for table in nessus_tables:
        # Check if table has CVE column
        cursor.execute(f"PRAGMA table_info([{table}])")
        columns = [row[1] for row in cursor.fetchall()]
        if "CVE" not in columns:
            continue

        # Check which enrichment columns exist
        has_kev = "vulncheck_kev" in columns
        has_nuclei = "nuclei_template" in columns

        # Need at least one enrichment to create view
        if not has_kev and not has_nuclei:
            continue

        valid_tables.append((table, has_kev, has_nuclei))
        view_name = f"v_{table}_exploits"

        # Drop and recreate view
        cursor.execute(f"DROP VIEW IF EXISTS [{view_name}]")

        # Build dynamic SELECT with available columns
        select_parts = [
            f"'{table}' as scan_source",
            "n.CVE",
            "n.Name",
            "n.Risk",
            "n.Host",
            "n.Port",
            "n.Protocol",
        ]

        # KEV columns
        if has_kev:
            select_parts.extend([
                "CASE WHEN n.vulncheck_kev = 1 THEN 'YES' ELSE '' END as in_KEV",
                "CASE WHEN n.vulncheck_initial_access = 1 THEN 'YES' ELSE '' END as initial_access",
                "n.vulncheck_ransomware as ransomware",
                "n.vulncheck_vendor as vendor",
                "n.vulncheck_product as product",
                "COUNT(x.xdb_url) as exploit_count",
                "GROUP_CONCAT(x.xdb_url, CHAR(10)) as exploit_urls",
            ])
        else:
            select_parts.extend([
                "'' as in_KEV",
                "'' as initial_access",
                "'' as ransomware",
                "'' as vendor",
                "'' as product",
                "0 as exploit_count",
                "'' as exploit_urls",
            ])

        # Nuclei columns
        if has_nuclei:
            select_parts.extend([
                "CASE WHEN n.nuclei_template = 1 THEN 'YES' ELSE '' END as has_nuclei_template",
                "n.nuclei_template_name",
                "n.nuclei_template_severity",
                "n.nuclei_template_path",
            ])
        else:
            select_parts.extend([
                "'' as has_nuclei_template",
                "'' as nuclei_template_name",
                "'' as nuclei_template_severity",
                "'' as nuclei_template_path",
            ])

        # Combined exploitability indicator
        if has_kev and has_nuclei:
            select_parts.append(
                "CASE WHEN n.vulncheck_kev = 1 OR n.nuclei_template = 1 THEN 'YES' ELSE '' END as exploitable"
            )
        elif has_kev:
            select_parts.append(
                "CASE WHEN n.vulncheck_kev = 1 THEN 'YES' ELSE '' END as exploitable"
            )
        elif has_nuclei:
            select_parts.append(
                "CASE WHEN n.nuclei_template = 1 THEN 'YES' ELSE '' END as exploitable"
            )

        select_sql = ",\n                ".join(select_parts)

        # Build ORDER BY with available columns
        order_parts = []
        if has_kev:
            order_parts.extend([
                "n.vulncheck_initial_access DESC",
                "n.vulncheck_kev DESC",
            ])
        if has_nuclei:
            order_parts.append("n.nuclei_template DESC")
        order_parts.append("""CASE n.Risk
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END""")
        order_sql = ",\n                ".join(order_parts)

        # Use LEFT JOIN for XDB only if KEV enrichment exists
        if has_kev:
            cursor.execute(f"""
                CREATE VIEW [{view_name}] AS
                SELECT
                    {select_sql}
                FROM [{table}] n
                LEFT JOIN vulncheck_xdb x ON n.CVE = x.cve
                WHERE n.CVE IS NOT NULL AND n.CVE <> ''
                GROUP BY n.rowid
                ORDER BY
                    {order_sql}
            """)
        else:
            cursor.execute(f"""
                CREATE VIEW [{view_name}] AS
                SELECT
                    {select_sql}
                FROM [{table}] n
                WHERE n.CVE IS NOT NULL AND n.CVE <> ''
                ORDER BY
                    {order_sql}
            """)

    # Clean up old views
    cursor.execute("DROP VIEW IF EXISTS [findings_with_exploits]")
    cursor.execute("DROP VIEW IF EXISTS [all_findings_with_exploits]")

    # Create global view combining all scans
    if valid_tables:
        cursor.execute("DROP VIEW IF EXISTS [exploitable_vulnerabilities]")

        # Check if any table has KEV or nuclei enrichment
        any_has_kev = any(t[1] for t in valid_tables)
        any_has_nuclei = any(t[2] for t in valid_tables)

        # Build UNION ALL query for all tables
        union_parts = []
        for table, has_kev, has_nuclei in valid_tables:
            select_parts = [
                f"'{table}' as scan_source",
                "n.CVE",
                "n.Name",
                "n.Risk",
                "n.Host",
                "n.Port",
                "n.Protocol",
            ]

            # KEV columns (use actual values if available, empty strings otherwise)
            if has_kev:
                select_parts.extend([
                    "CASE WHEN n.vulncheck_kev = 1 THEN 'YES' ELSE '' END as in_KEV",
                    "CASE WHEN n.vulncheck_initial_access = 1 THEN 'YES' ELSE '' END as initial_access",
                    "n.vulncheck_ransomware as ransomware",
                    "n.vulncheck_vendor as vendor",
                    "n.vulncheck_product as product",
                    "(SELECT COUNT(*) FROM vulncheck_xdb x WHERE x.cve = n.CVE) as exploit_count",
                    "(SELECT GROUP_CONCAT(x.xdb_url, CHAR(10)) FROM vulncheck_xdb x WHERE x.cve = n.CVE) as exploit_urls",
                ])
            else:
                select_parts.extend([
                    "'' as in_KEV",
                    "'' as initial_access",
                    "'' as ransomware",
                    "'' as vendor",
                    "'' as product",
                    "0 as exploit_count",
                    "'' as exploit_urls",
                ])

            # Nuclei columns
            if has_nuclei:
                select_parts.extend([
                    "CASE WHEN n.nuclei_template = 1 THEN 'YES' ELSE '' END as has_nuclei_template",
                    "n.nuclei_template_name",
                    "n.nuclei_template_severity",
                    "n.nuclei_template_path",
                ])
            else:
                select_parts.extend([
                    "'' as has_nuclei_template",
                    "'' as nuclei_template_name",
                    "'' as nuclei_template_severity",
                    "'' as nuclei_template_path",
                ])

            # Combined exploitability indicator
            if has_kev and has_nuclei:
                select_parts.append(
                    "CASE WHEN n.vulncheck_kev = 1 OR n.nuclei_template = 1 THEN 'YES' ELSE '' END as exploitable"
                )
            elif has_kev:
                select_parts.append(
                    "CASE WHEN n.vulncheck_kev = 1 THEN 'YES' ELSE '' END as exploitable"
                )
            elif has_nuclei:
                select_parts.append(
                    "CASE WHEN n.nuclei_template = 1 THEN 'YES' ELSE '' END as exploitable"
                )
            else:
                select_parts.append("'' as exploitable")

            select_sql = ",\n                    ".join(select_parts)

            union_parts.append(f"""
                SELECT
                    {select_sql}
                FROM [{table}] n
                WHERE n.CVE IS NOT NULL AND n.CVE <> ''
            """)

        union_query = " UNION ALL ".join(union_parts)

        # Build ORDER BY for global view
        order_parts = ["CASE WHEN initial_access = 'YES' THEN 0 ELSE 1 END"]
        order_parts.append("CASE WHEN exploitable = 'YES' THEN 0 ELSE 1 END")
        order_parts.append("CASE WHEN in_KEV = 'YES' THEN 0 ELSE 1 END")
        if any_has_nuclei:
            order_parts.append("CASE WHEN has_nuclei_template = 'YES' THEN 0 ELSE 1 END")
        order_parts.append("""CASE Risk
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END""")
        order_sql = ",\n                ".join(order_parts)

        cursor.execute(f"""
            CREATE VIEW [exploitable_vulnerabilities] AS
            SELECT * FROM ({union_query})
            ORDER BY
                {order_sql}
        """)

    conn.commit()
    conn.close()


@cli.command()
@click.pass_context
def init(ctx):
    """Initialize a new nexporter database with VulnCheck tables."""
    from vulncheck import VulnCheckKEV

    db_path = ctx.obj["db"]

    # Create empty database if needed
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.close()

    # Initialize VulnCheck tables
    try:
        vc = VulnCheckKEV(db_path, api_key="placeholder")
        console.print(f"[green]Initialized database: {db_path}[/green]")
        console.print("VulnCheck KEV tables created. Run 'nexporter kev sync' to populate KEV data.")
    except Exception as e:
        # Tables already created in __init__, so this should work
        console.print(f"[green]Database ready: {db_path}[/green]")


if __name__ == "__main__":
    try:
        cli()
    except Exception as e:
        console.print_exception(show_locals=True)
