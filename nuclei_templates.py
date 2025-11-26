"""
Nuclei Templates Integration Module for Nexporter

Provides:
- Scan nuclei-templates directory for CVE coverage
- Enrich Nessus findings with nuclei template availability
- Track template metadata (severity, file path)
"""

import json
import logging
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger("nexporter.nuclei")

DEFAULT_TEMPLATES_PATH = Path.home() / "nuclei-templates"


class NucleiTemplates:
    """Nuclei templates integration for CVE coverage analysis."""

    def __init__(self, db_path: str, templates_path: Optional[str] = None):
        """
        Initialize Nuclei templates integration.

        Args:
            db_path: Path to the nexporter SQLite database
            templates_path: Path to nuclei-templates directory (default: ~/nuclei-templates)
        """
        self.db_path = db_path
        self.templates_path = Path(templates_path) if templates_path else DEFAULT_TEMPLATES_PATH
        self._init_nuclei_tables()

    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_nuclei_tables(self):
        """Initialize nuclei templates tables in the database."""
        conn = self._get_conn()
        cursor = conn.cursor()

        # Main nuclei CVE templates table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS nuclei_cve_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve TEXT UNIQUE NOT NULL,
                template_name TEXT,
                severity TEXT,
                description TEXT,
                cvss_score TEXT,
                file_path TEXT,
                last_updated TEXT
            )
        """)

        # Sync metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS nuclei_sync_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sync_type TEXT NOT NULL,
                last_sync TEXT NOT NULL,
                templates_path TEXT,
                record_count INTEGER,
                status TEXT
            )
        """)

        # Create index for fast CVE lookups
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_nuclei_cve ON nuclei_cve_templates(cve)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_nuclei_severity ON nuclei_cve_templates(severity)"
        )

        conn.commit()
        conn.close()
        log.info("Nuclei templates tables initialized")

    def sync_templates(self, force: bool = False) -> dict:
        """
        Sync nuclei templates CVE data from local directory.

        Args:
            force: Force sync even if recently synced

        Returns:
            dict with sync statistics
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        # Check if templates path exists
        if not self.templates_path.exists():
            conn.close()
            return {
                "status": "error",
                "error": f"Templates directory not found: {self.templates_path}",
                "hint": "Run 'nuclei -update-templates' or specify --templates-path"
            }

        # Check for cves.json (preferred) or scan yaml files
        cves_json_path = self.templates_path / "cves.json"

        log.info(f"Syncing nuclei templates from {self.templates_path}...")

        stats = {"inserted": 0, "updated": 0, "total_templates": 0}

        if cves_json_path.exists():
            # Fast path: use pre-built cves.json
            stats = self._sync_from_cves_json(cursor, cves_json_path)
        else:
            # Slow path: scan yaml files
            stats = self._sync_from_yaml_files(cursor)

        # Record sync metadata
        cursor.execute("""
            INSERT INTO nuclei_sync_metadata (sync_type, last_sync, templates_path, record_count, status)
            VALUES (?, ?, ?, ?, ?)
        """, ("templates", datetime.now().isoformat(), str(self.templates_path), stats["total_templates"], "success"))

        conn.commit()
        conn.close()

        log.info(f"Nuclei sync complete: {stats}")
        return {"status": "success", **stats}

    def _sync_from_cves_json(self, cursor, cves_json_path: Path) -> dict:
        """Sync from the pre-built cves.json file (fast)."""
        stats = {"inserted": 0, "updated": 0, "total_templates": 0}

        log.info("Using cves.json for fast sync...")

        with open(cves_json_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                cve = entry.get("ID", "")
                if not cve.startswith("CVE-"):
                    continue

                info = entry.get("Info", {})
                classification = info.get("Classification", {})

                cursor.execute("""
                    INSERT INTO nuclei_cve_templates (
                        cve, template_name, severity, description, cvss_score, file_path, last_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve) DO UPDATE SET
                        template_name = excluded.template_name,
                        severity = excluded.severity,
                        description = excluded.description,
                        cvss_score = excluded.cvss_score,
                        file_path = excluded.file_path,
                        last_updated = excluded.last_updated
                """, (
                    cve,
                    info.get("Name"),
                    info.get("Severity"),
                    info.get("Description", "")[:500],  # Truncate long descriptions
                    classification.get("CVSSScore"),
                    entry.get("file_path"),
                    datetime.now().isoformat()
                ))

                if cursor.rowcount > 0:
                    stats["inserted"] += 1
                else:
                    stats["updated"] += 1
                stats["total_templates"] += 1

        return stats

    def _sync_from_yaml_files(self, cursor) -> dict:
        """Sync by scanning yaml files (slow fallback)."""
        import re

        stats = {"inserted": 0, "updated": 0, "total_templates": 0}

        log.info("Scanning yaml files (this may take a while)...")

        # Find all yaml files in cves directories
        cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

        for yaml_file in self.templates_path.rglob("*.yaml"):
            # Quick check: is this a CVE template?
            relative_path = yaml_file.relative_to(self.templates_path)
            path_str = str(relative_path)

            # Look for CVE in path or filename
            cve_match = cve_pattern.search(path_str)
            if not cve_match:
                continue

            cve = cve_match.group().upper()

            # Try to extract basic info from file
            try:
                with open(yaml_file, "r", errors="ignore") as f:
                    content = f.read(2000)  # Read first 2KB only

                # Extract name and severity with simple regex
                name_match = re.search(r'name:\s*["\']?([^"\'\n]+)', content)
                severity_match = re.search(r'severity:\s*(\w+)', content)

                template_name = name_match.group(1).strip() if name_match else None
                severity = severity_match.group(1).lower() if severity_match else None

                cursor.execute("""
                    INSERT INTO nuclei_cve_templates (
                        cve, template_name, severity, file_path, last_updated
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(cve) DO UPDATE SET
                        template_name = COALESCE(excluded.template_name, nuclei_cve_templates.template_name),
                        severity = COALESCE(excluded.severity, nuclei_cve_templates.severity),
                        file_path = excluded.file_path,
                        last_updated = excluded.last_updated
                """, (
                    cve,
                    template_name,
                    severity,
                    str(relative_path),
                    datetime.now().isoformat()
                ))

                stats["total_templates"] += 1
                if cursor.rowcount > 0:
                    stats["inserted"] += 1

            except Exception as e:
                log.debug(f"Error processing {yaml_file}: {e}")
                continue

        return stats

    def lookup_cve(self, cve: str) -> Optional[dict]:
        """
        Look up a CVE in the nuclei templates database.

        Args:
            cve: CVE identifier (e.g., CVE-2022-22965)

        Returns:
            dict with template data if found, None otherwise
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM nuclei_cve_templates WHERE cve = ?", (cve,))
        row = cursor.fetchone()

        conn.close()
        return dict(row) if row else None

    def enrich_nessus_findings(self, table_name: Optional[str] = None) -> dict:
        """
        Enrich Nessus findings with nuclei template availability.

        Adds columns to Nessus tables:
        - nuclei_template: 1 if nuclei template exists, 0 otherwise
        - nuclei_template_path: Path to the template file
        - nuclei_template_severity: Severity from nuclei template

        Args:
            table_name: Specific table to enrich, or None for all Nessus tables

        Returns:
            dict with enrichment statistics
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        # Get list of Nessus tables
        if table_name:
            tables = [table_name]
        else:
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table'
                AND name NOT LIKE 'vulncheck_%'
                AND name NOT LIKE 'nuclei_%'
                AND name NOT LIKE '_source_info_%'
                AND name NOT LIKE 'sqlite_%'
            """)
            tables = [row[0] for row in cursor.fetchall()]

        stats = {"tables_processed": 0, "findings_enriched": 0, "nuclei_matches": 0}

        for tbl in tables:
            log.info(f"Enriching table with nuclei data: {tbl}")

            # Check if CVE column exists
            cursor.execute(f"PRAGMA table_info([{tbl}])")
            columns = {row[1]: row[2] for row in cursor.fetchall()}

            if "CVE" not in columns:
                log.warning(f"Table {tbl} has no CVE column, skipping")
                continue

            # Add enrichment columns if they don't exist
            enrichment_columns = [
                ("nuclei_template", "INTEGER DEFAULT 0"),
                ("nuclei_template_path", "TEXT"),
                ("nuclei_template_severity", "TEXT"),
                ("nuclei_template_name", "TEXT"),
            ]

            for col_name, col_type in enrichment_columns:
                if col_name not in columns:
                    cursor.execute(f"ALTER TABLE [{tbl}] ADD COLUMN {col_name} {col_type}")
                    log.info(f"Added column {col_name} to {tbl}")

            # Get all unique CVEs from the table
            cursor.execute(f"SELECT DISTINCT CVE FROM [{tbl}] WHERE CVE IS NOT NULL AND CVE <> ''")
            cves = [row[0] for row in cursor.fetchall()]

            for cve in cves:
                # Handle multiple CVEs in a single field (comma-separated)
                cve_list = [c.strip() for c in cve.split(",") if c.strip()]

                nuclei_match = False
                template_path = None
                template_severity = None
                template_name = None

                for single_cve in cve_list:
                    template_data = self.lookup_cve(single_cve)
                    if template_data:
                        nuclei_match = True
                        template_path = template_data.get("file_path")
                        template_severity = template_data.get("severity")
                        template_name = template_data.get("template_name")
                        break  # Use first match

                # Update the findings
                cursor.execute(f"""
                    UPDATE [{tbl}] SET
                        nuclei_template = ?,
                        nuclei_template_path = ?,
                        nuclei_template_severity = ?,
                        nuclei_template_name = ?
                    WHERE CVE = ?
                """, (
                    1 if nuclei_match else 0,
                    template_path,
                    template_severity,
                    template_name,
                    cve
                ))

                stats["findings_enriched"] += cursor.rowcount
                if nuclei_match:
                    stats["nuclei_matches"] += 1

            stats["tables_processed"] += 1

        conn.commit()
        conn.close()

        log.info(f"Nuclei enrichment complete: {stats}")
        return stats

    def get_templates_summary(self) -> dict:
        """Get summary statistics of the local nuclei templates database."""
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM nuclei_cve_templates")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT severity, COUNT(*) FROM nuclei_cve_templates GROUP BY severity")
        by_severity = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute(
            "SELECT last_sync, templates_path FROM nuclei_sync_metadata WHERE sync_type = 'templates' ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        last_sync = row["last_sync"] if row else None
        templates_path = row["templates_path"] if row else None

        conn.close()

        return {
            "total_cve_templates": total,
            "by_severity": by_severity,
            "templates_path": templates_path,
            "last_sync": last_sync,
        }
