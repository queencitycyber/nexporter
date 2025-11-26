"""
VulnCheck KEV Integration Module for Nexporter

Provides:
- KEV database download and sync
- CVE-to-KEV lookup
- Initial access classification
- Exploit database (XDB) linking
"""

import io
import json
import logging
import os
import sqlite3
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import requests

log = logging.getLogger("nexporter.vulncheck")


class VulnCheckKEV:
    """VulnCheck Known Exploited Vulnerabilities integration."""

    KEV_API_URL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
    EXPLOITS_API_URL = "https://api.vulncheck.com/v3/index/exploits"

    def __init__(self, db_path: str, api_key: Optional[str] = None):
        """
        Initialize VulnCheck KEV integration.

        Args:
            db_path: Path to the nexporter SQLite database
            api_key: VulnCheck API key (or set VULNCHECK_API_KEY env var)
        """
        self.db_path = db_path
        self.api_key = api_key or os.environ.get("VULNCHECK_API_KEY")
        if not self.api_key:
            raise ValueError(
                "VulnCheck API key required. Set VULNCHECK_API_KEY env var or pass api_key parameter."
            )
        self._init_kev_tables()

    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_kev_tables(self):
        """Initialize VulnCheck KEV tables in the database."""
        conn = self._get_conn()
        cursor = conn.cursor()

        # Main KEV table - stores the VulnCheck KEV data
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulncheck_kev (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve TEXT UNIQUE NOT NULL,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                short_description TEXT,
                required_action TEXT,
                known_ransomware_use TEXT,
                cwes TEXT,
                exploit_type TEXT,
                is_initial_access INTEGER DEFAULT 0,
                cisa_date_added TEXT,
                vulncheck_date_added TEXT,
                due_date TEXT,
                reported_exploited_by_canaries INTEGER DEFAULT 0,
                last_updated TEXT,
                raw_json TEXT
            )
        """)

        # XDB (Exploit Database) links table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulncheck_xdb (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve TEXT NOT NULL,
                xdb_id TEXT,
                xdb_url TEXT,
                exploit_type TEXT,
                clone_ssh_url TEXT,
                date_added TEXT,
                FOREIGN KEY (cve) REFERENCES vulncheck_kev(cve)
            )
        """)

        # Reported exploitation sources table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulncheck_exploitation_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve TEXT NOT NULL,
                source_url TEXT,
                date_added TEXT,
                FOREIGN KEY (cve) REFERENCES vulncheck_kev(cve)
            )
        """)

        # KEV sync metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulncheck_sync_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sync_type TEXT NOT NULL,
                last_sync TEXT NOT NULL,
                record_count INTEGER,
                status TEXT
            )
        """)

        # Create index for fast CVE lookups
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulncheck_kev_cve ON vulncheck_kev(cve)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulncheck_xdb_cve ON vulncheck_xdb(cve)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulncheck_kev_initial_access ON vulncheck_kev(is_initial_access)"
        )

        conn.commit()
        conn.close()
        log.info("VulnCheck KEV tables initialized")

    def _make_request(self, url: str, params: Optional[dict] = None) -> dict:
        """Make authenticated request to VulnCheck API."""
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        response = requests.get(url, headers=headers, params=params, timeout=120)
        response.raise_for_status()
        return response.json()

    def _download_kev_backup(self) -> list:
        """Download and extract KEV backup ZIP file."""
        # First, get the backup URL
        data = self._make_request(self.KEV_API_URL)
        backup_info = data.get("data", [])

        if not backup_info:
            raise ValueError("No backup data returned from API")

        # The backup endpoint returns metadata with a URL to download the ZIP
        zip_url = backup_info[0].get("url")
        if not zip_url:
            raise ValueError("No download URL in backup response")

        log.info("Downloading KEV backup ZIP file...")
        # Download the ZIP file (no auth needed for the S3 URL)
        zip_response = requests.get(zip_url, timeout=300)
        zip_response.raise_for_status()

        log.info("Extracting KEV data from ZIP...")
        # Extract JSON from ZIP
        with zipfile.ZipFile(io.BytesIO(zip_response.content)) as zf:
            # Find the JSON file in the ZIP
            json_files = [f for f in zf.namelist() if f.endswith('.json')]
            if not json_files:
                raise ValueError("No JSON file found in backup ZIP")

            with zf.open(json_files[0]) as jf:
                kev_data = json.load(jf)

        return kev_data

    def sync_kev(self, force: bool = False) -> dict:
        """
        Sync VulnCheck KEV database.

        Args:
            force: Force sync even if recently synced

        Returns:
            dict with sync statistics
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        # Check last sync time
        cursor.execute(
            "SELECT last_sync FROM vulncheck_sync_metadata WHERE sync_type = 'kev' ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()

        if row and not force:
            last_sync = datetime.fromisoformat(row["last_sync"])
            if datetime.now() - last_sync < timedelta(hours=24):
                log.info(f"KEV database synced within 24 hours (last: {last_sync}). Use force=True to override.")
                conn.close()
                return {"status": "skipped", "reason": "recently_synced", "last_sync": str(last_sync)}

        log.info("Downloading VulnCheck KEV database...")
        try:
            kev_entries = self._download_kev_backup()
        except (requests.exceptions.HTTPError, ValueError) as e:
            log.error(f"Failed to fetch KEV data: {e}")
            conn.close()
            return {"status": "error", "error": str(e)}
        log.info(f"Processing {len(kev_entries)} KEV entries...")

        stats = {"inserted": 0, "updated": 0, "xdb_links": 0, "exploitation_sources": 0}

        for entry in kev_entries:
            cves = entry.get("cve", [])
            if not cves:
                continue

            for cve in cves:
                # Determine if this is an initial access vulnerability
                # based on exploit types in XDB entries
                xdb_entries = entry.get("vulncheck_xdb", [])
                exploit_types = [x.get("exploit_type", "") for x in xdb_entries]
                is_initial_access = "initial-access" in [et.lower() for et in exploit_types if et]

                # Also check if any exploit type indicates remote/initial access
                for et in exploit_types:
                    if et and any(
                        keyword in et.lower()
                        for keyword in ["initial-access", "remote", "rce", "unauthenticated"]
                    ):
                        is_initial_access = True
                        break

                # Insert or update KEV entry
                cursor.execute(
                    """
                    INSERT INTO vulncheck_kev (
                        cve, vendor_project, product, vulnerability_name,
                        short_description, required_action, known_ransomware_use,
                        cwes, exploit_type, is_initial_access,
                        cisa_date_added, vulncheck_date_added, due_date,
                        reported_exploited_by_canaries, last_updated, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve) DO UPDATE SET
                        vendor_project = excluded.vendor_project,
                        product = excluded.product,
                        vulnerability_name = excluded.vulnerability_name,
                        short_description = excluded.short_description,
                        required_action = excluded.required_action,
                        known_ransomware_use = excluded.known_ransomware_use,
                        cwes = excluded.cwes,
                        exploit_type = excluded.exploit_type,
                        is_initial_access = excluded.is_initial_access,
                        cisa_date_added = excluded.cisa_date_added,
                        vulncheck_date_added = excluded.vulncheck_date_added,
                        due_date = excluded.due_date,
                        reported_exploited_by_canaries = excluded.reported_exploited_by_canaries,
                        last_updated = excluded.last_updated,
                        raw_json = excluded.raw_json
                """,
                    (
                        cve,
                        entry.get("vendorProject"),
                        entry.get("product"),
                        entry.get("vulnerabilityName"),
                        entry.get("shortDescription"),
                        entry.get("required_action"),
                        entry.get("knownRansomwareCampaignUse"),
                        json.dumps(entry.get("cwes", [])),
                        ",".join(exploit_types) if exploit_types else None,
                        1 if is_initial_access else 0,
                        entry.get("cisa_date_added"),
                        entry.get("date_added"),
                        entry.get("dueDate"),
                        1 if entry.get("reported_exploited_by_vulncheck_canaries") else 0,
                        datetime.now().isoformat(),
                        json.dumps(entry),
                    ),
                )

                if cursor.rowcount > 0:
                    stats["inserted"] += 1
                else:
                    stats["updated"] += 1

                # Delete existing XDB entries for this CVE and re-insert
                cursor.execute("DELETE FROM vulncheck_xdb WHERE cve = ?", (cve,))
                for xdb in xdb_entries:
                    cursor.execute(
                        """
                        INSERT INTO vulncheck_xdb (cve, xdb_id, xdb_url, exploit_type, clone_ssh_url, date_added)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """,
                        (
                            cve,
                            xdb.get("xdb_id"),
                            xdb.get("xdb_url"),
                            xdb.get("exploit_type"),
                            xdb.get("clone_ssh_url"),
                            xdb.get("date_added"),
                        ),
                    )
                    stats["xdb_links"] += 1

                # Delete existing exploitation sources and re-insert
                cursor.execute(
                    "DELETE FROM vulncheck_exploitation_sources WHERE cve = ?", (cve,)
                )
                for source in entry.get("vulncheck_reported_exploitation", []):
                    cursor.execute(
                        """
                        INSERT INTO vulncheck_exploitation_sources (cve, source_url, date_added)
                        VALUES (?, ?, ?)
                    """,
                        (cve, source.get("url"), source.get("date_added")),
                    )
                    stats["exploitation_sources"] += 1

        # Record sync metadata
        cursor.execute(
            """
            INSERT INTO vulncheck_sync_metadata (sync_type, last_sync, record_count, status)
            VALUES (?, ?, ?, ?)
        """,
            ("kev", datetime.now().isoformat(), len(kev_entries), "success"),
        )

        conn.commit()
        conn.close()

        log.info(f"KEV sync complete: {stats}")
        return {"status": "success", **stats}

    def lookup_cve(self, cve: str) -> Optional[dict]:
        """
        Look up a CVE in the local KEV database.

        Args:
            cve: CVE identifier (e.g., CVE-2022-22965)

        Returns:
            dict with KEV data if found, None otherwise
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM vulncheck_kev WHERE cve = ?", (cve,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            return None

        result = dict(row)

        # Get XDB links
        cursor.execute(
            "SELECT xdb_id, xdb_url, exploit_type, clone_ssh_url, date_added FROM vulncheck_xdb WHERE cve = ?",
            (cve,),
        )
        result["xdb_links"] = [dict(r) for r in cursor.fetchall()]

        # Get exploitation sources
        cursor.execute(
            "SELECT source_url, date_added FROM vulncheck_exploitation_sources WHERE cve = ?",
            (cve,),
        )
        result["exploitation_sources"] = [dict(r) for r in cursor.fetchall()]

        conn.close()
        return result

    def enrich_nessus_findings(self, table_name: Optional[str] = None) -> dict:
        """
        Enrich Nessus findings with VulnCheck KEV data.

        Adds columns to Nessus tables:
        - vulncheck_kev: 1 if in KEV, 0 otherwise
        - vulncheck_initial_access: 1 if classified as initial access
        - vulncheck_xdb_urls: JSON array of exploit URLs
        - vulncheck_ransomware: ransomware campaign association
        - vulncheck_exploit_type: exploit type classification

        Args:
            table_name: Specific table to enrich, or None for all Nessus tables

        Returns:
            dict with enrichment statistics
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        # Get list of Nessus tables (exclude our metadata tables)
        if table_name:
            tables = [table_name]
        else:
            cursor.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='table'
                AND name NOT LIKE 'vulncheck_%'
                AND name NOT LIKE '_source_info_%'
                AND name NOT LIKE 'sqlite_%'
            """
            )
            tables = [row[0] for row in cursor.fetchall()]

        stats = {"tables_processed": 0, "findings_enriched": 0, "kev_matches": 0, "initial_access_matches": 0}

        for tbl in tables:
            log.info(f"Enriching table: {tbl}")

            # Check if CVE column exists
            cursor.execute(f"PRAGMA table_info([{tbl}])")
            columns = {row[1]: row[2] for row in cursor.fetchall()}

            if "CVE" not in columns:
                log.warning(f"Table {tbl} has no CVE column, skipping")
                continue

            # Add enrichment columns if they don't exist
            enrichment_columns = [
                ("vulncheck_kev", "INTEGER DEFAULT 0"),
                ("vulncheck_initial_access", "INTEGER DEFAULT 0"),
                ("vulncheck_xdb_urls", "TEXT"),
                ("vulncheck_ransomware", "TEXT"),
                ("vulncheck_exploit_type", "TEXT"),
                ("vulncheck_vendor", "TEXT"),
                ("vulncheck_product", "TEXT"),
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

                kev_match = False
                initial_access = False
                xdb_urls = []
                ransomware = None
                exploit_type = None
                vendor = None
                product = None

                for single_cve in cve_list:
                    kev_data = self.lookup_cve(single_cve)
                    if kev_data:
                        kev_match = True
                        if kev_data.get("is_initial_access"):
                            initial_access = True
                        if kev_data.get("known_ransomware_use"):
                            ransomware = kev_data["known_ransomware_use"]
                        if kev_data.get("exploit_type"):
                            exploit_type = kev_data["exploit_type"]
                        if kev_data.get("vendor_project"):
                            vendor = kev_data["vendor_project"]
                        if kev_data.get("product"):
                            product = kev_data["product"]
                        for xdb in kev_data.get("xdb_links", []):
                            if xdb.get("xdb_url"):
                                xdb_urls.append(xdb["xdb_url"])

                # Update the findings
                cursor.execute(
                    f"""
                    UPDATE [{tbl}] SET
                        vulncheck_kev = ?,
                        vulncheck_initial_access = ?,
                        vulncheck_xdb_urls = ?,
                        vulncheck_ransomware = ?,
                        vulncheck_exploit_type = ?,
                        vulncheck_vendor = ?,
                        vulncheck_product = ?
                    WHERE CVE = ?
                """,
                    (
                        1 if kev_match else 0,
                        1 if initial_access else 0,
                        json.dumps(xdb_urls) if xdb_urls else None,
                        ransomware,
                        exploit_type,
                        vendor,
                        product,
                        cve,
                    ),
                )

                stats["findings_enriched"] += cursor.rowcount
                if kev_match:
                    stats["kev_matches"] += 1
                if initial_access:
                    stats["initial_access_matches"] += 1

            stats["tables_processed"] += 1

        conn.commit()
        conn.close()

        log.info(f"Enrichment complete: {stats}")
        return stats

    def get_kev_summary(self) -> dict:
        """Get summary statistics of the local KEV database."""
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM vulncheck_kev")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM vulncheck_kev WHERE is_initial_access = 1")
        initial_access = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM vulncheck_kev WHERE known_ransomware_use IS NOT NULL AND known_ransomware_use <> ''"
        )
        ransomware = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM vulncheck_kev WHERE cisa_date_added IS NOT NULL"
        )
        in_cisa = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM vulncheck_xdb")
        xdb_count = cursor.fetchone()[0]

        cursor.execute(
            "SELECT last_sync FROM vulncheck_sync_metadata WHERE sync_type = 'kev' ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        last_sync = row["last_sync"] if row else None

        conn.close()

        return {
            "total_kev_entries": total,
            "initial_access_vulns": initial_access,
            "ransomware_associated": ransomware,
            "in_cisa_kev": in_cisa,
            "vulncheck_only": total - in_cisa,
            "xdb_exploit_links": xdb_count,
            "last_sync": last_sync,
        }

    def get_initial_access_vulns(self) -> list:
        """Get all initial access vulnerabilities from KEV."""
        conn = self._get_conn()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT cve, vendor_project, product, vulnerability_name, exploit_type,
                   known_ransomware_use, cisa_date_added, vulncheck_date_added
            FROM vulncheck_kev
            WHERE is_initial_access = 1
            ORDER BY vulncheck_date_added DESC
        """
        )

        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results

    def find_enriched_findings(
        self,
        kev_only: bool = False,
        initial_access_only: bool = False,
        table_name: Optional[str] = None,
    ) -> list:
        """
        Query enriched Nessus findings.

        Args:
            kev_only: Only return findings in KEV
            initial_access_only: Only return initial access vulnerabilities
            table_name: Specific table to query

        Returns:
            List of enriched findings
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        # Get tables to query
        if table_name:
            tables = [table_name]
        else:
            cursor.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='table'
                AND name NOT LIKE 'vulncheck_%'
                AND name NOT LIKE '_source_info_%'
                AND name NOT LIKE 'sqlite_%'
            """
            )
            tables = [row[0] for row in cursor.fetchall()]

        results = []
        for tbl in tables:
            # Check if table has been enriched
            cursor.execute(f"PRAGMA table_info([{tbl}])")
            columns = [row[1] for row in cursor.fetchall()]

            if "vulncheck_kev" not in columns:
                continue

            where_clauses = []
            if kev_only:
                where_clauses.append("vulncheck_kev = 1")
            if initial_access_only:
                where_clauses.append("vulncheck_initial_access = 1")

            where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

            cursor.execute(
                f"""
                SELECT CVE, Name, Risk, Host, Port, Protocol,
                       vulncheck_kev, vulncheck_initial_access,
                       vulncheck_xdb_urls, vulncheck_ransomware,
                       vulncheck_exploit_type, vulncheck_vendor, vulncheck_product
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
            """
            )

            for row in cursor.fetchall():
                result = dict(row)
                result["_table"] = tbl
                results.append(result)

        conn.close()
        return results
