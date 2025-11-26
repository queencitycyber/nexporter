# nexporter

nexporter lets you export & explore Nessus professional scan data with VulnCheck exploit intelligence and Nuclei template coverage.

![image](https://user-images.githubusercontent.com/13237617/216835626-07c2a0d2-1527-42b0-a657-89c6329e9e23.png)

## Features

- **Export** scans directly from Nessus Professional
- **Import** CSV scan exports into a unified SQLite database
- **VulnCheck KEV Integration** - Enrich findings with Known Exploited Vulnerabilities data
- **Nuclei Templates Integration** - Check which CVEs have nuclei scanner templates available
- **Initial Access Classification** - Identify vulnerabilities that enable remote, unauthenticated access
- **Exploit Database Links** - Direct links to proof-of-concept exploits from VulnCheck XDB
- **Ransomware Association** - Flag vulnerabilities used in ransomware campaigns
- **Combined Exploitability View** - See findings that have KEV AND/OR nuclei template coverage
- **Datasette UI** - Explore data through a web interface

## Why

Nessus is alright when working with a handful of scans. But what if you have 50 different scans and wished to collate them all into a single database? That's what I tried to do here.

The project uses `sqlitebiter` and `datasette` to transform all the `csv` files into a single `.sqlite` database and serve them locally in a browser for API integration, respectively.

**New in v0.2.0**: VulnCheck KEV integration helps prioritize findings by identifying which vulnerabilities are actively exploited in the wild, particularly those classified as "initial access" - the most dangerous class of vulnerabilities for external assessments. Nuclei templates integration shows which CVEs have nuclei scanner templates available, enabling automated verification of Nessus findings.

## Installation

```bash
git clone https://github.com/queencitycyber/nexporter
cd nexporter
python3 -m venv venv
source venv/bin/activate
pip install rich-click requests sqlitebiter datasette sh
```

## Quick Start

```bash
# Activate virtual environment
source venv/bin/activate

# 1. Export from Nessus (or use existing CSV exports)
python3 nexporter.py export -t https://127.0.0.1:8834 -u username

# 2. Import CSV files
python3 nexporter.py import scan1.csv scan2.csv
# Or import a directory of CSVs
python3 nexporter.py import -d ./scans/

# 3. Sync VulnCheck KEV database (requires API key)
export VULNCHECK_API_KEY=your_api_key
python3 nexporter.py kev sync

# 4. Enrich findings with KEV data
python3 nexporter.py kev enrich

# 5. Query enriched findings
python3 nexporter.py query --kev-only
python3 nexporter.py query --initial-access

# 6. Explore in browser
python3 nexporter.py serve
```

## Commands

### Export from Nessus

```bash
python3 nexporter.py export -t https://127.0.0.1:8834 -u username -p password -o csv
```

Or use environment variables:
```bash
export NESSUS_USER=USERNAME
export NESSUS_PASS=PASSWORD
python3 nexporter.py export -t https://127.0.0.1:8834
```

### Import CSV Files

```bash
# Import specific files
python3 nexporter.py import scan1.csv scan2.csv scan3.csv

# Import all CSVs from a directory
python3 nexporter.py import -d ./scans/

# Use a custom database path
python3 nexporter.py -d myproject.db import scan.csv
```

### VulnCheck KEV Operations

#### Sync KEV Database

Downloads the VulnCheck KEV database locally. This includes ~3,700+ known exploited vulnerabilities (175% more than CISA KEV alone).

```bash
# Using environment variable
export VULNCHECK_API_KEY=your_api_key
python3 nexporter.py kev sync

# Using CLI flag
python3 nexporter.py kev sync --api-key your_api_key

# Force re-sync (normally skips if synced within 24 hours)
python3 nexporter.py kev sync --force
```

#### Check KEV Status

```bash
python3 nexporter.py kev status
```

Output:
```
      VulnCheck KEV Database Status
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Metric                         ┃ Value  ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ Total KEV Entries              │ 3,712  │
│ Initial Access Vulnerabilities │ 847    │
│ Ransomware Associated          │ 312    │
│ In CISA KEV                    │ 1,234  │
│ VulnCheck Only (not in CISA)   │ 2,478  │
│ XDB Exploit Links              │ 5,621  │
│ Last Sync                      │ 2024-… │
└────────────────────────────────┴────────┘
```

#### Look Up a Specific CVE

```bash
python3 nexporter.py kev lookup CVE-2022-22965
```

Output:
```
         KEV Entry: CVE-2022-22965
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
┃ Field                ┃ Value             ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ CVE                  │ CVE-2022-22965    │
│ Vendor               │ VMware            │
│ Product              │ Spring Framework  │
│ Vulnerability Name   │ Spring4Shell      │
│ Initial Access       │ YES               │
│ Ransomware Use       │ Known             │
│ Exploit Type         │ initial-access    │
│ CISA Date Added      │ 2022-04-04        │
│ VulnCheck Date Added │ 2022-03-31        │
└──────────────────────┴───────────────────┘

        Exploit Database (XDB) Links
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Type           ┃ URL                     ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ initial-access │ https://vulncheck.com/… │
│ initial-access │ https://vulncheck.com/… │
└────────────────┴─────────────────────────┘
```

#### Enrich Nessus Findings

Adds VulnCheck intelligence columns to your Nessus scan data:

```bash
python3 nexporter.py kev enrich
```

This adds the following columns to each Nessus table:
- `vulncheck_kev` - 1 if the CVE is in KEV, 0 otherwise
- `vulncheck_initial_access` - 1 if classified as initial access vulnerability
- `vulncheck_xdb_urls` - JSON array of exploit PoC URLs
- `vulncheck_ransomware` - Ransomware campaign association
- `vulncheck_exploit_type` - Exploit classification

### Nuclei Templates Operations

#### Sync Nuclei Templates

Scans your local nuclei-templates directory for CVE coverage:

```bash
# Default path: ~/nuclei-templates
python3 nexporter.py nuclei sync

# Custom templates path
python3 nexporter.py nuclei sync --templates-path /path/to/nuclei-templates
```

#### Check Nuclei Status

```bash
python3 nexporter.py nuclei status
```

Output:
```
  Nuclei Templates Database Status
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Metric              ┃ Value                    ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Total CVE Templates │ 3553                     │
│ Templates Path      │ /Users/me/nuclei-templates│
│ Last Sync           │ 2024-11-25T10:28:57      │
└─────────────────────┴──────────────────────────┘

    Templates by Severity
┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ medium   │ 1412  │
│ critical │ 1187  │
│ high     │ 942   │
│ low      │ 12    │
└──────────┴───────┘
```

#### Look Up a CVE in Nuclei Templates

```bash
python3 nexporter.py nuclei lookup CVE-2022-22965
```

#### Enrich Findings with Nuclei Data

```bash
python3 nexporter.py nuclei enrich
```

This adds the following columns to Nessus tables:
- `nuclei_template` - 1 if nuclei template exists, 0 otherwise
- `nuclei_template_name` - Name of the nuclei template
- `nuclei_template_severity` - Severity from nuclei template
- `nuclei_template_path` - Path to the template file

### Query Findings

```bash
# All findings with CVEs
python3 nexporter.py query

# Only KEV vulnerabilities (actively exploited)
python3 nexporter.py query --kev-only

# Only initial access vulnerabilities (most critical for external assessments)
python3 nexporter.py query --initial-access

# Combine filters
python3 nexporter.py query --kev-only --initial-access

# Output formats
python3 nexporter.py query -f table  # Default, rich table
python3 nexporter.py query -f json   # JSON output
python3 nexporter.py query -f csv    # CSV output
```

### Web Interface

```bash
python3 nexporter.py serve
# Opens http://localhost:8001
```

The web interface includes:
- **exploitable_vulnerabilities** - Global view with combined KEV + Nuclei data
- **v_[scan_name]_exploits** - Per-scan views with enrichment
- **exploitable** column - "YES" if KEV OR nuclei template exists

## VulnCheck API Key

Get a free API key from [VulnCheck](https://vulncheck.com):

1. Sign up for a community account at https://vulncheck.com
2. Navigate to your dashboard
3. Copy your API key

The API key is **never stored** - it's only used at runtime via:
- Environment variable: `VULNCHECK_API_KEY`
- CLI flag: `--api-key`

## Database Schema

### VulnCheck Tables

**vulncheck_kev** - Known Exploited Vulnerabilities
| Column | Description |
|--------|-------------|
| cve | CVE identifier |
| vendor_project | Vendor name |
| product | Product name |
| vulnerability_name | Descriptive name |
| is_initial_access | 1 if initial access vuln |
| known_ransomware_use | Ransomware association |
| exploit_type | Exploit classification |
| cisa_date_added | Date added to CISA KEV |
| vulncheck_date_added | Date added to VulnCheck KEV |

**vulncheck_xdb** - Exploit Database Links
| Column | Description |
|--------|-------------|
| cve | CVE identifier |
| xdb_url | URL to exploit PoC |
| exploit_type | Type of exploit |
| clone_ssh_url | Git clone URL for PoC |

### Nuclei Templates Tables

**nuclei_cve_templates** - CVE Template Coverage
| Column | Description |
|--------|-------------|
| cve | CVE identifier |
| template_name | Name of the nuclei template |
| severity | Severity (critical, high, medium, low) |
| description | Template description |
| cvss_score | CVSS score if available |
| file_path | Path to template file |

### Enrichment Columns (added to Nessus tables)

**VulnCheck KEV columns:**
| Column | Description |
|--------|-------------|
| vulncheck_kev | 1 if in KEV, 0 otherwise |
| vulncheck_initial_access | 1 if initial access vuln |
| vulncheck_xdb_urls | JSON array of exploit URLs |
| vulncheck_ransomware | Ransomware campaign info |
| vulncheck_exploit_type | Exploit classification |

**Nuclei templates columns:**
| Column | Description |
|--------|-------------|
| nuclei_template | 1 if nuclei template exists, 0 otherwise |
| nuclei_template_name | Name of the nuclei template |
| nuclei_template_severity | Severity from nuclei template |
| nuclei_template_path | Path to template file |

## Use Cases

### Pentesting Prioritization

Focus on what matters most for external assessments:

```bash
# Find initial access vulnerabilities - the most dangerous for perimeter security
python3 nexporter.py query --initial-access -f json > critical_findings.json
```

### Vulnerability Management

Identify which findings have known exploits in the wild:

```bash
# All actively exploited vulnerabilities
python3 nexporter.py query --kev-only

# Export for ticketing system
python3 nexporter.py query --kev-only -f csv > kev_findings.csv
```

### Ransomware Risk Assessment

```bash
# Query the database directly for ransomware-associated vulns
sqlite3 nexporter.db "
  SELECT n.CVE, n.Host, n.Name, k.known_ransomware_use
  FROM your_scan_table n
  JOIN vulncheck_kev k ON n.CVE = k.cve
  WHERE k.known_ransomware_use IS NOT NULL
"
```

## Thanks

- [puzzlepeaches](https://github.com/puzzlepeaches) who helped on the hard stuff
- [Simon Willison](https://github.com/simonw) for [datasette](https://github.com/simonw/datasette)
- [Tsuyoshi Hombashi](https://github.com/thombashi) for [sqlitebiter](https://github.com/thombashi/sqlitebiter)
- [Nick Berrie](https://github.com/machevalia) for VulnCheck KEV and Nuclei templates integration features
