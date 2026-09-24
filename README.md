# FleetCVEs

A small local advisory inbox backed by NVD, SQLite, NiceGUI, a JSON API, and a CLI. Advisories are imported broadly; explicit rules file away only those proven irrelevant. Everything uncertain stays in the Inbox for notes and manual completion. No CPE catalog download, asset inventory, or login is required.

## Quick start

Python 3.10+:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
fleetcves serve
```

Open <http://127.0.0.1:8080>. The first sync imports the NVD CVE collection and can take a long time without a key; later syncs use modification windows. Run `fleetcves sync` independently from cron/systemd or another scheduler. The local server runs periodic syncs. It binds **localhost only** and has **no authentication**: do not expose it on a network without adding access control.

## Coverage and decisions

Add vendors in **Coverage** to focus the default **Monitored vendors** view in the Inbox and Archive. Adding/removing a vendor instantly includes/excludes its advisories from that view; this is bulk culling of the work queue, **not deletion or automatic archiving**. Switch **View** to **All advisories** to inspect every retained CVE, or **No product mapping** to audit unmapped CVEs. With no vendors configured the default view shows setup guidance, not the entire NVD feed. NVD's CVE API has no reliable affected-manufacturer parameter: sourceIdentifier identifies the CVE source, not the affected vendor; keywordSearch searches text, while CPE-based virtualMatchString depends on incomplete/correctable mappings. FleetCVEs imports without a vendor restriction and retains every advisory. Vendor filtering matches the CPE vendor field exactly (case-insensitive), and product search applies only to the product field of the **same** vulnerable CPE. Missing, incomplete, or differently named NVD mappings can still hide relevant entries from the monitored view; review **No product mapping** and **All advisories** periodically. Open **NVD details** on an advisory for CVSS scores/vectors, CWEs, affected CPE criteria/version bounds, source/status, and references.

Two rules are supported:

- **Product exclusion:** a vendor/product pair known not to be deployed, with an explicit reason. Every potentially affected product in a simple advisory must be covered before it can be auto-archived.
- **Minimum deployed version:** a vendor/product, numeric branch (e.g. `17.6`), and minimum version (e.g. `17.6.6`). Only a simple affected range provably ending *before* the minimum on the same branch can be archived (e.g. `>=17.6.0, <17.6.4`). An inclusive end equal to the minimum is not safe. An upper-only range such as `<17.6.4` may also include older branches, so it stays in the Inbox unless NVD supplies an explicit same-branch lower bound. Unclear branches, wildcard-only versions, nonnumeric versions, complex configurations, and missing data stay in the Inbox.

Auto-archive is **not** a patch or manual completion. Its rule IDs, explanation, and evaluation time are visible in Archive. Adding, disabling, or deleting rules re-evaluates automatic decisions, and changed NVD source data re-evaluates its advisory. Manual completion survives sync and rules; a completed advisory whose NVD modification time changes is flagged for review. Reopen it to apply current rules again. Rule lists show how many advisories each currently helps archive.

## Configuration

| Variable | Purpose |
| --- | --- |
| `FLEETCVES_DB` | SQLite file; default `./fleetcves.sqlite3` |
| `FLEETCVES_PORT` | Local UI/API port; default `8080` |
| `NVD_API_KEY` | Optional key for higher NVD request limits |
| `NVD_API_BASE` | NVD REST base URL; default `https://services.nvd.nist.gov/rest/json` |

Requests are serialized and spaced at least 6.1 seconds apart (0.65 with a key), within the NVD 5/30s or 50/30s limits. Sync pages at 2,000 items. Incremental queries use overlapping `lastModStartDate`/`lastModEndDate` windows smaller than the NVD 120-day maximum. A failed run keeps its previous successful cursor and saved advisories; replay is idempotent. No real-time guarantee or perfect vendor coverage is implied. See [NVD CVE API documentation](https://nvd.nist.gov/developers/vulnerabilities).

## CLI

```bash
fleetcves sync
fleetcves inbox --state inbox
fleetcves inbox --state completed --search CVE-2026
fleetcves add-coverage cisco
fleetcves coverage
fleetcves add-rule exclude cisco unused_product --reason 'Not deployed'
fleetcves add-rule baseline cisco ios_xe --branch 17.6 --minimum-version 17.6.6
fleetcves rules
fleetcves disable-rule 1
fleetcves delete-rule 1
fleetcves export --state inbox --vendor cisco > inbox.csv
fleetcves --db /path/to/fleet.sqlite3 sync
```

`export` also accepts `--search`, `--product`, `--severity`, and `--state all|inbox|completed|auto_archived`. CSV includes source and decision data and prefixes formula-like cells to protect spreadsheet readers.

## JSON API

The localhost server exposes GET /api/advisories (search, vendor, product, severity, state, limit, offset, scope), GET /api/advisories/count, GET /api/advisories/{cve_id} (full stored NVD record), GET /api/export.csv (same filters), coverage and rules CRUD routes, and advisory notes/completion updates. scope=covered|unmapped|all defaults to all for API compatibility; the UI defaults to covered. The UI and CLI share one SQLite file.

For a local integration, for example:

```bash
curl 'http://127.0.0.1:8080/api/advisories?state=inbox&vendor=cisco&severity=HIGH'
curl -X POST http://127.0.0.1:8080/api/coverage -H 'Content-Type: application/json' -d '{"vendor":"cisco"}'
curl -X PUT http://127.0.0.1:8080/api/advisories/CVE-2026-1234/complete -H 'Content-Type: application/json' -d '{"complete":true}'
curl -o inbox.csv 'http://127.0.0.1:8080/api/export.csv?state=inbox&vendor=cisco'
```

In the UI, complete an Inbox item after review; reopen it from **Archive / Completed → Completed**. Automatic decisions appear separately under **Archived**, with the matching rule IDs and explanation. Filtering and CSV export use the selected view's filters; no advisory is deleted by a rule.

## Existing databases

Schema initialization is idempotent. Existing cves rows gain raw JSON and display product columns; vulnerable CPE vendor/product pairs are indexed from stored raw NVD records once on upgrade and updated on source corrections. Old CPE catalog, findings, and statuses tables are left intact. Nonempty legacy per-CPE statuses are copied into advisory notes, retaining their CPE names; they are **not** assumed to mean manual completion. Historical CVEs without raw configurations appear under **No product mapping** until NVD imports them. Old CPE tracking/polling commands are removed; a fresh advisory sync is needed for complete coverage.

## Check

```bash
python -m unittest discover -v
```
