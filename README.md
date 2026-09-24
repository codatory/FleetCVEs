# FleetCVEs

A local NVD CPE and CVE tracker with a NiceGUI browser interface, JSON API, CLI, and SQLite database. Select the CPE versions you care about, hide versions you do not use, and record a triage status for each CPE/CVE finding.

## Quick start

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
fleetcves serve
```

Open <http://127.0.0.1:8080>. On startup, the app syncs the NVD CPE catalog in the background. The **first sync downloads the full catalog** and can take a long time without an NVD API key; later syncs request changed CPEs. Search the catalog and check **Track** for the versions you want polled. Uncheck **In use** to hide a tracked version's findings without losing its triage decisions. Findings are polled in the background and can be marked *mitigated*, *not applicable*, *patched*, or with a custom status.

The server listens on **localhost only** and has **no authentication**. Do not expose it to other hosts without adding access control.

## Configuration

| Environment variable | Purpose |
| --- | --- |
| `FLEETCVES_DB` | SQLite file path; defaults to `./fleetcves.sqlite3` |
| `FLEETCVES_PORT` | Browser and API port; defaults to `8080` |
| `NVD_API_KEY` | Optional NVD API key for higher request limits |
| `NVD_API_BASE` | NVD REST base URL; defaults to `https://services.nvd.nist.gov/rest/json` |

The app respects NVD request limits (5 requests per 30 seconds without a key, 50 with one). A failed catalog sync retries without advancing its change cursor; findings keep their statuses when repolled.

## CLI

```bash
fleetcves sync                         # sync the CPE catalog now
fleetcves cpes widget                  # search the local catalog (JSON)
fleetcves track 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*'
fleetcves poll                         # poll tracked CPEs now
fleetcves findings                     # list visible findings (JSON)
fleetcves in-use 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*' no
fleetcves add-status 'risk accepted'
fleetcves status 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*' CVE-2026-1234 'risk accepted'
```

Use `fleetcves status <cpe> <cve> clear` to remove a triage status, `fleetcves track <cpe> --off` to stop tracking, or `fleetcves --db /path/to/db.sqlite3 <command>` to choose a database for one command.

## JSON API

The same local server exposes:

| Method | Route | Body / query |
| --- | --- | --- |
| GET | `/api/cpes` | `?search=widget&limit=100` |
| PUT | `/api/cpes/{name}/tracked` | `{"enabled": true}` |
| PUT | `/api/cpes/{name}/in-use` | `{"enabled": false}` |
| GET | `/api/findings` | — |
| GET | `/api/statuses` | — |
| POST | `/api/statuses` | `{"name": "risk accepted"}` |
| PUT | `/api/findings/status` | `{"cpe_name": "...", "cve_id": "CVE-...", "status": "patched"}`; use `null` to clear |

URL-encode the CPE name in path parameters. The API and CLI operate on the same SQLite file.

## Check

```bash
python -m unittest test_fleetcves
```
