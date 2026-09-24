"""Local NVD catalog and vulnerability tracker; run `python -m fleetcves --help`."""

import argparse
import json
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

DB_PATH = Path(os.environ.get('FLEETCVES_DB', 'fleetcves.sqlite3'))
NVD_BASE = os.environ.get('NVD_API_BASE', 'https://services.nvd.nist.gov/rest/json').rstrip('/')
_last_request = 0.0
_request_lock = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


@contextmanager
def database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys = ON')
    try:
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def initialize():
    with database() as db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS cpes (
                name TEXT PRIMARY KEY, title TEXT NOT NULL, vendor TEXT NOT NULL,
                product TEXT NOT NULL, version TEXT NOT NULL, modified TEXT NOT NULL,
                deprecated INTEGER NOT NULL DEFAULT 0, tracked INTEGER NOT NULL DEFAULT 0,
                in_use INTEGER NOT NULL DEFAULT 1, polled_at TEXT
            );
            CREATE INDEX IF NOT EXISTS cpes_search ON cpes(vendor, product, version);
            CREATE TABLE IF NOT EXISTS statuses (name TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY, description TEXT NOT NULL, severity TEXT,
                published TEXT, modified TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                cpe_name TEXT NOT NULL REFERENCES cpes(name),
                cve_id TEXT NOT NULL REFERENCES cves(id),
                status TEXT REFERENCES statuses(name),
                PRIMARY KEY(cpe_name, cve_id)
            );
        ''')
        db.executemany('INSERT OR IGNORE INTO statuses VALUES (?)',
                       [('mitigated',), ('not applicable',), ('patched',)])


def rows(sql, params=()):
    with database() as db:
        return [dict(row) for row in db.execute(sql, params)]


def request(endpoint, params):
    global _last_request
    # NVD's public limit is 5 requests / 30 seconds; API keys allow 50 / 30 seconds.
    with _request_lock:
        interval = 0.65 if os.environ.get('NVD_API_KEY') else 6.1
        delay = interval - (time.monotonic() - _last_request)
        if delay > 0:
            time.sleep(delay)
        headers = {'User-Agent': 'FleetCVEs/0.1'}
        if os.environ.get('NVD_API_KEY'):
            headers['apiKey'] = os.environ['NVD_API_KEY']
        req = Request(f'{NVD_BASE}/{endpoint}?{urlencode(params)}', headers=headers)
        _last_request = time.monotonic()
        with urlopen(req, timeout=45) as response:
            return json.load(response)


def sync_cpes():
    """Page the entire catalog initially; later query bounded modification windows.

    Cursor advances only after a full window, so a failed run safely replays it.
    """
    initialize()
    cursor = rows("SELECT value FROM metadata WHERE key='cpe_cursor'")
    end = now()
    start = datetime.fromisoformat(cursor[0]['value'].replace('Z', '+00:00')) - timedelta(seconds=1) if cursor else None
    total = 0
    while True:
        window_end = min(start + timedelta(days=119), datetime.fromisoformat(end.replace('Z', '+00:00'))) if start else None
        params = {'resultsPerPage': 10000}
        if start:
            params.update(lastModStartDate=start.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                          lastModEndDate=window_end.isoformat(timespec='milliseconds').replace('+00:00', 'Z'))
        index = 0
        while True:
            data = request('cpes/2.0', {**params, 'startIndex': index})
            items = data['products']
            with database() as db:
                for item in items:
                    cpe = item['cpe']
                    name = cpe['cpeName']
                    parts = re.split(r'(?<!\\):', name)
                    db.execute('''INSERT INTO cpes(name,title,vendor,product,version,modified,deprecated)
                        VALUES (?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET
                        title=excluded.title, modified=excluded.modified, deprecated=excluded.deprecated''',
                        (name, next((t['title'] for t in cpe.get('titles', []) if t.get('lang') == 'en'), name),
                         parts[3], parts[4], parts[5], cpe['lastModified'], int(cpe.get('deprecated', False))))
            total += len(items)
            index += len(items)
            if not items or index >= data['totalResults']:
                break
        if not start or window_end >= datetime.fromisoformat(end.replace('Z', '+00:00')):
            break
        start = window_end - timedelta(seconds=1)
    with database() as db:
        db.execute("INSERT INTO metadata VALUES ('cpe_cursor', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (end,))
    return total


def catalog(search='', limit=100):
    return rows('''SELECT name,title,vendor,product,version,tracked,in_use,deprecated FROM cpes
        WHERE (name LIKE ? OR title LIKE ?) AND deprecated=0
        ORDER BY tracked DESC, vendor, product, version LIMIT ?''',
        (f'%{search}%', f'%{search}%', min(max(int(limit), 1), 500)))


def track(name, enabled=True):
    with database() as db:
        result = db.execute('UPDATE cpes SET tracked=? WHERE name=? AND deprecated=0', (int(enabled), name))
        if not result.rowcount:
            raise ValueError('CPE not found or deprecated')


def set_in_use(name, enabled):
    with database() as db:
        result = db.execute('UPDATE cpes SET in_use=? WHERE name=? AND tracked=1', (int(enabled), name))
        if not result.rowcount:
            raise ValueError('Tracked CPE not found')


def poll(name):
    cpe = rows('SELECT name FROM cpes WHERE name=? AND tracked=1 AND deprecated=0', (name,))
    if not cpe:
        raise ValueError('Tracked CPE not found')
    index = 0
    seen = set()
    while True:
        data = request('cves/2.0', {'cpeName': name, 'resultsPerPage': 2000, 'startIndex': index})
        items = data['vulnerabilities']
        with database() as db:
            for item in items:
                cve = item['cve']
                ident = cve['id']
                seen.add(ident)
                metrics = cve.get('metrics', {})
                score = next((entry['cvssData'].get('baseSeverity') for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2', 'cvssMetricV40') for entry in metrics.get(key, []) if 'baseSeverity' in entry.get('cvssData', {})), None)
                description = next((d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'), '')
                db.execute('''INSERT INTO cves VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                    description=excluded.description,severity=excluded.severity,
                    published=excluded.published,modified=excluded.modified''',
                    (ident, description, score, cve.get('published'), cve.get('lastModified')))
                db.execute('INSERT OR IGNORE INTO findings(cpe_name,cve_id) VALUES (?,?)', (name, ident))
        index += len(items)
        if not items or index >= data['totalResults']:
            break
    with database() as db:
        # A complete poll reconciles removed or corrected NVD matches without losing other CPE findings.
        if seen:
            db.execute(f"DELETE FROM findings WHERE cpe_name=? AND cve_id NOT IN ({','.join('?' for _ in seen)})", (name, *seen))
        else:
            db.execute('DELETE FROM findings WHERE cpe_name=?', (name,))
        db.execute('UPDATE cpes SET polled_at=? WHERE name=?', (now(), name))
    return len(seen)


def poll_due(hours=24):
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    for cpe in rows('SELECT name FROM cpes WHERE tracked=1 AND deprecated=0 AND (polled_at IS NULL OR polled_at < ?) ORDER BY polled_at LIMIT 100', (cutoff,)):
        poll(cpe['name'])


def findings():
    return rows('''SELECT f.cpe_name,f.cve_id,f.status,c.description,c.severity,c.published,
        p.vendor,p.product,p.version FROM findings f JOIN cves c ON c.id=f.cve_id
        JOIN cpes p ON p.name=f.cpe_name WHERE p.tracked=1 AND p.in_use=1
        ORDER BY c.published DESC LIMIT 500''')


def set_status(cpe_name, cve_id, status):
    with database() as db:
        if status is not None and not db.execute('SELECT 1 FROM statuses WHERE name=?', (status,)).fetchone():
            raise ValueError('Unknown status')
        result = db.execute('UPDATE findings SET status=? WHERE cpe_name=? AND cve_id=?', (status, cpe_name, cve_id))
        if not result.rowcount:
            raise ValueError('Finding not found')


def add_status(name):
    name = name.strip()
    if not name or len(name) > 60:
        raise ValueError('Status must be 1–60 characters')
    with database() as db:
        db.execute('INSERT INTO statuses VALUES (?)', (name,))


def main():
    parser = argparse.ArgumentParser(description='Local NVD CPE and CVE tracker')
    parser.add_argument('--db', help='SQLite path (default: FLEETCVES_DB or ./fleetcves.sqlite3)')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('serve')
    sub.add_parser('sync')
    sub.add_parser('poll')
    ls = sub.add_parser('cpes'); ls.add_argument('search', nargs='?', default='')
    tr = sub.add_parser('track'); tr.add_argument('name'); tr.add_argument('--off', action='store_true')
    use = sub.add_parser('in-use'); use.add_argument('name'); use.add_argument('enabled', choices=['yes', 'no'])
    sub.add_parser('findings')
    st = sub.add_parser('status'); st.add_argument('cpe'); st.add_argument('cve'); st.add_argument('name')
    custom = sub.add_parser('add-status'); custom.add_argument('name')
    args = parser.parse_args()
    global DB_PATH
    if args.db:
        DB_PATH = Path(args.db)
    initialize()
    if args.command == 'serve':
        from web import run
        run()
    elif args.command == 'sync':
        print(sync_cpes())
    elif args.command == 'poll':
        poll_due(hours=0)
    elif args.command == 'cpes':
        print(json.dumps(catalog(args.search), indent=2))
    elif args.command == 'track':
        track(args.name, not args.off)
    elif args.command == 'in-use':
        set_in_use(args.name, args.enabled == 'yes')
    elif args.command == 'findings':
        print(json.dumps(findings(), indent=2))
    elif args.command == 'status':
        set_status(args.cpe, args.cve, None if args.name == 'clear' else args.name)
    elif args.command == 'add-status':
        add_status(args.name)


if __name__ == '__main__':
    main()
