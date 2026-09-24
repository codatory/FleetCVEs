"""Local NVD advisory inbox; run `python -m fleetcves --help`."""
import argparse
import csv
import io
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from rules import _cpe_parts, evaluate

DB_PATH = Path(os.environ.get('FLEETCVES_DB', 'fleetcves.sqlite3'))
NVD_BASE = os.environ.get('NVD_API_BASE', 'https://services.nvd.nist.gov/rest/json').rstrip('/')
_last_request = 0.0
_request_lock = threading.Lock()
_sync_lock = threading.Lock()


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
        db.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        db.execute('''CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY, description TEXT NOT NULL, severity TEXT,
            published TEXT, modified TEXT, raw TEXT, products TEXT NOT NULL DEFAULT '')''')
        columns = {row['name'] for row in db.execute('PRAGMA table_info(cves)')}
        if 'raw' not in columns:
            db.execute('ALTER TABLE cves ADD COLUMN raw TEXT')
        if 'products' not in columns:
            db.execute("ALTER TABLE cves ADD COLUMN products TEXT NOT NULL DEFAULT ''")
        db.execute('CREATE TABLE IF NOT EXISTS coverage (vendor TEXT PRIMARY KEY COLLATE NOCASE)')
        db.execute('''CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('exclude','baseline')),
            vendor TEXT NOT NULL, product TEXT NOT NULL, branch TEXT,
            minimum_version TEXT, reason TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)''')
        db.execute('''CREATE TABLE IF NOT EXISTS advisory_products (
            cve_id TEXT NOT NULL REFERENCES cves(id), vendor TEXT NOT NULL COLLATE NOCASE,
            product TEXT NOT NULL COLLATE NOCASE, PRIMARY KEY(cve_id,vendor,product))''')
        db.execute('CREATE INDEX IF NOT EXISTS advisory_products_vendor ON advisory_products(vendor,product,cve_id)')
        db.execute('CREATE INDEX IF NOT EXISTS cves_published ON cves(published DESC,id DESC)')
        if not db.execute("SELECT 1 FROM metadata WHERE key='advisory_products_v1'").fetchone():
            for record in db.execute('SELECT id,raw FROM cves WHERE raw IS NOT NULL'):
                db.executemany('INSERT OR IGNORE INTO advisory_products VALUES (?,?,?)',
                               ((record['id'], v, p) for v, p in _matches(json.loads(record['raw']))))
            db.execute("INSERT INTO metadata VALUES ('advisory_products_v1','1')")
        db.execute('''CREATE TABLE IF NOT EXISTS triage (
            cve_id TEXT PRIMARY KEY REFERENCES cves(id), notes TEXT NOT NULL DEFAULT '',
            completed_at TEXT, reviewed_modified TEXT, disposition TEXT, rule_ids TEXT,
            reason TEXT, evaluated_at TEXT)''')
        if 'disposition' not in {row['name'] for row in db.execute('PRAGMA table_info(triage)')}:
            db.execute('ALTER TABLE triage ADD COLUMN disposition TEXT')
        # Older databases placed user statuses on CPE/CVE edges. Copy them once onto
        # the durable advisory, without deleting the original tables or asserting a patch.
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='findings'").fetchone():
            db.execute('''INSERT OR IGNORE INTO triage(cve_id,notes)
                SELECT cve_id, group_concat(cpe_name || ': ' || status, '; ')
                FROM findings WHERE status IS NOT NULL GROUP BY cve_id''')


def rows(sql, params=()):
    with database() as db:
        return [dict(row) for row in db.execute(sql, params)]


def request(endpoint, params):
    global _last_request
    with _request_lock:
        # 5 / 30s public, 50 / 30s keyed; serialized even across UI and CLI threads.
        interval = 0.65 if os.environ.get('NVD_API_KEY') else 6.1
        delay = interval - (time.monotonic() - _last_request)
        if delay > 0:
            time.sleep(delay)
        headers = {'User-Agent': 'FleetCVEs/0.2'}
        if os.environ.get('NVD_API_KEY'):
            headers['apiKey'] = os.environ['NVD_API_KEY']
        _last_request = time.monotonic()
        with urlopen(Request(f'{NVD_BASE}/{endpoint}?{urlencode(params)}', headers=headers), timeout=45) as response:
            return json.load(response)


def _matches(cve):
    """Index vulnerable CPE vendor/product pairs; retain raw configurations for decisions."""
    found = set()
    def visit(node):
        for match in node.get('cpeMatch', []):
            if match.get('vulnerable') is True:
                parts = _cpe_parts(match.get('criteria'))
                if parts and parts[3] not in ('*', '-') and parts[4] not in ('*', '-'):
                    found.add((parts[3], parts[4]))
        for child in node.get('children', []):
            visit(child)
    for configuration in cve.get('configurations', []):
        for node in configuration.get('nodes', []):
            visit(node)
    return sorted(found)


def _enabled(db):
    return [dict(row) for row in db.execute('SELECT * FROM rules WHERE enabled=1 ORDER BY id')]


def _decision(db, ident, raw, rules):
    record = db.execute('SELECT completed_at,disposition FROM triage WHERE cve_id=?', (ident,)).fetchone()
    if record and (record['completed_at'] or record['disposition'] == 'verified'):
        return
    result = evaluate(json.loads(raw), rules) if raw else None
    ids, reason = result if result else (None, None)
    db.execute('''INSERT INTO triage(cve_id,rule_ids,reason,evaluated_at) VALUES (?,?,?,?)
        ON CONFLICT(cve_id) DO UPDATE SET rule_ids=excluded.rule_ids,
        reason=excluded.reason,evaluated_at=excluded.evaluated_at''',
        (ident, json.dumps(ids) if ids else None, reason, now()))


def sync_advisories(on_progress=None):
    """Download all CVEs initially; replay overlapping modification windows thereafter.

    A window is never checkpointed until every page in the whole run succeeds.
    """
    with _sync_lock:
        initialize()
        cursor = rows("SELECT value FROM metadata WHERE key='advisory_cursor'")
        end = datetime.now(timezone.utc)
        start = datetime.fromisoformat(cursor[0]['value'].replace('Z', '+00:00')) - timedelta(seconds=1) if cursor else None
        total = 0
        while True:
            window_end = min(start + timedelta(days=119), end) if start else None
            params = {'resultsPerPage': 2000}
            if start:
                params.update(lastModStartDate=start.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                              lastModEndDate=window_end.isoformat(timespec='milliseconds').replace('+00:00', 'Z'))
            index = 0
            while True:
                data = request('cves/2.0', {**params, 'startIndex': index})
                items = data['vulnerabilities']
                count = data['totalResults']
                if not items and index < count:
                    raise ValueError('NVD returned an incomplete advisory page')
                with database() as db:
                    active = _enabled(db)
                    for item in items:
                        cve = item['cve']
                        ident = cve['id']
                        raw = json.dumps(cve, separators=(',', ':'), sort_keys=True)
                        metrics = cve.get('metrics', {})
                        severity = next((v['cvssData']['baseSeverity'] for key in
                            ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2')
                            for v in metrics.get(key, []) if 'baseSeverity' in v.get('cvssData', {})), None)
                        description = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), '')
                        old = db.execute('SELECT raw FROM cves WHERE id=?', (ident,)).fetchone()
                        if old and old['raw'] == raw:
                            continue
                        matches = _matches(cve)
                        db.execute('''INSERT INTO cves(id,description,severity,published,modified,raw,products)
                            VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                            description=excluded.description,severity=excluded.severity,
                            published=excluded.published,modified=excluded.modified,
                            raw=excluded.raw,products=excluded.products''',
                            (ident, description, severity, cve.get('published'), cve.get('lastModified'), raw,
                             ', '.join(f'{v}/{p}' for v, p in matches)))
                        db.execute('DELETE FROM advisory_products WHERE cve_id=?', (ident,))
                        db.executemany('INSERT OR IGNORE INTO advisory_products VALUES (?,?,?)', ((ident, v, p) for v, p in matches))
                        _decision(db, ident, raw, active)
                total += len(items)
                index += len(items)
                if on_progress:
                    on_progress(total, index, count)
                if index >= count:
                    break
            if not start or window_end >= end:
                break
            start = window_end - timedelta(seconds=1)
        with database() as db:
            db.execute("INSERT INTO metadata VALUES ('advisory_cursor', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (end.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),))
        return total


def coverage():
    return rows('SELECT vendor FROM coverage ORDER BY vendor COLLATE NOCASE')


def add_coverage(vendor):
    vendor = vendor.strip()
    if not vendor:
        raise ValueError('Vendor is required')
    with database() as db:
        db.execute('INSERT OR IGNORE INTO coverage VALUES (?)', (vendor,))


def remove_coverage(vendor):
    with database() as db:
        db.execute('DELETE FROM coverage WHERE vendor=?', (vendor,))


def rules_list():
    return rows('''SELECT r.*, (SELECT COUNT(*) FROM triage t WHERE t.rule_ids IS NOT NULL
        AND EXISTS (SELECT 1 FROM json_each(t.rule_ids) WHERE value=r.id)) AS archived_count
        FROM rules r ORDER BY r.id''')


def reevaluate(db):
    active = _enabled(db)
    for row in db.execute('''SELECT c.id,c.raw FROM cves c LEFT JOIN triage t ON t.cve_id=c.id
                             WHERE t.completed_at IS NULL AND t.disposition IS NULL''').fetchall():
        _decision(db, row['id'], row['raw'], active)


def add_rule(kind, vendor, product, branch='', minimum_version='', reason=''):
    vendor, product, branch, minimum_version, reason = (s.strip() for s in (vendor, product, branch, minimum_version, reason))
    if kind not in ('exclude', 'baseline') or not vendor or not product or (kind == 'baseline' and (not branch or not minimum_version)) or (kind == 'exclude' and (branch or minimum_version)):
        raise ValueError('Specify a vendor/product and, for baselines, a branch and minimum version')
    if kind == 'exclude' and not reason:
        raise ValueError('Product exclusion requires a reason')
    with database() as db:
        ident = db.execute('INSERT INTO rules(kind,vendor,product,branch,minimum_version,reason) VALUES (?,?,?,?,?,?)',
                           (kind, vendor, product, branch or None, minimum_version or None, reason)).lastrowid
        reevaluate(db)
        return ident


def set_rule_enabled(ident, enabled):
    with database() as db:
        if not db.execute('UPDATE rules SET enabled=? WHERE id=?', (int(enabled), ident)).rowcount:
            raise ValueError('Rule not found')
        reevaluate(db)


def delete_rule(ident):
    with database() as db:
        if not db.execute('DELETE FROM rules WHERE id=?', (ident,)).rowcount:
            raise ValueError('Rule not found')
        reevaluate(db)


def set_notes(cve_id, notes):
    with database() as db:
        if not db.execute('SELECT 1 FROM cves WHERE id=?', (cve_id,)).fetchone():
            raise ValueError('Advisory not found')
        db.execute('INSERT INTO triage(cve_id,notes) VALUES (?,?) ON CONFLICT(cve_id) DO UPDATE SET notes=excluded.notes', (cve_id, notes))


def set_disposition(cve_id, disposition):
    if disposition not in (None, 'verified', 'not_applicable', 'resolved'):
        raise ValueError('Unknown disposition')
    with database() as db:
        cve = db.execute('SELECT modified,raw FROM cves WHERE id=?', (cve_id,)).fetchone()
        if not cve:
            raise ValueError('Advisory not found')
        if disposition is None:
            db.execute('UPDATE triage SET disposition=NULL,completed_at=NULL,reviewed_modified=NULL WHERE cve_id=?', (cve_id,))
            _decision(db, cve_id, cve['raw'], _enabled(db))
        else:
            db.execute('''INSERT INTO triage(cve_id,disposition,completed_at,reviewed_modified,rule_ids,reason,evaluated_at)
                VALUES (?,?,?,?,NULL,NULL,NULL) ON CONFLICT(cve_id) DO UPDATE SET
                disposition=excluded.disposition,completed_at=excluded.completed_at,
                reviewed_modified=excluded.reviewed_modified,rule_ids=NULL,reason=NULL,evaluated_at=NULL''',
                (cve_id, disposition, now() if disposition != 'verified' else None, cve['modified']))


def _where(search='', vendor='', product='', severity='', state='inbox', scope='all'):
    clause = ['1=1']
    params = []
    if search:
        clause.append('(c.id LIKE ? OR c.description LIKE ?)')
        params.extend((f'%{search}%', f'%{search}%'))
    if vendor or product:
        terms = ['ap.cve_id=c.id']
        if vendor:
            terms.append('ap.vendor=?')
            params.append(vendor)
        if product:
            terms.append('instr(lower(ap.product),lower(?))>0')
            params.append(product)
        clause.append('EXISTS (SELECT 1 FROM advisory_products ap WHERE ' + ' AND '.join(terms) + ')')
    if severity:
        clause.append('c.severity=?')
        params.append(severity)
    states = {'inbox': 't.completed_at IS NULL AND t.rule_ids IS NULL',
              'verified': "t.disposition='verified'",
              'reviewed': 't.completed_at IS NOT NULL',
              'auto_archived': 't.completed_at IS NULL AND t.rule_ids IS NOT NULL',
              'all': '1=1'}
    if state not in states:
        raise ValueError('Unknown state')
    clause.append(states[state])
    scopes = {'all': None,
              'covered': 'EXISTS (SELECT 1 FROM advisory_products ap JOIN coverage v ON v.vendor=ap.vendor WHERE ap.cve_id=c.id)',
              'unmapped': 'NOT EXISTS (SELECT 1 FROM advisory_products ap WHERE ap.cve_id=c.id)'}
    if scope not in scopes:
        raise ValueError('Unknown scope')
    if scopes[scope]:
        clause.append(scopes[scope])
    return ' AND '.join(clause), params


def advisory_count(search='', vendor='', product='', severity='', state='inbox', scope='all'):
    where, params = _where(search, vendor, product, severity, state, scope)
    return rows(f'SELECT COUNT(*) AS total FROM cves c LEFT JOIN triage t ON t.cve_id=c.id WHERE {where}', params)[0]['total']


def advisories(search='', vendor='', product='', severity='', state='inbox', limit=50, offset=0, scope='all'):
    where, params = _where(search, vendor, product, severity, state, scope)
    return rows(f'''SELECT c.id,c.description,c.severity,c.published,c.modified,c.products,
        CASE WHEN t.completed_at IS NOT NULL THEN 'reviewed'
             WHEN t.rule_ids IS NOT NULL THEN 'auto_archived' ELSE 'inbox' END AS state,
        CASE WHEN t.completed_at IS NOT NULL AND t.disposition IS NULL THEN 'completed'
             ELSE t.disposition END AS disposition,
        COALESCE(t.notes,'') AS notes,t.completed_at,t.reviewed_modified,t.rule_ids,
        t.reason,t.evaluated_at,
        CASE WHEN t.reviewed_modified IS NOT NULL AND c.modified != t.reviewed_modified THEN 1 ELSE 0 END AS changed_since_review
        FROM cves c LEFT JOIN triage t ON t.cve_id=c.id WHERE {where}
        ORDER BY c.published DESC,c.id DESC LIMIT ? OFFSET ?''',
        (*params, min(max(int(limit), 1), 5000), max(int(offset), 0)))

def advisory_detail(cve_id):
    data = rows('SELECT raw FROM cves WHERE id=?', (cve_id,))
    if not data:
        raise ValueError('Advisory not found')
    return json.loads(data[0]['raw']) if data[0]['raw'] else {}

def advisory_products(cve_id):
    return rows('SELECT vendor,product FROM advisory_products WHERE cve_id=? ORDER BY vendor,product', (cve_id,))


def export_csv(search='', vendor='', product='', severity='', state='all', scope='all'):
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(('CVE', 'Severity', 'Published', 'Modified', 'Vendor/Product', 'State', 'Disposition',
                     'Automatic rule IDs', 'Automatic reason', 'Notes', 'Completed'))
    offset = 0
    while True:
        batch = advisories(search, vendor, product, severity, state, 5000, offset, scope)
        for item in batch:
            fields = (item['id'], item['severity'], item['published'], item['modified'],
                      item['products'], item['state'], item['disposition'], item['rule_ids'], item['reason'],
                      item['notes'], item['completed_at'])
            writer.writerow([_csv_safe(field) for field in fields])
        offset += len(batch)
        if len(batch) < 5000:
            break
    return stream.getvalue()


def _csv_safe(value):
    value = str(value or '')
    return "'" + value if value.lstrip().startswith(('=', '+', '-', '@')) or value.startswith(('\t', '\r', '\n')) else value


def main():
    parser = argparse.ArgumentParser(description='Local NVD advisory inbox')
    parser.add_argument('--db', help='SQLite path')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('serve')
    sub.add_parser('sync')
    listing = sub.add_parser('inbox')
    listing.add_argument('--state', choices=['inbox', 'verified', 'reviewed', 'auto_archived', 'all'], default='inbox')
    listing.add_argument('--search', default='')
    sub.add_parser('coverage')
    add = sub.add_parser('add-coverage'); add.add_argument('vendor')
    sub.add_parser('rules')
    rule = sub.add_parser('add-rule'); rule.add_argument('kind', choices=['exclude', 'baseline'])
    rule.add_argument('vendor'); rule.add_argument('product'); rule.add_argument('--branch', default='')
    rule.add_argument('--minimum-version', default=''); rule.add_argument('--reason', default='')
    disable = sub.add_parser('disable-rule'); disable.add_argument('id', type=int)
    remove = sub.add_parser('delete-rule'); remove.add_argument('id', type=int)
    export = sub.add_parser('export'); export.add_argument('--state', choices=['inbox', 'verified', 'reviewed', 'auto_archived', 'all'], default='all')
    export.add_argument('--search', default=''); export.add_argument('--vendor', default='')
    export.add_argument('--product', default=''); export.add_argument('--severity', default='')
    args = parser.parse_args()
    global DB_PATH
    if args.db:
        DB_PATH = Path(args.db)
    initialize()
    if args.command == 'serve':
        from web import run
        run()
    elif args.command == 'sync':
        print(sync_advisories())
    elif args.command == 'inbox':
        print(json.dumps(advisories(search=args.search, state=args.state), indent=2))
    elif args.command == 'coverage':
        print(json.dumps(coverage(), indent=2))
    elif args.command == 'add-coverage':
        add_coverage(args.vendor)
    elif args.command == 'rules':
        print(json.dumps(rules_list(), indent=2))
    elif args.command == 'add-rule':
        print(add_rule(args.kind, args.vendor, args.product, args.branch, args.minimum_version, args.reason))
    elif args.command == 'disable-rule':
        set_rule_enabled(args.id, False)
    elif args.command == 'delete-rule':
        delete_rule(args.id)
    elif args.command == 'export':
        print(export_csv(args.search, args.vendor, args.product, args.severity, args.state), end='')


if __name__ == '__main__':
    main()
