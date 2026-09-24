"""End-to-end advisory store tests using NVD-shaped fixtures, without live requests."""
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fleetcves as app


def match(product='router', **versions):
    return {'vulnerable': True, 'criteria': f'cpe:2.3:o:acme:{product}:*:*:*:*:*:*:*:*', **versions}


def advisory(ident='CVE-2026-1234', matches=None, modified='2026-01-01T00:00:00.000Z', description='An issue'):
    if matches is None:
        matches = [match()]
    return {'id': ident, 'lastModified': modified, 'published': '2026-01-01T00:00:00.000Z',
            'descriptions': [{'lang': 'en', 'value': description}],
            'metrics': {'cvssMetricV31': [{'cvssData': {'baseSeverity': 'HIGH'}}]},
            'configurations': [{'nodes': [{'operator': 'OR', 'cpeMatch': matches}]}]}


class AdvisoryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        original = app.DB_PATH
        app.DB_PATH = Path(self.temp.name) / 'data.db'
        self.addCleanup(setattr, app, 'DB_PATH', original)
        app.initialize()

    def sync(self, *records):
        with patch.object(app, 'request', return_value={'vulnerabilities': [{'cve': c} for c in records], 'totalResults': len(records)}):
            return app.sync_advisories()

    def test_ingestion_idempotent_and_manual_work_survives_refresh(self):
        cve = advisory()
        self.assertEqual(self.sync(cve), 1)
        app.set_notes(cve['id'], 'investigating')
        app.set_complete(cve['id'], True)
        self.assertEqual(self.sync(cve), 1)
        updated = advisory(matches=[match('changed')], modified='2026-02-01T00:00:00.000Z')
        self.sync(updated)
        entry = app.advisories(state='completed')[0]
        self.assertEqual(app.advisory_count(state='all'), 1)
        self.assertEqual(entry['notes'], 'investigating')
        self.assertEqual(entry['state'], 'completed')
        self.assertEqual(entry['changed_since_review'], 1)
        self.assertIn('changed', entry['products'])

    def test_failure_keeps_prior_successful_cursor_and_rows(self):
        self.sync(advisory())
        before = app.rows("SELECT value FROM metadata WHERE key='advisory_cursor'")[0]['value']
        with patch.object(app, 'request', side_effect=RuntimeError('network down')):
            with self.assertRaisesRegex(RuntimeError, 'network down'):
                app.sync_advisories()
        self.assertEqual(app.rows("SELECT value FROM metadata WHERE key='advisory_cursor'")[0]['value'], before)
        self.assertEqual(app.advisory_count(state='all'), 1)

    def test_multi_page_failure_preserves_cursor_and_prior_advisory(self):
        self.sync(advisory())
        before = app.rows("SELECT value FROM metadata WHERE key='advisory_cursor'")[0]['value']
        def page(endpoint, params):
            if params['startIndex']:
                raise RuntimeError('second page failed')
            return {'vulnerabilities': [{'cve': advisory('CVE-2026-9876')}], 'totalResults': 2}
        with patch.object(app, 'request', side_effect=page):
            with self.assertRaisesRegex(RuntimeError, 'second page'):
                app.sync_advisories()
        self.assertEqual(app.rows("SELECT value FROM metadata WHERE key='advisory_cursor'")[0]['value'], before)
        self.assertEqual(app.advisory_count(state='all'), 2)

    def test_exclusions_require_every_product_and_change_reopens(self):
        cve = advisory(matches=[match('router'), match('switch')])
        self.sync(cve)
        router = app.add_rule('exclude', 'acme', 'router', reason='Not deployed')
        self.assertEqual(app.advisory_count(), 1)
        switch = app.add_rule('exclude', 'acme', 'switch', reason='Not deployed')
        entry = app.advisories(state='auto_archived')[0]
        self.assertEqual(json.loads(entry['rule_ids']), [router, switch])
        self.assertIn('Not deployed', entry['reason'])
        app.set_rule_enabled(switch, False)
        self.assertEqual(app.advisory_count(), 1)
        app.set_rule_enabled(switch, True)
        app.delete_rule(router)
        self.assertEqual(app.advisory_count(), 1)

    def test_source_correction_reopens_automatic_archive(self):
        self.sync(advisory())
        app.add_rule('exclude', 'acme', 'router', reason='Not deployed')
        self.assertEqual(app.advisory_count(state='auto_archived'), 1)
        self.sync(advisory(matches=[match('router'), match('switch')], modified='2026-02-01T00:00:00.000Z'))
        self.assertEqual(app.advisory_count(), 1)
        self.assertIsNone(app.advisories()[0]['rule_ids'])


    def test_baseline_only_archives_below_boundary_and_manual_wins(self):
        below = advisory(matches=[match(versionStartIncluding='17.6.0', versionEndExcluding='17.6.4')])
        overlap = advisory('CVE-2026-0002', [match(versionEndIncluding='17.6.6')])
        unknown = advisory('CVE-2026-0003', [match(versionEndExcluding='17.6.4b')])
        self.sync(below, overlap, unknown)
        app.add_rule('baseline', 'acme', 'router', branch='17.6', minimum_version='17.6.6')
        self.assertEqual([x['id'] for x in app.advisories(state='auto_archived')], [below['id']])
        self.assertEqual(app.advisory_count(), 2)
        app.set_complete(below['id'], True)
        app.delete_rule(1)
        self.assertEqual(app.advisories(state='completed')[0]['state'], 'completed')
        app.set_complete(below['id'], False)
        self.assertEqual(app.advisory_count(), 3)

    def test_export_filters_and_neutralizes_spreadsheet_formulas(self):
        self.sync(advisory(description='=HYPERLINK("bad")'), advisory('CVE-2026-0002', [match('switch')]))
        app.set_notes('CVE-2026-1234', '  @SUM(A1)')
        result = list(csv.DictReader(io.StringIO(app.export_csv(product='router', state='inbox'))))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['CVE'], 'CVE-2026-1234')
        self.assertEqual(result[0]['Notes'], "'  @SUM(A1)")
        self.assertEqual(result[0]['State'], 'inbox')

    def test_coverage_and_vendor_product_filters_use_cpe_fields(self):
        other = advisory('CVE-2026-0002', [{'vulnerable': True, 'criteria': 'cpe:2.3:a:other:acme_router:*:*:*:*:*:*:*:*'}])
        self.sync(advisory(), other)
        app.add_coverage('acme')
        self.assertEqual([r['id'] for r in app.advisories(vendor='acme')], ['CVE-2026-1234'])
        self.assertEqual(app.advisory_count(vendor='acme', product='acme_router'), 0)
        self.assertEqual(app.advisory_count(scope='covered'), 1)
        self.assertEqual(app.advisory_count(scope='all'), 2)
        app.remove_coverage('acme')
        self.assertEqual(app.advisory_count(scope='covered'), 0)

    def test_source_correction_reindexes_pairs_and_preserves_unmapped(self):
        self.sync(advisory())
        self.sync(advisory(matches=[{'vulnerable': True, 'criteria': 'cpe:2.3:a:other:router:*:*:*:*:*:*:*:*'}],
                           modified='2026-02-01T00:00:00.000Z'))
        self.assertEqual(app.advisory_count(vendor='acme'), 0)
        self.assertEqual(app.advisory_count(vendor='other', product='router'), 1)
        self.sync(advisory(matches=[], modified='2026-03-01T00:00:00.000Z'))
        self.assertEqual(app.advisory_count(scope='unmapped'), 1)
        self.assertEqual(app.advisory_count(vendor='other'), 0)


    def test_existing_raw_advisories_are_backfilled_once(self):
        cve = advisory()
        with app.database() as db:
            db.execute("DELETE FROM metadata WHERE key='advisory_products_v1'")
            db.execute('INSERT INTO cves(id,description,raw) VALUES (?,?,?)', (cve['id'], 'legacy', json.dumps(cve)))
        app.initialize()
        app.initialize()
        self.assertEqual(app.advisory_count(vendor='acme', product='router', state='all'), 1)
        self.assertEqual(app.advisory_detail(cve['id'])['configurations'], cve['configurations'])


    def test_legacy_database_preserves_status_and_original_tables(self):
        with app.database() as db:
            db.execute('CREATE TABLE cpes (name TEXT PRIMARY KEY)')
            db.execute('CREATE TABLE findings (cpe_name TEXT, cve_id TEXT, status TEXT)')
            db.execute("INSERT INTO cves(id,description) VALUES ('CVE-2026-1234','legacy')")
            db.execute("INSERT INTO findings VALUES ('legacy:router','CVE-2026-1234','patched')")
        app.initialize()
        app.initialize()
        self.assertIn('patched', app.advisories()[0]['notes'])
        self.assertEqual(app.rows('SELECT COUNT(*) AS n FROM findings')[0]['n'], 1)


if __name__ == '__main__':
    unittest.main()
