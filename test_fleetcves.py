"""End-to-end advisory store tests using NVD-shaped fixtures, without live requests."""
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fleetcves as app
import web


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

    def test_cvss_v2_severity_is_available_to_filters(self):
        older = advisory()
        older['metrics'] = {'cvssMetricV2': [{'cvssData': {'baseScore': 7.5}, 'baseSeverity': 'HIGH'}]}
        newer = advisory('CVE-2026-0002')
        newer['metrics']['cvssMetricV2'] = [{'cvssData': {'baseScore': 4.0}, 'baseSeverity': 'MEDIUM'}]
        self.sync(older, newer)
        self.assertEqual(app.advisory_count(severity='HIGH', state='all'), 2)

    def test_existing_cvss_v2_advisory_severity_is_backfilled(self):
        cve = advisory()
        cve['metrics'] = {'cvssMetricV2': [{'cvssData': {'baseScore': 7.5}, 'baseSeverity': 'HIGH'}]}
        with app.database() as db:
            db.execute("DELETE FROM metadata WHERE key='cvss_v2_severity_v1'")
            db.execute('INSERT INTO cves(id,description,raw) VALUES (?,?,?)',
                       (cve['id'], 'legacy', json.dumps(cve)))
        app.initialize()
        self.assertEqual(app.advisory_count(severity='HIGH', state='all'), 1)

    def test_ingestion_idempotent_and_manual_work_survives_refresh(self):
        cve = advisory()
        self.assertEqual(self.sync(cve), 1)
        app.set_notes(cve['id'], 'investigating')
        app.set_disposition(cve['id'], 'resolved')
        self.assertEqual(self.sync(cve), 1)
        updated = advisory(matches=[match('changed')], modified='2026-02-01T00:00:00.000Z')
        self.sync(updated)
        entry = app.advisories(state='reviewed')[0]
        self.assertEqual(app.advisory_count(state='all'), 1)
        self.assertEqual(entry['notes'], 'investigating')
        self.assertEqual(entry['disposition'], 'resolved')
        self.assertEqual(entry['changed_since_review'], 1)
        self.assertIn('changed', entry['products'])

    def test_initial_import_resumes_after_failed_page(self):
        first = {'vulnerabilities': [{'cve': advisory()}], 'totalResults': 2}
        with patch.object(app, 'request', side_effect=[first, RuntimeError('second page failed')]):
            with self.assertRaisesRegex(RuntimeError, 'second page failed'):
                app.sync_advisories()
        seen = []
        def resumed(endpoint, params):
            if 'lastModStartDate' in params:
                return {'vulnerabilities': [], 'totalResults': 0}
            seen.append(params['startIndex'])
            return {'vulnerabilities': [{'cve': advisory('CVE-2026-5678')}], 'totalResults': 2}
        with patch.object(app, 'request', side_effect=resumed):
            self.assertEqual(app.sync_advisories(), 1)
        self.assertEqual(seen, [1])
        self.assertEqual(app.advisory_count(state='all'), 2)

    def test_completed_update_window_is_not_replayed_after_failure(self):
        original = (app.datetime.now(app.timezone.utc) - app.timedelta(days=250)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        with app.database() as db:
            db.execute("INSERT INTO metadata VALUES ('advisory_cursor', ?)", (original,))
        starts = []
        def interrupted(endpoint, params):
            starts.append(params['lastModStartDate'])
            if len(starts) == 2:
                raise RuntimeError('second window failed')
            return {'vulnerabilities': [], 'totalResults': 0}
        with patch.object(app, 'request', side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError, 'second window failed'):
                app.sync_advisories()
        checkpoint = app.rows("SELECT value FROM metadata WHERE key='advisory_cursor'")[0]['value']
        self.assertGreater(checkpoint, original)
        resumed = []
        def finish(endpoint, params):
            resumed.append(params['lastModStartDate'])
            return {'vulnerabilities': [], 'totalResults': 0}
        with patch.object(app, 'request', side_effect=finish):
            app.sync_advisories()
        self.assertEqual(resumed[0], starts[1])
        self.assertNotIn(starts[0], resumed)

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

    def test_new_exclusion_retroactively_archives_nested_existing_advisory(self):
        cve = advisory()
        cve['configurations'][0]['nodes'] = [{'operator': 'AND', 'children': [
            {'operator': 'OR', 'cpeMatch': [match()]},
            {'operator': 'OR', 'cpeMatch': [{'vulnerable': False, 'criteria': 'cpe:2.3:o:acme:platform:*:*:*:*:*:*:*:*'}]},
        ]}]
        self.sync(cve)
        self.assertEqual(app.advisory_count(), 1)
        ident = app.add_rule('exclude', 'acme', 'router', reason='Not deployed')
        self.assertEqual(app.advisories(state='auto_archived')[0]['rule_ids'], json.dumps([ident]))
        app.set_rule_enabled(ident, False)
        self.assertEqual(app.advisory_count(), 1)


    def test_source_correction_reopens_automatic_archive(self):
        self.sync(advisory())
        app.add_rule('exclude', 'acme', 'router', reason='Not deployed')
        self.assertEqual(app.advisory_count(state='auto_archived'), 1)
        self.sync(advisory(matches=[match('router'), match('switch')], modified='2026-02-01T00:00:00.000Z'))
        self.assertEqual(app.advisory_count(), 1)
        self.assertIsNone(app.advisories()[0]['rule_ids'])

    def test_manual_dispositions_survive_sync_and_override_rules(self):
        cve = advisory()
        self.sync(cve)
        app.set_disposition(cve['id'], 'verified')
        app.add_rule('exclude', 'acme', 'router', reason='Not deployed')
        self.assertEqual(app.advisories()[0]['disposition'], 'verified')
        self.sync(advisory(modified='2026-02-01T00:00:00.000Z'))
        self.assertEqual(app.advisories()[0]['changed_since_review'], 1)
        app.set_disposition(cve['id'], 'not_applicable')
        self.assertEqual(app.advisories(state='reviewed')[0]['disposition'], 'not_applicable')
        app.set_disposition(cve['id'], 'resolved')
        self.assertEqual(app.advisories(state='reviewed')[0]['disposition'], 'resolved')
        app.set_disposition(cve['id'], None)
        self.assertEqual(app.advisories(state='auto_archived')[0]['disposition'], None)


    def test_baseline_only_archives_below_boundary_and_manual_wins(self):
        below = advisory(matches=[match(versionStartIncluding='17.6.0', versionEndExcluding='17.6.4')])
        overlap = advisory('CVE-2026-0002', [match(versionEndIncluding='17.6.6')])
        unknown = advisory('CVE-2026-0003', [match(versionEndExcluding='17.6.4b')])
        self.sync(below, overlap, unknown)
        app.add_rule('baseline', 'acme', 'router', branch='17.6', minimum_version='17.6.6')
        self.assertEqual([x['id'] for x in app.advisories(state='auto_archived')], [below['id']])
        self.assertEqual(app.advisory_count(), 2)
        app.set_disposition(below['id'], 'resolved')
        app.delete_rule(1)
        self.assertEqual(app.advisories(state='reviewed')[0]['disposition'], 'resolved')
        app.set_disposition(below['id'], None)
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


    def test_legacy_completed_record_is_not_relabelled_as_resolved(self):
        self.sync(advisory())
        with app.database() as db:
            db.execute('UPDATE triage SET completed_at=?,reviewed_modified=? WHERE cve_id=?', (app.now(), '2026-01-01T00:00:00.000Z', 'CVE-2026-1234'))
            db.execute('ALTER TABLE triage DROP COLUMN disposition')
        app.initialize()
        item = app.advisories(state='reviewed')[0]
        self.assertEqual(item['disposition'], 'completed')
        app.set_disposition(item['id'], None)
        self.assertEqual(app.advisory_count(), 1)

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


class PresentationTest(unittest.TestCase):
    def test_product_and_rule_summaries_keep_decision_context(self):
        self.assertEqual(web.product_summary('cisco/ios_xe, hpe/server'), 'cisco · ios xe +1 more')
        self.assertEqual(web.product_summary(''), 'No NVD product mapping')
        self.assertEqual(web.rule_summary({'kind': 'exclude', 'vendor': 'cisco', 'product': 'unused_ap', 'reason': 'No access points'}),
                         'Product not deployed · cisco / unused_ap · No access points')
        self.assertEqual(web.rule_summary({'kind': 'baseline', 'vendor': 'cisco', 'product': 'ios_xe', 'branch': '17.6', 'minimum_version': '17.6.6'}),
                         'Minimum deployed version · cisco / ios_xe · branch 17.6 · ≥ 17.6.6')
        self.assertEqual(web.readable_date('2026-09-18T10:00:00.000Z'), 'Sep 18, 2026')


if __name__ == '__main__':
    unittest.main()
