"""Run with `python -m unittest test_fleetcves`."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fleetcves as app

NAME = 'cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*'
OTHER = 'cpe:2.3:a:example:widget:2.0:*:*:*:*:*:*:*'


class TrackerTest(unittest.TestCase):
    def test_sync_poll_and_triage_survive_refresh(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'DB_PATH', Path(directory) / 'data.db'):
            calls = []

            def nvd(endpoint, params):
                calls.append((endpoint, params))
                if endpoint == 'cpes/2.0':
                    products = [{'cpe': {'cpeName': name, 'lastModified': '2026-01-01T00:00:00.000',
                                         'titles': [{'lang': 'en', 'title': 'Example Widget'}]}}
                                for name in (NAME, OTHER)]
                    return {'products': products, 'totalResults': 2}
                return {'vulnerabilities': [{'cve': {
                    'id': 'CVE-2026-1234', 'lastModified': '2026-01-01T00:00:00.000',
                    'published': '2026-01-01T00:00:00.000',
                    'descriptions': [{'lang': 'en', 'value': 'A serious issue'}],
                    'metrics': {'cvssMetricV31': [{'cvssData': {'baseSeverity': 'HIGH'}}]}
                }}], 'totalResults': 1}

            with patch.object(app, 'request', side_effect=nvd):
                self.assertEqual(app.sync_cpes(), 2)
                self.assertEqual(app.sync_cpes(), 2)
                self.assertIn('lastModStartDate', calls[-1][1])
                app.track(NAME)
                app.track(OTHER)
                app.poll(NAME)
                app.poll(OTHER)
                app.add_status('risk accepted')
                app.set_status(NAME, 'CVE-2026-1234', 'risk accepted')
                app.poll(NAME)
                self.assertEqual(len(app.findings()), 2)
                self.assertEqual(next(f['status'] for f in app.findings() if f['cpe_name'] == NAME), 'risk accepted')
                app.set_in_use(OTHER, False)
                self.assertEqual([f['cpe_name'] for f in app.findings()], [NAME])
                self.assertEqual(app.catalog('widget')[0]['tracked'], 1)
                self.assertEqual(app.catalog_count('widget'), 2)
                self.assertEqual([row['name'] for row in app.catalog('widget', 1, 1)], [OTHER])
                with self.assertRaises(ValueError):
                    app.set_status(NAME, 'CVE-2026-1234', 'unknown')


if __name__ == '__main__':
    unittest.main()
