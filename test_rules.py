"""Focused behavioral checks for conservative advisory rules."""

import unittest

from rules import evaluate


def cpe(product='widget', version='1.4', vendor='acme'):
    return f'cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*'


def advisory(*entries, operator='OR', negate=False, children=None):
    node = {'operator': operator, 'negate': negate, 'cpeMatch': list(entries)}
    if children is not None:
        node['children'] = children
    return {'configurations': [{'nodes': [node]}]}


def match(criteria, **bounds):
    return {'vulnerable': True, 'criteria': criteria, **bounds}


def rule(identifier, kind='exclude', **fields):
    return {'id': identifier, 'kind': kind, 'vendor': 'acme', 'product': 'widget',
            'enabled': True, **fields}


class EvaluateTest(unittest.TestCase):
    def test_exclusion_parses_cpe_and_covers_all_products(self):
        cve = advisory(match(cpe()), match(cpe(r'widget\:pro')))
        rules = [rule(8, product='widget'), rule(9, product='widget:pro', reason='Retired')]
        ids, reason = evaluate(cve, rules)
        self.assertEqual(ids, [8, 9])
        self.assertIn('#8', reason)
        self.assertIn('#9', reason)
        self.assertIn('Retired', reason)

    def test_uncovered_or_alternative_stays_inbox(self):
        self.assertIsNone(evaluate(advisory(match(cpe()), match(cpe('other'))), [rule(1)]))

    def test_baseline_covers_only_numeric_versions_below_branch_floor(self):
        baseline = rule(3, 'baseline', branch='1.2', minimum_version='1.2.5')
        explanation = evaluate(advisory(match(cpe(version='1.2.4'))), [baseline])
        self.assertEqual(explanation[0], [3])
        self.assertIn('baseline', explanation[1])
        self.assertIn('1.2.4', explanation[1])
        self.assertIsNone(evaluate(advisory(match(cpe(version='1.2.5'))), [baseline]))
        self.assertIsNone(evaluate(advisory(match(cpe(version='1.2.4-rc1'))), [baseline]))

    def test_baseline_ranges_need_a_safe_branch_and_upper_boundary(self):
        baseline = rule(4, 'baseline', branch='17.6', minimum_version='17.6.6')
        covered = advisory(match(cpe(version='*'), versionStartIncluding='17.6.0', versionEndExcluding='17.6.4'))
        ids, reason = evaluate(covered, [baseline])
        self.assertEqual(ids, [4])
        self.assertIn('rule #4 baseline', reason)
        self.assertIn('<17.6.4', reason)
        self.assertIn('17.6.6', reason)
        self.assertIsNone(evaluate(advisory(match(cpe(version='*'), versionEndExcluding='17.6.4')), [baseline]))
        self.assertIsNone(evaluate(advisory(match(cpe(version='*'), versionEndIncluding='17.6.6')), [baseline]))
        self.assertIsNone(evaluate(advisory(match(cpe(version='*'), versionEndIncluding='18.0')), [baseline]))
        self.assertIsNone(evaluate(advisory(match(cpe(version='*'), versionStartIncluding='17.5.0', versionEndIncluding='17.6.4')), [baseline]))

    def test_disabled_and_complex_or_unsupported_configurations_stay_inbox(self):
        self.assertIsNone(evaluate(advisory(match(cpe())), [rule(1, enabled=False)]))
        for cve in (advisory(match(cpe()), operator='AND'),
                     advisory(match(cpe()), negate=True),
                     advisory(match(cpe()), children=[]),
                     {'configurations': [{'nodes': [{'operator': 'OR', 'cpeMatch': [
                         {'vulnerable': False, 'criteria': cpe()}]}]}]},
                     {'configurations': [{'nodes': [{'operator': 'OR', 'cpeMatch': [
                         {'vulnerable': True, 'criteria': 'not-a-cpe'}]}]}]}):
            self.assertIsNone(evaluate(cve, [rule(1)]))

    def test_missing_configuration_is_not_assumed_safe(self):
        self.assertIsNone(evaluate({}, [rule(1)]))


if __name__ == '__main__':
    unittest.main()
