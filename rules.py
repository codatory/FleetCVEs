"""Conservative advisory suppression rules for NVD configurations."""

import re


_NUMERIC = re.compile(r"[0-9]+(?:\.[0-9]+)*\Z")


def _cpe_parts(criteria):
    if not isinstance(criteria, str) or not criteria.startswith('cpe:2.3:'):
        return None
    fields, field, escaped = [], [], False
    for char in criteria:
        if escaped:
            field.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ':':
            fields.append(''.join(field))
            field.clear()
        else:
            field.append(char)
    if escaped:
        return None
    fields.append(''.join(field))
    return fields if len(fields) == 13 and fields[:2] == ['cpe', '2.3'] else None


def _version(value):
    if not isinstance(value, str) or not _NUMERIC.fullmatch(value):
        return None
    return tuple(map(int, value.split('.')))


def _compare(left, right):
    size = max(len(left), len(right))
    left, right = left + (0,) * (size - len(left)), right + (0,) * (size - len(right))
    return (left > right) - (left < right)


def _branch_contains(version, branch):
    branch = _version(branch)
    return bool(branch and len(version) >= len(branch) and version[:len(branch)] == branch)


def _baseline_covers(match, parts, rule):
    branch = rule.get('branch', '')
    branch_version = _version(branch)
    minimum = _version(rule.get('minimum_version', ''))
    if not branch_version or minimum is None or not _branch_contains(minimum, branch):
        return False
    start, start_exclusive = match.get('versionStartIncluding'), match.get('versionStartExcluding')
    end, end_exclusive = match.get('versionEndIncluding'), match.get('versionEndExcluding')
    if (start and start_exclusive) or (end and end_exclusive):
        return False
    exact = match.get('version') or parts[5]
    lower = _version(start or start_exclusive or exact)
    upper = _version(end or end_exclusive or exact)
    # Without an explicit lower bound, an upper-only range may include older branches.
    if lower is None or upper is None or not _branch_contains(lower, branch) or not _branch_contains(upper, branch):
        return False
    if _compare(lower, upper) > 0:
        return False
    comparison = _compare(upper, minimum)
    return comparison < 0 or (comparison == 0 and bool(end_exclusive))


def _matches_product(parts, rule):
    vendor, product = parts[3:5]
    return (vendor not in ('*', '-') and product not in ('*', '-')
            and vendor.casefold() == str(rule.get('vendor', '')).casefold()
            and product.casefold() == str(rule.get('product', '')).casefold())


def _vulnerable_matches(cve):
    """Collect every affected product, including nested AND/OR context."""
    configurations = cve.get('configurations')
    if not isinstance(configurations, list) or not configurations:
        return None
    matches = []

    def visit(node):
        if (not isinstance(node, dict) or node.get('operator') not in ('AND', 'OR')
                or node.get('negate', False) is not False):
            return False
        entries, children = node.get('cpeMatch', []), node.get('children', [])
        if (not isinstance(entries, list) or not isinstance(children, list)
                or not (entries or children)):
            return False
        for entry in entries:
            if not isinstance(entry, dict) or type(entry.get('vulnerable')) is not bool:
                return False
            if entry['vulnerable'] is False:
                continue
            parts = _cpe_parts(entry.get('criteria'))
            if parts is None or parts[2] not in ('a', 'o', 'h'):
                return False
            matches.append((entry, parts))
        return all(visit(child) for child in children)

    for configuration in configurations:
        if not isinstance(configuration, dict) or not isinstance(configuration.get('nodes'), list) or not configuration['nodes']:
            return None
        before = len(matches)
        if not all(visit(node) for node in configuration['nodes']) or len(matches) == before:
            return None
    return matches


def _affected_range(match, parts):
    start = match.get('versionStartIncluding') or match.get('versionStartExcluding')
    end = match.get('versionEndIncluding') or match.get('versionEndExcluding')
    if start or end:
        lower = ('>' if match.get('versionStartExcluding') else '≥') + (start or '') if start else 'branch start'
        upper = ('<' if match.get('versionEndExcluding') else '≤') + (end or '') if end else 'unbounded'
        return f'{lower} through {upper}'
    return f'version {parts[5]}'


def evaluate(cve: dict, rules: list[dict]) -> tuple[list[int], str] | None:
    """Return rule ids and reasons only when every vulnerable match is safely excluded."""
    matches = _vulnerable_matches(cve)
    if matches is None:
        return None
    applied, explanations = [], []
    for match, parts in matches:
        covered = None
        for rule in rules:
            if not rule.get('enabled', True) or rule.get('kind') not in ('exclude', 'baseline'):
                continue
            if not _matches_product(parts, rule):
                continue
            if rule['kind'] == 'baseline' and not _baseline_covers(match, parts, rule):
                continue
            try:
                rule_id = int(rule['id'])
            except (KeyError, TypeError, ValueError):
                continue
            covered = rule, rule_id
            break
        if covered is None:
            return None
        rule, rule_id = covered
        if rule_id not in applied:
            applied.append(rule_id)
        product = f"{parts[3]}/{parts[4]}"
        if rule['kind'] == 'baseline':
            text = (f"rule #{rule_id} baseline for {product}, branch {rule.get('branch')} "
                    f"(minimum {rule.get('minimum_version')}), affected {_affected_range(match, parts)}")
        else:
            text = f"rule #{rule_id} exclude for {product}, affected {_affected_range(match, parts)}"
        reason = str(rule.get('reason') or '').strip()
        if reason:
            text += f': {reason}'
        if text not in explanations:
            explanations.append(text)
    return applied, '; '.join(explanations)
