"""NiceGUI advisory inbox and localhost JSON API for FleetCVEs."""
import asyncio
import logging
import os
from urllib.parse import urlencode

from fastapi import HTTPException
from fastapi.responses import Response
from nicegui import app, ui
from pydantic import BaseModel

import fleetcves as store

log = logging.getLogger(__name__)
sync_state = 'Waiting for NVD sync'
_sync_task = None


class Enabled(BaseModel):
    enabled: bool


class Coverage(BaseModel):
    vendor: str


class Rule(BaseModel):
    kind: str
    vendor: str
    product: str
    branch: str = ''
    minimum_version: str = ''
    reason: str = ''


class Notes(BaseModel):
    notes: str


class Disposition(BaseModel):
    disposition: str | None


def apply(fn, *args):
    try:
        return fn(*args)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get('/api/advisories')
def api_advisories(search: str = '', vendor: str = '', product: str = '', severity: str = '', state: str = 'inbox', limit: int = 50, offset: int = 0, scope: str = 'all'):
    return apply(store.advisories, search, vendor, product, severity, state, limit, offset, scope)


@app.get('/api/advisories/count')
def api_advisory_count(search: str = '', vendor: str = '', product: str = '', severity: str = '', state: str = 'inbox', scope: str = 'all'):
    return {'total': apply(store.advisory_count, search, vendor, product, severity, state, scope)}

@app.get('/api/advisories/{cve_id}')
def api_advisory_detail(cve_id: str):
    return apply(store.advisory_detail, cve_id)


@app.put('/api/advisories/{cve_id}/notes')
def api_notes(cve_id: str, data: Notes):
    apply(store.set_notes, cve_id, data.notes)
    return {'ok': True}


@app.put('/api/advisories/{cve_id}/disposition')
def api_disposition(cve_id: str, data: Disposition):
    apply(store.set_disposition, cve_id, data.disposition)
    return {'ok': True}


@app.get('/api/coverage')
def api_coverage():
    return store.coverage()


@app.post('/api/coverage', status_code=201)
def api_add_coverage(data: Coverage):
    apply(store.add_coverage, data.vendor)
    return {'ok': True}


@app.delete('/api/coverage/{vendor:path}')
def api_remove_coverage(vendor: str):
    apply(store.remove_coverage, vendor)
    return {'ok': True}


@app.get('/api/rules')
def api_rules():
    return store.rules_list()


@app.post('/api/rules', status_code=201)
def api_add_rule(data: Rule):
    return {'id': apply(store.add_rule, data.kind, data.vendor, data.product, data.branch, data.minimum_version, data.reason)}


@app.put('/api/rules/{rule_id}/enabled')
def api_rule_enabled(rule_id: int, data: Enabled):
    apply(store.set_rule_enabled, rule_id, data.enabled)
    return {'ok': True}


@app.delete('/api/rules/{rule_id}')
def api_delete_rule(rule_id: int):
    apply(store.delete_rule, rule_id)
    return {'ok': True}


@app.get('/api/export')
@app.get('/api/export.csv')
def api_export_csv(search: str = '', vendor: str = '', product: str = '', severity: str = '', state: str = 'all', scope: str = 'all'):
    return Response(apply(store.export_csv, search, vendor, product, severity, state, scope), media_type='text/csv; charset=utf-8',
                    headers={'Content-Disposition': 'attachment; filename="advisories.csv"'})


async def run_sync():
    global sync_state, _sync_task
    if _sync_task and not _sync_task.done():
        return

    def progress(*args):
        global sync_state
        sync_state = f'Syncing NVD advisories ({args[0]:,} processed)…' if args and isinstance(args[0], int) else 'Syncing NVD advisories…'

    async def work():
        global sync_state
        sync_state = 'Syncing NVD advisories…'
        try:
            count = await asyncio.to_thread(store.sync_advisories, progress)
            sync_state = f'Advisories synced ({count:,}); last sync {store.now()}'
        except Exception as exc:
            sync_state = f'NVD sync failed: {exc}'
            log.exception('Advisory sync failed')

    _sync_task = asyncio.create_task(work())


async def sync_worker():
    while True:
        await run_sync()
        if _sync_task:
            await _sync_task
        await asyncio.sleep(3600)


@app.post('/api/sync')
async def api_sync():
    await run_sync()
    return {'ok': True, 'state': sync_state}


@app.get('/api/sync')
def api_sync_status():
    return {'state': sync_state}


@app.on_startup
async def startup():
    store.initialize()
    asyncio.create_task(sync_worker())


def change(action, refresh):
    try:
        action()
        refresh()
    except (ValueError, KeyError) as exc:
        ui.notify(str(exc), type='negative')

def show_nvd_detail(cve_id):
    cve = store.advisory_detail(cve_id)
    ui.label(f"NVD source: {cve.get('sourceIdentifier') or '—'} · Status: {cve.get('vulnStatus') or '—'}")
    for key, metrics in cve.get('metrics', {}).items():
        for metric in metrics:
            data = metric.get('cvssData', {})
            ui.label(f"{key}: {data.get('baseScore', '—')} {data.get('baseSeverity') or metric.get('baseSeverity') or ''} · {data.get('vectorString', '—')} ({metric.get('type', '—')})")
    for weakness in cve.get('weaknesses', []):
        ui.label('CWE: ' + ', '.join(d.get('value', '') for d in weakness.get('description', []) if d.get('lang') == 'en'))
    for configuration in cve.get('configurations', []):
        def show_node(node):
            ui.label(f"Configuration {node.get('operator', 'OR')}:" + (' NOT' if node.get('negate') else ''))
            for match in node.get('cpeMatch', []):
                bounds = ', '.join(f'{key}: {match[key]}' for key in ('versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding') if key in match)
                ui.label(f"{'Affected' if match.get('vulnerable') else 'Required context'}: {match.get('criteria', '—')}" + (f' · {bounds}' if bounds else ''))
            for child in node.get('children', []):
                show_node(child)
        for node in configuration.get('nodes', []):
            show_node(node)
    if not cve.get('configurations'):
        ui.label('No affected CPE configuration supplied by NVD.')
    for reference in cve.get('references', []):
        url = reference.get('url', '')
        if url.startswith(('https://', 'http://')):
            ui.link(url, url, new_tab=True).classes('break-all')

def load_nvd_detail(expansion, cve_id):
    expansion.clear()
    with expansion:
        show_nvd_detail(cve_id)



@ui.page('/')
def index():
    ui.page_title('FleetCVEs — Advisory inbox')
    ui.label('FleetCVEs').classes('text-3xl font-bold')
    with ui.row().classes('items-center gap-3'):
        ui.label().bind_text_from(globals(), 'sync_state').classes('text-sm text-gray-600')
        ui.button('Sync now', on_click=lambda: asyncio.create_task(run_sync())).props('outline')

    with ui.tabs().classes('w-full') as tabs:
        coverage_tab = ui.tab('Coverage')
        rules_tab = ui.tab('Rules')
        inbox_tab = ui.tab('Inbox')
        archive_tab = ui.tab('Archived / Reviewed')
    with ui.tab_panels(tabs, value=inbox_tab).classes('w-full'):
        with ui.tab_panel(coverage_tab):
            ui.label('Vendors you want monitored').classes('text-lg font-semibold')
            vendor_input = ui.input('Vendor').classes('w-80')

            @ui.refreshable
            def show_coverage():
                for item in store.coverage():
                    vendor = item['vendor'] if isinstance(item, dict) else item
                    with ui.row().classes('items-center gap-3 border-b py-2'):
                        ui.label(vendor).classes('flex-1')
                        ui.button('Remove', on_click=lambda _, v=vendor: change(lambda: store.remove_coverage(v), show_coverage.refresh)).props('flat color=negative')

            def add_vendor():
                change(lambda: store.add_coverage(vendor_input.value or ''), show_coverage.refresh)
                vendor_input.value = ''
            vendor_input.on('keydown.enter', lambda: add_vendor())
            ui.button('Add vendor', on_click=add_vendor)
            show_coverage()

        with ui.tab_panel(rules_tab):
            ui.label('Rules apply to a vendor/product across all advisories; they are not a per-CVE status. Only provably irrelevant advisories auto-archive. Start from an advisory to prefill its affected product.').classes('text-sm text-gray-600')
            with ui.row().classes('items-end gap-2 flex-wrap'):
                kind = ui.select({'exclude': 'Not deployed (exclude)', 'baseline': 'Minimum deployed version'}, value='exclude', label='Rule type').classes('w-56')
                rvendor = ui.input('NVD vendor').classes('w-40')
                rproduct = ui.input('NVD product').classes('w-40')
                branch = ui.input('Numeric branch (e.g. 17.6)').classes('w-48')
                minimum = ui.input('Minimum deployed version').classes('w-48')
                branch.set_visibility(False)
                minimum.set_visibility(False)
                kind.on_value_change(lambda e: (branch.set_visibility(e.value == 'baseline'), minimum.set_visibility(e.value == 'baseline')))
                reason = ui.input('Reason (required for not deployed)').classes('w-64')
                def add_rule():
                    change(lambda: store.add_rule(kind.value, rvendor.value or '', rproduct.value or '',
                                                  (branch.value or '') if kind.value == 'baseline' else '',
                                                  (minimum.value or '') if kind.value == 'baseline' else '', reason.value or ''),
                           lambda: (show_rules.refresh(), inbox_refresh(), archive_refresh()))
                ui.button('Add rule', on_click=add_rule)

            @ui.refreshable
            def show_rules():
                for rule in store.rules_list():
                    with ui.row().classes('w-full items-center gap-3 border-b py-2'):
                        ui.checkbox(value=bool(rule['enabled']), on_change=lambda e, rid=rule['id']: change(lambda: store.set_rule_enabled(rid, e.value), show_rules.refresh))
                        ui.label(f"{rule['kind']}: {rule['vendor']} / {rule['product']}" + (f" / {rule['branch']}" if rule['branch'] else '')).classes('flex-1')
                        if rule.get('minimum_version'):
                            ui.label(f"≥ {rule['minimum_version']}").classes('text-sm')
                        if rule.get('reason'):
                            ui.label(rule['reason']).classes('text-sm text-gray-600')
                        ui.label(f"{rule.get('archived_count', 0)} archived").classes('text-xs text-gray-500')
                        ui.button('Delete', on_click=lambda _, rid=rule['id']: change(lambda: store.delete_rule(rid), show_rules.refresh)).props('flat color=negative')
            show_rules()

        def advisory_panel(state_filter):
            with ui.row().classes('items-end gap-3 flex-wrap'):
                scope = ui.select({'covered': 'Monitored vendors', 'unmapped': 'No product mapping', 'all': 'All advisories'}, value='covered', label='View').classes('w-56')
                search = ui.input('Search advisories').props('clearable').classes('w-64')
                vendor = ui.input('Vendor').props('clearable').classes('w-40')
                product = ui.input('Product').props('clearable').classes('w-40')
                severity = ui.select(['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'], value='', label='Severity').classes('w-40')
                ui.button('Filter', on_click=lambda: (page.update(offset=0), show_items.refresh())).props('outline')
            page = {'offset': 0}
            def product_rule(cve_id):
                pairs = store.advisory_products(cve_id)
                with ui.dialog() as dialog, ui.card().classes('w-full max-w-lg'):
                    ui.label(f'Create product rule from {cve_id}').classes('text-lg font-semibold')
                    ui.label('Rules apply to this vendor/product across all advisories, not just this CVE. An advisory is archived only when every affected product is safely covered.').classes('text-sm')
                    pair = ui.select({i: f"{p['vendor']} / {p['product']}" for i, p in enumerate(pairs)}, value=0, label='Affected product').classes('w-full')
                    rule_kind = ui.select({'exclude': 'Not deployed (exclude)', 'baseline': 'Minimum deployed version'}, value='exclude', label='Rule type').classes('w-full')
                    rule_branch = ui.input('Numeric branch (e.g. 17.6)').classes('w-full')
                    rule_minimum = ui.input('Minimum deployed version (e.g. 17.6.6)').classes('w-full')
                    rule_branch.set_visibility(False)
                    rule_minimum.set_visibility(False)
                    rule_kind.on_value_change(lambda e: (rule_branch.set_visibility(e.value == 'baseline'), rule_minimum.set_visibility(e.value == 'baseline')))
                    rule_reason = ui.input('Reason (required for not deployed)').classes('w-full')
                    def save_rule():
                        selected = pairs[pair.value]
                        try:
                            store.add_rule(rule_kind.value, selected['vendor'], selected['product'],
                                           rule_branch.value or '' if rule_kind.value == 'baseline' else '',
                                           rule_minimum.value or '' if rule_kind.value == 'baseline' else '', rule_reason.value or '')
                        except ValueError as exc:
                            ui.notify(str(exc), type='negative')
                            return
                        dialog.close()
                        show_items.refresh()
                        show_rules.refresh()
                        ui.notify('Product rule saved')
                    with ui.row():
                        ui.button('Create rule', on_click=save_rule)
                        ui.button('Cancel', on_click=dialog.close).props('flat')
                dialog.open()

            @ui.refreshable
            def show_items():
                query = dict(search=search.value or '', vendor=vendor.value or '', product=product.value or '', severity=severity.value or '', state=state_filter, scope=scope.value, limit=50, offset=page['offset'])
                total = store.advisory_count(**{k: query[k] for k in ('search', 'vendor', 'product', 'severity', 'state', 'scope')})
                items = store.advisories(**query)
                with ui.row().classes('items-center gap-2'):
                    ui.label(f"{total:,} {'advisory' if total == 1 else 'advisories'}")
                    prev = ui.button('Previous', on_click=lambda: move(-50)).props('flat')
                    prev.set_visibility(page['offset'] > 0)
                    next_page = ui.button('Next', on_click=lambda: move(50)).props('flat')
                    next_page.set_visibility(page['offset'] + 50 < total)
                    csv_query = urlencode({k: v for k, v in query.items() if k not in ('limit', 'offset')})
                    ui.button('Export CSV', on_click=lambda: ui.download('/api/export?' + csv_query)).props('outline')
                if scope.value == 'covered':
                    if not store.coverage():
                        ui.label('No monitored vendors yet. Add vendors in Coverage to focus the inbox, or switch View to All advisories.').classes('text-orange-800')
                        ui.button('Set monitored vendors', on_click=lambda: tabs.set_value(coverage_tab)).props('outline')
                    else:
                        ui.label('Showing monitored vendors only. Other vendors and advisories without product mappings remain in All advisories / No product mapping.').classes('text-sm text-gray-600')
                if not items:
                    ui.label('No matching advisories.').classes('text-gray-600')
                for item in items:
                    with ui.column().classes('w-full border-b py-3 gap-1'):
                        with ui.row().classes('items-center gap-3'):
                            ui.link(item['id'], f"https://nvd.nist.gov/vuln/detail/{item['id']}", new_tab=True).classes('font-semibold')
                            ui.badge(item.get('severity') or 'UNRATED')
                            ui.label((item.get('disposition') or item.get('state') or '').replace('_', ' ').upper())
                            ui.label(f"Published {item.get('published') or '—'} · Modified {item.get('modified') or '—'}").classes('text-sm text-gray-600')
                            ui.label(item.get('products') or '').classes('text-sm text-gray-600')
                            if item.get('changed_since_review'):
                                ui.badge('Changed since review', color='orange')
                        ui.label(item.get('description') or '').classes('text-sm')
                        detail = ui.expansion('NVD details · CVSS, CWE, affected versions, references').classes('w-full')
                        detail.on_value_change(lambda e, cid=item['id'], exp=detail: load_nvd_detail(exp, cid) if e.value else None)
                        if item.get('rule_ids'):
                            ui.label(f"Rule IDs: {item.get('rule_ids') or '—'} · {item.get('reason') or ''} · Evaluated {item.get('evaluated_at') or '—'}").classes('text-xs text-gray-500')
                        with ui.row().classes('w-full items-center gap-2'):
                            notes = ui.input('Notes', value=item.get('notes') or '').classes('flex-1')
                            ui.button('Save notes', on_click=lambda _, cid=item['id'], field=notes: change(lambda: store.set_notes(cid, field.value or ''), show_items.refresh)).props('flat')
                            for label, disposition in (('N/A', 'not_applicable'), ('Verified', 'verified'), ('Resolved', 'resolved')):
                                if item.get('disposition') != disposition:
                                    ui.button(label, on_click=lambda _, cid=item['id'], value=disposition: change(lambda: store.set_disposition(cid, value), show_items.refresh)).props('outline')
                            if item.get('disposition'):
                                ui.button('Reopen', on_click=lambda _, cid=item['id']: change(lambda: store.set_disposition(cid, None), show_items.refresh)).props('flat')
                            if item.get('products'):
                                ui.button('Create product rule', on_click=lambda _, cid=item['id']: product_rule(cid)).props('flat')

            def move(delta):
                page['offset'] = max(0, page['offset'] + delta)
                show_items.refresh()
            for field in (search, vendor, product):
                field.on('keydown.enter', lambda: (page.update(offset=0), show_items.refresh()))
            severity.on_value_change(lambda _: (page.update(offset=0), show_items.refresh()))
            scope.on_value_change(lambda _: (page.update(offset=0), show_items.refresh()))
            show_items()
            ui.timer(30, show_items.refresh)
            return show_items.refresh

        with ui.tab_panel(inbox_tab):
            inbox_refresh = advisory_panel('inbox')
        with ui.tab_panel(archive_tab):
            with ui.tabs().classes('w-full') as archived_tabs:
                archived = ui.tab('Archived')
                completed = ui.tab('Reviewed')
            with ui.tab_panels(archived_tabs, value=archived).classes('w-full'):
                with ui.tab_panel(archived):
                    archive_refresh = advisory_panel('auto_archived')
                with ui.tab_panel(completed):
                    completed_refresh = advisory_panel('reviewed')
    tabs.on_value_change(lambda _: (inbox_refresh(), archive_refresh(), completed_refresh(), show_rules.refresh()))
    archived_tabs.on_value_change(lambda _: (archive_refresh(), completed_refresh()))


def run():
    store.initialize()
    ui.run(host='127.0.0.1', port=int(os.environ.get('FLEETCVES_PORT', 8080)), reload=False, show=False)
