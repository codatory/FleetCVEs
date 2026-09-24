"""NiceGUI advisory inbox and localhost JSON API for FleetCVEs."""
import asyncio
import json
from datetime import datetime
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

    def progress(total, index, count):
        global sync_state
        sync_state = f'Syncing NVD advisories · {index:,}/{count:,} in current window · {total:,} processed this run'

    async def work():
        global sync_state
        sync_state = 'Syncing NVD advisories…'
        try:
            count = await asyncio.to_thread(store.sync_advisories, progress)
            sync_state = f'NVD updated {store.now()[11:16]} UTC · {count:,} records checked'
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


def readable_date(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).strftime('%b %d, %Y').replace(' 0', ' ') if value else '—'


def product_summary(products):
    pairs = products.split(', ') if products else []
    if not pairs:
        return 'No NVD product mapping'
    first = pairs[0].replace('/', ' · ', 1).replace('_', ' ')
    return first + (f' +{len(pairs) - 1} more' if len(pairs) > 1 else '')


def rule_summary(rule):
    product = f"{rule['vendor']} / {rule['product']}"
    if rule['kind'] == 'exclude':
        return f"Product not deployed · {product} · {rule['reason']}"
    return f"Minimum deployed version · {product} · branch {rule['branch']} · ≥ {rule['minimum_version']}"


def change(action, refresh):
    try:
        action()
        refresh()
    except (ValueError, KeyError) as exc:
        ui.notify(str(exc), type='negative')

def show_nvd_detail(cve_id):
    cve = store.advisory_detail(cve_id)
    ui.label('Source and scoring').classes('font-semibold mt-2')
    ui.label(f"NVD source: {cve.get('sourceIdentifier') or '—'} · Status: {cve.get('vulnStatus') or '—'}").classes('text-sm')
    ui.label(f"Published: {cve.get('published') or '—'} · Modified: {cve.get('lastModified') or '—'}").classes('text-xs text-gray-600 break-all')
    for key, metrics in cve.get('metrics', {}).items():
        for metric in metrics:
            data = metric.get('cvssData', {})
            ui.label(f"{key}: {data.get('baseScore', '—')} {data.get('baseSeverity') or metric.get('baseSeverity') or ''} · {data.get('vectorString', '—')} ({metric.get('type', '—')})").classes('text-sm break-all')
    for weakness in cve.get('weaknesses', []):
        ui.label('CWE: ' + ', '.join(d.get('value', '') for d in weakness.get('description', []) if d.get('lang') == 'en')).classes('text-sm')
    ui.label('Affected configurations').classes('font-semibold mt-2')
    def show_node(node):
        with ui.column().classes('ml-4 border-l pl-3 gap-1'):
            ui.label(f"{node.get('operator', 'OR')}" + (' · NOT' if node.get('negate') else '')).classes('text-sm font-medium')
            for match in node.get('cpeMatch', []):
                bounds = ', '.join(f'{key}: {match[key]}' for key in ('versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding') if key in match)
                ui.label(f"{'Affected' if match.get('vulnerable') else 'Required context'}: {match.get('criteria', '—')}" + (f' · {bounds}' if bounds else '')).classes('font-mono text-xs break-all')
            for child in node.get('children', []):
                show_node(child)
    for configuration in cve.get('configurations', []):
        for node in configuration.get('nodes', []):
            show_node(node)
    if not cve.get('configurations'):
        ui.label('No affected CPE configuration supplied by NVD.').classes('text-sm')
    if cve.get('references'):
        ui.label('References').classes('font-semibold mt-2')
        for reference in cve['references']:
            url = reference.get('url', '')
            if url.startswith(('https://', 'http://')):
                ui.link(url, url, new_tab=True).classes('text-sm break-all')

def load_nvd_detail(expansion, cve_id):
    expansion.clear()
    with expansion:
        show_nvd_detail(cve_id)



@ui.page('/', language='en-US')
def index():
    ui.page_title('FleetCVEs — Inbox')
    ui.colors(primary='#285c86')
    with ui.row().classes('w-full max-w-5xl mx-auto items-center justify-between gap-3 flex-wrap px-2'):
        ui.html('<h1 class="text-2xl font-bold">Advisory inbox</h1>')
        with ui.row().classes('items-center gap-2'):
            ui.label().bind_text_from(globals(), 'sync_state').classes('text-xs text-gray-600')
            ui.button('Sync now', on_click=lambda: asyncio.create_task(sync_and_refresh())).props('flat dense')
    with ui.tabs().classes('w-full max-w-5xl mx-auto') as tabs:
        inbox_tab = ui.tab('Inbox')
        archive_tab = ui.tab('History')
        coverage_tab = ui.tab('Coverage')
        rules_tab = ui.tab('Rules')
    with ui.tab_panels(tabs, value=inbox_tab).classes('w-full max-w-5xl mx-auto'):
        with ui.tab_panel(coverage_tab):
            ui.label('Monitored vendors').classes('text-lg font-semibold')
            ui.label('These vendors focus the default Inbox. Monitoring never dismisses advisories.').classes('text-sm text-gray-600')
            with ui.row().classes('items-end gap-2 flex-wrap'):
                vendor_input = ui.input('NVD vendor').props('placeholder="e.g. cisco"').classes('w-64')
                def add_vendor():
                    change(lambda: store.add_coverage(vendor_input.value or ''), refresh_coverage_views)
                    vendor_input.value = ''
                vendor_input.on('keydown.enter', lambda: add_vendor())
                ui.button('Monitor vendor', on_click=add_vendor)

            @ui.refreshable
            def show_coverage():
                vendors = store.coverage()
                if not vendors:
                    ui.label('No vendors monitored yet. Add one above, or use All advisories in the Inbox.').classes('text-sm text-gray-600')
                for item in vendors:
                    vendor = item['vendor']
                    with ui.row().classes('w-full items-center gap-3 border-b py-2'):
                        ui.label(vendor.replace('_', ' ')).classes('flex-1 font-medium')
                        ui.button('Remove', on_click=lambda _, v=vendor: change(lambda: store.remove_coverage(v), refresh_coverage_views)).props('flat dense color=negative')
            show_coverage()

        with ui.tab_panel(rules_tab):
            ui.label('Triage rules').classes('text-lg font-semibold')
            ui.label('Rules auto-file only advisories proven irrelevant. Create one from an advisory to prefill its product.').classes('text-sm text-gray-600')

            with ui.expansion('Add rule manually').classes('w-full'):
                with ui.row().classes('items-end gap-2 flex-wrap'):
                    kind = ui.select({'exclude': 'Product not deployed', 'baseline': 'Minimum deployed version'}, value='exclude', label='Rule type').classes('w-56')
                    rvendor = ui.input('NVD vendor').classes('w-40')
                    rproduct = ui.input('NVD product').classes('w-40')
                    branch = ui.input('Numeric branch (e.g. 17.6)').classes('w-48')
                    minimum = ui.input('Minimum deployed version').classes('w-48')
                    branch.set_visibility(False)
                    minimum.set_visibility(False)
                    kind.on_value_change(lambda e: (branch.set_visibility(e.value == 'baseline'), minimum.set_visibility(e.value == 'baseline')))
                    reason = ui.input('Reason (required if not deployed)').classes('w-56')
                    def add_rule():
                        change(lambda: store.add_rule(kind.value, rvendor.value or '', rproduct.value or '',
                                                      (branch.value or '') if kind.value == 'baseline' else '',
                                                      (minimum.value or '') if kind.value == 'baseline' else '', reason.value or ''),
                               refresh_rule_views)
                    ui.button('Add rule', on_click=add_rule)

            def confirm_delete(rule):
                with ui.dialog() as dialog, ui.card():
                    ui.label(f"Delete rule for {rule['vendor']} / {rule['product']}?").classes('font-semibold')
                    ui.label('Its automatically filed advisories will be re-evaluated.').classes('text-sm')
                    with ui.row():
                        ui.button('Delete rule', on_click=lambda: (change(lambda: store.delete_rule(rule['id']), refresh_rule_views), dialog.close())).props('color=negative')
                        ui.button('Cancel', on_click=dialog.close).props('flat')
                dialog.open()

            @ui.refreshable
            def show_rules():
                rules = store.rules_list()
                active = sum(bool(rule['enabled']) for rule in rules)
                filed = store.advisory_count(state='auto_archived')
                ui.label(f"{active} active {'rule' if active == 1 else 'rules'} · {filed:,} {'advisory' if filed == 1 else 'advisories'} auto-filed").classes('text-sm text-gray-600')
                if not rules:
                    ui.label('No rules yet. Create one from an advisory or add one manually.').classes('text-sm text-gray-600')
                for rule in rules:
                    with ui.row().classes('w-full items-center gap-3 border-b py-3 flex-wrap'):
                        with ui.column().classes('flex-1 min-w-52 gap-1'):
                            ui.label(rule_summary(rule)).classes('font-medium')
                            count = rule['archived_count']
                            ui.label(f"{count} {'advisory' if count == 1 else 'advisories'} currently auto-filed").classes('text-xs text-gray-600')
                        ui.checkbox('Enabled', value=bool(rule['enabled']), on_change=lambda e, rid=rule['id']: change(lambda: store.set_rule_enabled(rid, e.value), refresh_rule_views))
                        ui.button('Delete', on_click=lambda _, r=rule: confirm_delete(r)).props('flat dense color=negative')
            show_rules()

        def advisory_panel(state_filter):
            page = {'offset': 0}
            with ui.row().classes('items-end gap-3 flex-wrap'):
                scope = ui.select({'covered': 'Monitored vendors', 'unmapped': 'No product mapping', 'all': 'All advisories'}, value='covered', label='Scope').classes('w-52')
                search = ui.input('Search CVE or description').props('clearable').classes('w-64')
                severity = ui.select(['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'], value='', label='Severity').classes('w-36')
                ui.button('Search', on_click=lambda: apply_filters()).props('outline dense')
                ui.button('Clear', on_click=lambda: clear_filters()).props('flat dense')
            with ui.expansion('More filters').classes('w-full text-sm'):
                with ui.row().classes('items-end gap-2 flex-wrap'):
                    vendor = ui.input('NVD vendor').props('clearable').classes('w-44')
                    product = ui.input('NVD product').props('clearable').classes('w-44')
                    ui.button('Apply', on_click=lambda: apply_filters()).props('outline dense')

            def apply_filters():
                page['offset'] = 0
                show_items.refresh()

            def clear_filters():
                search.value = ''
                vendor.value = ''
                product.value = ''
                severity.value = ''
                apply_filters()
            def edit_notes(item):
                with ui.dialog() as dialog, ui.card().classes('w-full max-w-lg'):
                    ui.label(f"Notes · {item['id']}").classes('font-semibold')
                    notes = ui.textarea('Your notes', value=item.get('notes') or '').classes('w-full')
                    def save():
                        try:
                            store.set_notes(item['id'], notes.value or '')
                        except ValueError as exc:
                            ui.notify(str(exc), type='negative')
                            return
                        dialog.close()
                        show_items.refresh()
                        ui.notify('Notes saved')
                    with ui.row():
                        ui.button('Save notes', on_click=save)
                        ui.button('Cancel', on_click=dialog.close).props('flat')
                dialog.open()

            def product_rule(cve_id):
                pairs = store.advisory_products(cve_id)
                with ui.dialog() as dialog, ui.card().classes('w-full max-w-lg'):
                    ui.label('Create reusable product rule').classes('text-lg font-semibold')
                    ui.label(f'From {cve_id} · Applies to all existing and future matching advisories.').classes('text-sm text-gray-600')
                    pair = ui.select({i: f"{p['vendor']} / {p['product']}" for i, p in enumerate(pairs)}, value=0, label='Product this rule covers').classes('w-full')
                    rule_kind = ui.select({'exclude': 'Product not deployed', 'baseline': 'Minimum deployed version'}, value='exclude', label='Rule').classes('w-full')
                    rule_branch = ui.input('Numeric branch (e.g. 17.6)').classes('w-full')
                    rule_minimum = ui.input('Minimum deployed version (e.g. 17.6.6)').classes('w-full')
                    rule_branch.set_visibility(False)
                    rule_minimum.set_visibility(False)
                    explanation = ui.label('No deployed systems in this branch are older than this version.').classes('text-xs text-gray-600')
                    explanation.set_visibility(False)
                    rule_kind.on_value_change(lambda e: (rule_branch.set_visibility(e.value == 'baseline'), rule_minimum.set_visibility(e.value == 'baseline'), explanation.set_visibility(e.value == 'baseline')))
                    rule_reason = ui.input('Reason (required if not deployed)').props('placeholder="Product not deployed"').classes('w-full')
                    def save_rule():
                        selected = pairs[pair.value]
                        try:
                            ident = store.add_rule(rule_kind.value, selected['vendor'], selected['product'],
                                                   (rule_branch.value or '') if rule_kind.value == 'baseline' else '',
                                                   (rule_minimum.value or '') if rule_kind.value == 'baseline' else '',
                                                   rule_reason.value or '')
                        except ValueError as exc:
                            ui.notify(str(exc), type='negative')
                            return
                        dialog.close()
                        refresh_rule_views()
                        count = next(rule['archived_count'] for rule in store.rules_list() if rule['id'] == ident)
                        ui.notify(f"Rule saved · {count} {'advisory' if count == 1 else 'advisories'} currently auto-filed")
                    with ui.row():
                        ui.button('Create rule', on_click=save_rule)
                        ui.button('Cancel', on_click=dialog.close).props('flat')
                dialog.open()
            @ui.refreshable
            def show_items():
                query = dict(search=search.value or '', vendor=vendor.value or '', product=product.value or '', severity=severity.value or '', state=state_filter, scope=scope.value, limit=50, offset=page['offset'])
                total = store.advisory_count(**{k: query[k] for k in ('search', 'vendor', 'product', 'severity', 'state', 'scope')})
                items = store.advisories(**query)
                rules = {rule['id']: rule for rule in store.rules_list()} if any(item['rule_ids'] for item in items) else {}
                with ui.row().classes('w-full items-center gap-2 flex-wrap'):
                    ui.label(f"{total:,} {'advisory' if total == 1 else 'advisories'}").classes('font-medium')
                    if scope.value == 'covered' and store.coverage():
                        ui.label('Monitored: ' + ', '.join(v['vendor'] for v in store.coverage())).classes('text-xs text-gray-600')
                    ui.space()
                    ui.button('Refresh', on_click=show_items.refresh).props('flat dense')
                    csv_query = urlencode({k: v for k, v in query.items() if k not in ('limit', 'offset')})
                    ui.button('Export CSV', on_click=lambda: ui.download('/api/export?' + csv_query)).props('flat dense')
                    prev = ui.button('Previous', on_click=lambda: move(-50)).props('flat dense')
                    prev.set_visibility(page['offset'] > 0)
                    next_page = ui.button('Next', on_click=lambda: move(50)).props('flat dense')
                    next_page.set_visibility(page['offset'] + 50 < total)
                if scope.value == 'covered' and not store.coverage():
                    ui.label('No monitored vendors yet. Add one to focus this inbox, or choose All advisories above.').classes('text-sm text-gray-600')
                    ui.button('Set monitored vendors', on_click=lambda: tabs.set_value(coverage_tab)).props('outline dense')
                elif not items:
                    ui.label('No matching advisories.').classes('text-sm text-gray-600')
                for item in items:
                    with ui.column().classes('w-full border-b py-3 gap-1'):
                        with ui.row().classes('items-center gap-2 flex-wrap'):
                            ui.link(item['id'], f"https://nvd.nist.gov/vuln/detail/{item['id']}", new_tab=True).classes('font-semibold text-base')
                            ui.badge(item.get('severity') or 'UNRATED')
                            if item.get('disposition'):
                                ui.badge({'not_applicable': 'N/A', 'verified': 'VERIFIED', 'resolved': 'RESOLVED', 'completed': 'COMPLETED'}.get(item['disposition'], item['disposition'].upper()), color='grey')
                            if item.get('changed_since_review'):
                                ui.badge('Changed since review', color='orange')
                        ui.label(product_summary(item.get('products'))).classes('text-sm font-medium')
                        ui.label(item.get('description') or 'No English description supplied by NVD.').classes('text-sm line-clamp-2')
                        if item.get('rule_ids'):
                            for rid in json.loads(item['rule_ids']):
                                if rid in rules:
                                    ui.label('Auto-filed by: ' + rule_summary(rules[rid])).classes('text-xs text-gray-700')
                            if not any(rid in rules for rid in json.loads(item['rule_ids'])):
                                ui.label('Auto-filed by a rule that is no longer present.').classes('text-xs text-gray-700')
                        elif item.get('disposition') == 'verified':
                            ui.label('Verified manually; remains in Inbox.').classes('text-xs text-gray-600')
                        elif not item.get('products'):
                            ui.label('No NVD product mapping · Manual review required.').classes('text-xs text-gray-600')
                        elif state_filter == 'inbox':
                            ui.label('Applicability could not be safely auto-resolved.').classes('text-xs text-gray-600')
                        ui.label(f"Published {readable_date(item.get('published'))} · Updated {readable_date(item.get('modified'))}").classes('text-xs text-gray-500')
                        with ui.row().classes('items-center gap-1 flex-wrap'):
                            for label, disposition, hint in (('N/A', 'not_applicable', 'Not applicable; move to Reviewed'), ('Verified', 'verified', 'Confirmed affected; keep in Inbox'), ('Resolved', 'resolved', 'Remediated; move to Reviewed')):
                                if item.get('disposition') != disposition:
                                    ui.button(label, on_click=lambda _, cid=item['id'], value=disposition: change(lambda: store.set_disposition(cid, value), show_items.refresh)).props('outline dense').tooltip(hint)
                            if item.get('disposition'):
                                ui.button('Reopen', on_click=lambda _, cid=item['id']: change(lambda: store.set_disposition(cid, None), show_items.refresh)).props('flat dense').tooltip('Clear manual decision and reapply rules')
                            ui.button('Edit notes' if item.get('notes') else 'Add note', on_click=lambda _, i=item: edit_notes(i)).props('flat dense')
                            if item.get('products'):
                                ui.button('Create rule', on_click=lambda _, cid=item['id']: product_rule(cid)).props('flat dense')
                        if item.get('notes'):
                            ui.label('Note: ' + item['notes']).classes('text-xs text-gray-600 whitespace-pre-wrap')
                        detail = ui.expansion('View NVD technical details').classes('w-full text-xs')
                        detail.on_value_change(lambda e, cid=item['id'], exp=detail: load_nvd_detail(exp, cid) if e.value else None)
            def move(delta):
                page['offset'] = max(0, page['offset'] + delta)
                show_items.refresh()
            for field in (search, vendor, product):
                field.on('keydown.enter', lambda: apply_filters())
            severity.on_value_change(lambda _: apply_filters())
            scope.on_value_change(lambda _: apply_filters())
            show_items()
            return show_items.refresh
        with ui.tab_panel(inbox_tab):
            inbox_refresh = advisory_panel('inbox')
        with ui.tab_panel(archive_tab):
            with ui.tabs().classes('w-full') as archived_tabs:
                auto_filed = ui.tab('Auto-filed')
                completed = ui.tab('Reviewed')
            with ui.tab_panels(archived_tabs, value=auto_filed).classes('w-full'):
                with ui.tab_panel(auto_filed):
                    archive_refresh = advisory_panel('auto_archived')
                with ui.tab_panel(completed):
                    completed_refresh = advisory_panel('reviewed')
    def refresh_rule_views():
        show_rules.refresh()
        inbox_refresh()
        archive_refresh()
        completed_refresh()
    def refresh_coverage_views():
        show_coverage.refresh()
        inbox_refresh()
        archive_refresh()
        completed_refresh()
    async def sync_and_refresh():
        await run_sync()
        await _sync_task
        inbox_refresh()
        archive_refresh()
        completed_refresh()
    last_sync = sync_state
    def refresh_after_background_sync():
        nonlocal last_sync
        if sync_state != last_sync:
            last_sync = sync_state
            if sync_state.startswith('NVD updated'):
                inbox_refresh()
                archive_refresh()
                completed_refresh()
    ui.timer(5, refresh_after_background_sync)
    tabs.on_value_change(lambda _: (inbox_refresh(), archive_refresh(), completed_refresh(), show_rules.refresh()))
    archived_tabs.on_value_change(lambda _: (archive_refresh(), completed_refresh()))


def run():
    store.initialize()
    ui.run(host='127.0.0.1', port=int(os.environ.get('FLEETCVES_PORT', 8080)), reload=False, show=False)
