"""NiceGUI browser and localhost JSON API for FleetCVEs."""

import asyncio
import logging
import os
import sqlite3

from fastapi import HTTPException
from nicegui import app, ui
from pydantic import BaseModel

import fleetcves as store

log = logging.getLogger(__name__)
sync_state = 'Waiting for NVD sync'


class Toggle(BaseModel):
    enabled: bool


class StatusChange(BaseModel):
    cpe_name: str
    cve_id: str
    status: str | None = None


class NewStatus(BaseModel):
    name: str


def apply(fn, *args):
    try:
        fn(*args)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get('/api/cpes')
def api_cpes(search: str = '', limit: int = 100):
    return store.catalog(search, limit)


@app.put('/api/cpes/{name:path}/tracked')
def api_track(name: str, change: Toggle):
    apply(store.track, name, change.enabled)
    return {'ok': True}


@app.put('/api/cpes/{name:path}/in-use')
def api_in_use(name: str, change: Toggle):
    apply(store.set_in_use, name, change.enabled)
    return {'ok': True}


@app.get('/api/findings')
def api_findings():
    return store.findings()


@app.get('/api/statuses')
def api_statuses():
    return store.rows('SELECT name FROM statuses ORDER BY name')


@app.post('/api/statuses', status_code=201)
def api_new_status(data: NewStatus):
    apply(store.add_status, data.name)
    return {'ok': True}


@app.put('/api/findings/status')
def api_status(data: StatusChange):
    apply(store.set_status, data.cpe_name, data.cve_id, data.status)
    return {'ok': True}


async def sync_worker():
    global sync_state
    while True:
        sync_state = 'Syncing CPE catalog from NVD…'
        try:
            count = await asyncio.to_thread(store.sync_cpes)
            sync_state = f'Catalog updated ({count} CPE records); last sync {store.now()}'
        except Exception as exc:
            sync_state = f'NVD sync failed: {exc}'
            log.exception('CPE sync failed; will retry')
        await asyncio.sleep(3600)


async def poll_worker():
    while True:
        try:
            await asyncio.to_thread(store.poll_due)
        except Exception:
            log.exception('Vulnerability polling failed; will retry')
        await asyncio.sleep(30)


@app.on_startup
async def startup():
    store.initialize()
    asyncio.create_task(sync_worker())
    asyncio.create_task(poll_worker())


@ui.page('/')
def index():
    ui.page_title('FleetCVEs')
    ui.label('FleetCVEs').classes('text-3xl font-bold')
    ui.label('Local NVD catalog and vulnerability triage').classes('text-gray-600')
    ui.label().bind_text_from(globals(), 'sync_state').classes('text-sm text-gray-600')

    with ui.tabs().classes('w-full') as tabs:
        catalog_tab = ui.tab('CPE catalog')
        findings_tab = ui.tab('Findings')
        statuses_tab = ui.tab('Statuses')
    with ui.tab_panels(tabs, value=catalog_tab).classes('w-full'):
        with ui.tab_panel(catalog_tab):
            with ui.row().classes('items-center'):
                search = ui.input('Search CPE name or title').props('clearable').classes('w-96')
                ui.button('Search', on_click=lambda: show_cpes.refresh())
            ui.label('Select versions to track; uncheck In use to hide their findings.').classes('text-sm text-gray-600')

            @ui.refreshable
            def show_cpes():
                entries = store.catalog(search.value or '', 100)
                if not entries:
                    ui.label('No CPEs yet. The initial NVD sync runs in the background.').classes('text-gray-600')
                for item in entries:
                    with ui.row().classes('w-full items-center gap-4 border-b py-2'):
                        with ui.column().classes('flex-1 gap-0'):
                            ui.label(f"{item['vendor']} / {item['product']} / {item['version']}").classes('font-medium')
                            ui.label(item['name']).classes('text-xs text-gray-500 break-all')
                        ui.checkbox('Track', value=bool(item['tracked']),
                                    on_change=lambda e, name=item['name']: (store.track(name, e.value), show_cpes.refresh()))
                        if item['tracked']:
                            ui.checkbox('In use', value=bool(item['in_use']),
                                        on_change=lambda e, name=item['name']: (store.set_in_use(name, e.value), show_findings.refresh()))
            show_cpes()

        with ui.tab_panel(findings_tab):
            ui.label('Findings for tracked versions in use').classes('text-xl font-semibold')

            @ui.refreshable
            def show_findings():
                entries = store.findings()
                if not entries:
                    ui.label('No findings yet. Track a CPE and allow the poller to query NVD.').classes('text-gray-600')
                options = ['Unreviewed'] + [r['name'] for r in store.rows('SELECT name FROM statuses ORDER BY name')]
                for finding in entries:
                    with ui.column().classes('w-full border-b py-3 gap-1'):
                        with ui.row().classes('items-center gap-3'):
                            ui.link(finding['cve_id'], f"https://nvd.nist.gov/vuln/detail/{finding['cve_id']}", new_tab=True).classes('font-bold')
                            ui.badge(finding['severity'] or 'UNRATED')
                            ui.label(f"{finding['vendor']} / {finding['product']} / {finding['version']}")
                            ui.select(options, value=finding['status'] or 'Unreviewed', label='Status',
                                      on_change=lambda e, f=finding: store.set_status(f['cpe_name'], f['cve_id'], None if e.value == 'Unreviewed' else e.value)).classes('w-44')
                        ui.label(finding['description']).classes('text-sm')
            show_findings()

        with ui.tab_panel(statuses_tab):
            ui.label('Custom finding statuses').classes('text-xl font-semibold')
            with ui.row().classes('items-center'):
                label = ui.input('New status')

                def create_status():
                    try:
                        store.add_status(label.value)
                        label.value = ''
                        show_statuses.refresh()
                        show_findings.refresh()
                    except (ValueError, sqlite3.IntegrityError) as exc:
                        ui.notify(str(exc), type='negative')

                ui.button('Add', on_click=create_status)

            @ui.refreshable
            def show_statuses():
                for row in store.rows('SELECT name FROM statuses ORDER BY name'):
                    ui.label(row['name'])
            show_statuses()

    ui.timer(15, lambda: (show_cpes.refresh(), show_findings.refresh()))


def run():
    store.initialize()
    ui.run(host='127.0.0.1', port=int(os.environ.get('FLEETCVES_PORT', 8080)),
           reload=False, show=False)
