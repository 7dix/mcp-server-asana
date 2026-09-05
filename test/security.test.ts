import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { AsanaClientWrapper } from '../src/asana-client-wrapper.js';
import { createHardenedTools } from '../src/hardened-tools.js';
import { readSecurityConfig } from '../src/security.js';

const TOKEN = 'FAKE-TOKEN-TEST-ONLY';
async function fixture(t: any, readOnly = false) {
  const tasks: Record<string, any> = {
    '1': { gid: '1', name: 'Parent', projects: [{ gid: '100' }], parent: null, custom_type: null },
    '2': { gid: '2', name: 'Nested', projects: [], parent: { gid: '1' }, custom_type: { gid: '500' } },
    '3': { gid: '3', name: 'Foreign', projects: [{ gid: '999' }], parent: null, custom_type: null },
    '4': { gid: '4', name: 'Mixed', projects: [{ gid: '100' }, { gid: '999' }], parent: null },
    '5': { gid: '5', name: 'Orphan', projects: [], parent: null },
  };
  const requests: any[] = [];
  const types = [{ gid: '500', name: 'Úkol', status_options: [
    { gid: '501', name: 'Probíhá', enabled: true, completion_state: 'Incomplete' },
    { gid: '502', name: 'Done', enabled: true, completion_state: 'Complete' },
    { gid: '503', name: 'Disabled', enabled: false, completion_state: 'Incomplete' },
  ] }];
  let failPut = false; let failGetAfterPut = false; let didPut = false; let ignorePut = false;
  const server = createServer(async (req, res) => {
    let raw = ''; for await (const part of req) raw += part;
    const url = new URL(req.url!, 'http://localhost');
    const body = raw ? JSON.parse(raw) : undefined;
    requests.push({ method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), body, auth: req.headers.authorization });
    const send = (data: unknown, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(data)); };
    const id = url.pathname.match(/^\/tasks\/(\d+)$/)?.[1];
    if (id && req.method === 'GET') {
      if (failGetAfterPut && didPut) return send({ errors: [{ message: 'CANARY confidential token=' + TOKEN }] }, 500);
      return tasks[id] ? send({ data: tasks[id] }) : send({ errors: [{ message: 'CANARY confidential token=' + TOKEN }] }, 404);
    }
    if (id && req.method === 'PUT') {
      if (failPut) return send({ errors: [{ message: 'CANARY private Asana body=' + TOKEN }] }, 403);
      didPut = true;
      const d = body.data;
      if (ignorePut) return send({ data: tasks[id] });
      Object.assign(tasks[id], d);
      if (d.custom_type) tasks[id].custom_type = { gid: d.custom_type };
      if (d.custom_type_status_option) tasks[id].custom_type_status_option = { gid: d.custom_type_status_option };
      return send({ data: tasks[id] });
    }
    if (req.method === 'POST' && (url.pathname === '/tasks' || url.pathname.endsWith('/subtasks'))) {
      const d = body.data; const parent = url.pathname.match(/^\/tasks\/(\d+)\/subtasks$/)?.[1];
      tasks['10'] = { ...d, gid: '10', projects: (d.projects ?? []).map((gid: string) => ({ gid })), parent: parent ? { gid: parent } : null, custom_type: null };
      return send({ data: tasks['10'] });
    }
    if (url.pathname === '/custom_types') {
      return url.searchParams.has('offset') ? send({ data: types, next_page: null }) : send({ data: [], next_page: { offset: 'NEXT' } });
    }
    if (url.pathname === '/projects/100/tasks') return send({ data: [{ gid: '1' }], next_page: { offset: 'TASK_NEXT' } });
    if (url.pathname === '/tasks/1/subtasks') return send({ data: [{ gid: '2' }], next_page: null });
    if (url.pathname === '/tasks/1/stories') return send({ data: [{ gid: '800', text: 'Meeting' }], next_page: null });
    if (url.pathname === '/sections/700') return send({ data: { gid: '700', project: { gid: '999' } } });
    return send({ errors: [{ message: 'Unimplemented fixture route' }] }, 404);
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise<void>(resolve => { server.closeAllConnections(); server.close(() => resolve()); }));
  const client = new AsanaClientWrapper(TOKEN);
  // Only the test can override the endpoint; production configuration has no URL override.
  (client as any).tasks.apiClient.basePath = 'http://127.0.0.1:' + (server.address() as any).port;
  const api = createHardenedTools(client, { projects: new Set(['100', '200']), readOnly });
  const call = async (name: string, args: any) => {
    const response = await api.call({ method: 'tools/call', params: { name, arguments: args } });
    return { error: response.isError === true, value: JSON.parse((response.content[0] as any).text) };
  };
  return { tasks, requests, api, call, ignorePut: () => { ignorePut = true; }, failPut: () => { failPut = true; }, failVerification: () => { failGetAfterPut = true; } };
}

test('configuration fails closed and read-only is the default', () => {
  assert.throws(() => readSecurityConfig({}));
  assert.throws(() => readSecurityConfig({ ASANA_ALLOWED_PROJECTS: '*' }));
  assert.throws(() => readSecurityConfig({ ASANA_ALLOWED_PROJECTS: '100', READ_ONLY_MODE: 'FALSE' }));
  assert.equal(readSecurityConfig({ ASANA_ALLOWED_PROJECTS: '100,200' }).readOnly, true);
});
test('read-only blocks direct writes even when client knows the tool name', async t => {
  const f = await fixture(t, true);
  assert.ok(f.api.tools.every(x => x.annotations?.readOnlyHint));
  assert.equal((await f.call('asana_update_task', { task_id: '1', name: 'Attempt' })).error, true);
  assert.equal(f.requests.length, 0);
});
test('delete and legacy global tools cannot be called directly', async t => {
  const f = await fixture(t);
  for (const name of ['asana_delete_task', 'asana_delete_section', 'asana_search_tasks', 'asana_get_my_tasks', 'asana_list_workspaces']) {
    assert.equal((await f.call(name, { task_id: '1' })).error, true);
  }
  assert.equal(f.requests.length, 0);
});
test('unknown arguments, nonnumeric IDs and oversized notes are rejected before HTTP', async t => {
  const f = await fixture(t);
  for (const args of [{ task_id: '1', projects: ['999'] }, { task_id: '../3', name: 'x' }, { task_id: '1', parent: '3' }, { task_id: '1', notes: 'x'.repeat(100001) }, { task_id: '1', custom_fields: { custom_type: '500' } }]) {
    assert.equal((await f.call('asana_update_task', args)).error, true);
  }
  assert.equal(f.requests.length, 0);
});
test('foreign, mixed-membership and orphan tasks cannot be updated', async t => {
  const f = await fixture(t);
  for (const id of ['3', '4', '5']) assert.equal((await f.call('asana_update_task', { task_id: id, name: 'x' })).error, true);
  assert.ok(f.requests.every(x => x.method === 'GET'));
});
test('nested subtasks inherit authorization through a parent', async t => {
  const f = await fixture(t);
  assert.equal((await f.call('asana_get_task', { task_id: '2' })).error, false);
  assert.ok(f.requests.some(x => x.path === '/tasks/1'));
});
test('cycles and incomplete membership responses fail closed', async t => {
  const f = await fixture(t); f.tasks['1'].parent = { gid: '2' };
  assert.equal((await f.call('asana_get_task', { task_id: '2' })).error, true);
  f.tasks['1'].parent = null; delete f.tasks['1'].projects;
  assert.equal((await f.call('asana_get_task', { task_id: '1' })).error, true);
});
test('scope is checked again after membership changes between calls', async t => {
  const f = await fixture(t);
  assert.equal((await f.call('asana_get_task', { task_id: '1' })).error, false);
  f.tasks['1'].projects = [{ gid: '999' }];
  assert.equal((await f.call('asana_update_task', { task_id: '1', name: 'x' })).error, true);
  assert.ok(f.requests.every(x => x.method === 'GET'));
});
test('status-only change retains type and sends correct top-level PUT body', async t => {
  const f = await fixture(t);
  const r = await f.call('asana_set_task_type_status', { task_id: '2', custom_type_status_option: '501' });
  assert.equal(r.error, false);
  assert.deepEqual(f.requests.find(x => x.method === 'PUT').body, { data: { resource_subtype: 'custom', custom_type: '500', custom_type_status_option: '501' } });
  assert.ok(f.requests.every(x => x.auth === 'Bearer ' + TOKEN));
  assert.ok(f.requests.some(x => x.path === '/custom_types' && x.query.offset === 'NEXT'));
});
test('foreign type, foreign status, disabled status and missing type are rejected without PUT', async t => {
  const f = await fixture(t);
  for (const args of [ { task_id: '1', custom_type: '999' }, { task_id: '2', custom_type_status_option: '999' }, { task_id: '2', custom_type_status_option: '503' }, { task_id: '1', custom_type_status_option: '501' } ]) {
    assert.equal((await f.call('asana_set_task_type_status', args)).error, true);
  }
  assert.ok(f.requests.every(x => x.method === 'GET'));
});
test('create validates type first, sends plain POST then custom PUT', async t => {
  const f = await fixture(t);
  const r = await f.call('asana_create_task', { project_id: '100', name: 'New', custom_type: '500', custom_type_status_option: '501' });
  assert.equal(r.error, false);
  const writes = f.requests.filter(x => x.method !== 'GET');
  assert.deepEqual(writes.map(x => x.method), ['POST', 'PUT']);
  assert.equal(writes[0].body.data.custom_type, undefined);
  assert.equal(writes[0].body.data.custom_type_status_option, undefined);
  assert.equal(writes[1].body.data.resource_subtype, 'custom');
});
test('invalid status prevents creation entirely', async t => {
  const f = await fixture(t);
  assert.equal((await f.call('asana_create_task', { project_id: '100', name: 'New', custom_type: '500', custom_type_status_option: '999' })).error, true);
  assert.ok(f.requests.every(x => x.method === 'GET'));
});
test('subtask creation uses parent endpoint and does not add project membership', async t => {
  const f = await fixture(t);
  assert.equal((await f.call('asana_create_subtask', { parent_task_id: '2', name: 'New child', custom_type: '500' })).error, false);
  const post = f.requests.find(x => x.method === 'POST');
  assert.equal(post.path, '/tasks/2/subtasks'); assert.equal(post.body.data.projects, undefined);
});
test('failure after creation returns task ID without duplicate creation or leaked error', async t => {
  const f = await fixture(t); f.failPut();
  const r = await f.call('asana_create_task', { project_id: '100', name: 'New', custom_type: '500' });
  assert.equal(r.error, true); assert.equal(r.value.created_task_id, '10'); assert.equal(r.value.partial_success, true);
  assert.equal(f.requests.filter(x => x.method === 'POST').length, 1);
  assert.doesNotMatch(JSON.stringify(r), /CANARY|FAKE-TOKEN/);
});
test('successful update with failed readback is identified as partial success', async t => {
  const f = await fixture(t); f.failVerification();
  const r = await f.call('asana_update_task', { task_id: '1', name: 'New' });
  assert.equal(r.error, true); assert.equal(r.value.partial_success, true); assert.equal(r.value.task_id, '1');
});
test('API failures expose status, never raw response or token', async t => {
  const f = await fixture(t);
  const r = await f.call('asana_get_task', { task_id: '999' });
  assert.equal(r.error, true); assert.equal(r.value.status, 404);
  assert.doesNotMatch(JSON.stringify(r), /CANARY|FAKE-TOKEN/);
});
test('bulk reads reject mixed scopes before returning data', async t => {
  const f = await fixture(t);
  assert.equal((await f.call('asana_get_multiple_tasks_by_gid', { task_ids: ['1', '3'] })).error, true);
});
test('lists preserve pagination and custom types follow every page', async t => {
  const f = await fixture(t);
  const r = await f.call('asana_get_tasks_for_project', { project_id: '100', limit: 25 });
  assert.equal(r.error, false); assert.equal(r.value.next_page.offset, 'TASK_NEXT');
  assert.equal(f.requests.find(x => x.path === '/projects/100/tasks').query.limit, '25');
  const types = await f.call('asana_get_custom_types', { project_id: '100' });
  assert.equal(types.value[0].status_options[0].name, 'Probíhá');
});
test('foreign sections, parents and dependency targets cannot be mutated', async t => {
  const f = await fixture(t);
  for (const [name, args] of [
    ['asana_add_task_to_section', { task_id: '1', section_id: '700' }],
    ['asana_set_parent_for_task', { task_id: '1', parent_task_id: '3' }],
    ['asana_add_task_dependencies', { task_id: '1', dependencies: ['3'] }],
  ] as const) assert.equal((await f.call(name, args)).error, true);
  assert.ok(f.requests.every(x => x.method === 'GET'));
});
test('custom tasks cannot silently bypass their status through completed=true', async t => {
  const f = await fixture(t);
  assert.equal((await f.call('asana_update_task', { task_id: '2', completed: true })).error, true);
  assert.ok(f.requests.every(x => x.method === 'GET'));
});
test('built stdio server advertises only tools and rejects writes without network or sensitive logs', async t => {
  const transport = new StdioClientTransport({ command: process.execPath, args: ['dist/index.js'],
    env: { ASANA_ACCESS_TOKEN: TOKEN, ASANA_ALLOWED_PROJECTS: '100' }, stderr: 'pipe' });
  const client = new Client({ name: 'test', version: '1' });
  let stderr = ''; transport.stderr?.on('data', data => { stderr += data.toString(); });
  t.after(() => client.close()); await client.connect(transport);
  assert.deepEqual(client.getServerCapabilities(), { tools: {} });
  const listed = await client.listTools(); assert.ok(listed.tools.length > 0);
  assert.ok(listed.tools.every(x => x.annotations?.readOnlyHint));
  const r = await client.callTool({ name: 'asana_update_task', arguments: { task_id: '1', notes: 'CANARY private meeting' } });
  assert.equal(r.isError, true); assert.doesNotMatch(stderr, /CANARY|FAKE-TOKEN/);
});

test('a successful HTTP response that ignores the custom fields is not reported as success', async t => {
  const f = await fixture(t); f.ignorePut();
  const r = await f.call('asana_set_task_type_status', { task_id: '1', custom_type: '500', custom_type_status_option: '501' });
  assert.equal(r.error, true); assert.equal(r.value.partial_success, true);
});
