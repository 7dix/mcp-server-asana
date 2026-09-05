import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EncryptJWT } from 'jose';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { AsanaClientWrapper } from '../src/asana-client-wrapper.js';
import { createHardenedTools } from '../src/hardened-tools.js';
import { registerAsanaTools } from '../src/mcp-server.js';
import {
  createAsanaAuthorizationRedirect,
  metadata,
  protectedResourceMetadata,
  readOAuthConfig,
  runtimeConfigurationError,
  s256,
  verifyMcpBearerToken,
} from '../src/oauth.js';

const SECRET = randomBytes(32).toString('base64url');
const ENV = {
  MCP_PUBLIC_ORIGIN: 'https://mcp.example.com',
  MCP_TOKEN_SECRET: SECRET,
  ASANA_OAUTH_CLIENT_ID: 'asana-client',
  ASANA_OAUTH_CLIENT_SECRET: 'asana-secret',
  ASANA_ALLOWED_PROJECTS: '100,200',
  READ_ONLY_MODE: 'false',
};

test('OAuth configuration fails closed and uses the exact MCP audience', () => {
  assert.throws(() => readOAuthConfig({}));
  assert.throws(() => readOAuthConfig({ ...ENV, MCP_PUBLIC_ORIGIN: 'http://mcp.example.com' }));
  assert.throws(() => readOAuthConfig({ ...ENV, MCP_TOKEN_SECRET: 'short' }));
  const config = readOAuthConfig(ENV);
  assert.equal(config.resource, 'https://mcp.example.com/api/mcp');
  assert.deepEqual(config.supportedScopes, ['asana:read', 'asana:write']);
  assert.equal(runtimeConfigurationError(ENV), undefined);
  assert.match(runtimeConfigurationError({ ...ENV, ASANA_ALLOWED_PROJECTS: '*' })!, /ASANA_ALLOWED_PROJECTS/);
});

test('OAuth discovery advertises PKCE, CIMD and protected resource binding', () => {
  const config = readOAuthConfig(ENV);
  assert.deepEqual(metadata(config), {
    issuer: 'https://mcp.example.com',
    authorization_endpoint: 'https://mcp.example.com/oauth/authorize',
    token_endpoint: 'https://mcp.example.com/oauth/token',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
    scopes_supported: ['asana:read', 'asana:write'],
  });
  assert.equal(protectedResourceMetadata(config).resource, 'https://mcp.example.com/api/mcp');
  assert.deepEqual(protectedResourceMetadata(config).authorization_servers, ['https://mcp.example.com']);
});

test('authorization request is strictly bound before redirecting to Asana', async () => {
  const config = readOAuthConfig(ENV);
  const verifier = 'v'.repeat(48);
  const base = new URL('https://mcp.example.com/oauth/authorize');
  base.search = new URLSearchParams({
    response_type: 'code',
    client_id: 'https://chatgpt.com/oauth/client.json',
    redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
    resource: config.resource,
    scope: 'asana:read asana:write',
    state: 'opaque-client-state',
    code_challenge: s256(verifier),
    code_challenge_method: 'S256',
  }).toString();
  const redirect = new URL(await createAsanaAuthorizationRedirect(base, config));
  assert.equal(redirect.origin, 'https://app.asana.com');
  assert.equal(redirect.pathname, '/-/oauth_authorize');
  assert.equal(redirect.searchParams.get('client_id'), 'asana-client');
  assert.equal(redirect.searchParams.get('redirect_uri'), 'https://mcp.example.com/oauth/callback');
  assert.equal(redirect.searchParams.get('code_challenge_method'), 'S256');
  assert.doesNotMatch(redirect.searchParams.get('state')!, /opaque-client-state|asana-secret/);

  for (const [field, value] of [
    ['resource', 'https://evil.example/api/mcp'],
    ['client_id', 'untrusted-client'],
    ['redirect_uri', 'https://evil.example/callback'],
    ['code_challenge_method', 'plain'],
  ]) {
    const invalid = new URL(base); invalid.searchParams.set(field, value);
    await assert.rejects(createAsanaAuthorizationRedirect(invalid, config));
  }
});

test('MCP access tokens are encrypted, audience-bound and expose only the upstream token to request context', async () => {
  const config = readOAuthConfig(ENV);
  const accessToken = await new EncryptJWT({
    kind: 'access_token', sub: '12345', client_id: 'https://chatgpt.com/oauth/client.json',
    resource: config.resource, scope: 'asana:read asana:write', asana_access_token: 'UPSTREAM-ASANA-TOKEN',
  }).setProtectedHeader({ alg: 'dir', enc: 'A256GCM', typ: 'JWT' })
    .setIssuer(config.origin).setAudience(config.resource).setIssuedAt().setExpirationTime('5m').encrypt(config.key);
  assert.doesNotMatch(accessToken, /UPSTREAM-ASANA-TOKEN/);
  const auth = await verifyMcpBearerToken(accessToken, config);
  assert.equal(auth?.resource?.toString(), config.resource);
  assert.equal(auth?.extra?.asanaAccessToken, 'UPSTREAM-ASANA-TOKEN');
  assert.equal(auth?.extra?.asanaUserGid, '12345');

  const wrongAudience = await new EncryptJWT({
    kind: 'access_token', sub: '12345', client_id: 'client', resource: 'https://evil.example',
    scope: 'asana:read', asana_access_token: 'UPSTREAM-ASANA-TOKEN',
  }).setProtectedHeader({ alg: 'dir', enc: 'A256GCM' }).setIssuer(config.origin)
    .setAudience('https://evil.example').setIssuedAt().setExpirationTime('5m').encrypt(config.key);
  await assert.rejects(verifyMcpBearerToken(wrongAudience, config));
});

test('every advertised tool declares its OAuth policy', () => {
  const api = createHardenedTools(new AsanaClientWrapper('unused'), { projects: new Set(['100']), readOnly: false });
  assert.ok(api.tools.length > 0);
  for (const tool of api.tools) {
    const schemes = tool._meta?.securitySchemes as Array<{ type: string; scopes: string[] }>;
    assert.equal(schemes[0].type, 'oauth2');
    assert.ok(schemes[0].scopes.includes('asana:read'));
    if (!tool.annotations?.readOnlyHint) assert.ok(schemes[0].scopes.includes('asana:write'));
    assert.deepEqual(api.scopesFor(tool.name), schemes[0].scopes);
  }
  assert.equal(api.scopesFor('unknown_tool'), undefined);
});

test('write tools enforce their OAuth scope before any Asana request', async t => {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const authInfo = {
    token: 'outer-token', clientId: 'client', scopes: ['asana:read'],
    resource: new URL('https://mcp.example.com/api/mcp'), extra: { asanaAccessToken: 'must-not-be-used' },
  };
  const send = clientTransport.send.bind(clientTransport);
  clientTransport.send = (message, options) => send(message, { ...options, authInfo });
  const server = new Server({ name: 'test', version: '1' }, { capabilities: { tools: {} } });
  registerAsanaTools(server, ENV, {
    requestOAuth: true,
    resourceMetadataUrl: 'https://mcp.example.com/.well-known/oauth-protected-resource',
  });
  const client = new Client({ name: 'test', version: '1' });
  t.after(async () => { await client.close(); await server.close(); });
  await server.connect(serverTransport); await client.connect(clientTransport);
  const response = await client.callTool({ name: 'asana_update_task', arguments: { task_id: '1', name: 'blocked' } });
  assert.equal(response.isError, true);
  assert.deepEqual(response._meta?.['mcp/www_authenticate'], [
    'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource" scope="asana:read asana:write"',
  ]);
  assert.match((response.content[0] as { text: string }).text, /does not grant/);
});
