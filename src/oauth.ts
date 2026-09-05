import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { EncryptJWT, errors as joseErrors, jwtDecrypt, type JWTPayload } from 'jose';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';

const ASANA_ISSUER = 'https://app.asana.com';
const DEFAULT_OPENAI_CLIENT_ID = 'https://chatgpt.com/oauth/client.json';
const DEFAULT_OPENAI_REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect';
const READ_SCOPE = 'asana:read';
const WRITE_SCOPE = 'asana:write';

export interface OAuthConfig {
  origin: string;
  resource: string;
  asanaClientId: string;
  asanaClientSecret: string;
  key: Uint8Array;
  allowedClientIds: Set<string>;
  allowedRedirectUris: Set<string>;
  supportedScopes: string[];
}

interface BridgeClaims extends JWTPayload {
  kind: 'asana_state' | 'authorization_code' | 'access_token' | 'refresh_token';
  client_id: string;
  redirect_uri?: string;
  resource: string;
  scope: string;
  oauth_state?: string;
  code_challenge?: string;
  asana_code_verifier?: string;
  asana_access_token?: string;
  asana_refresh_token?: string;
  asana_expires_at?: number;
}

export class OAuthError extends Error {
  constructor(public readonly code: string, message: string, public readonly status = 400) { super(message); }
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new OAuthError('server_configuration_error', `${name} is required.`, 503);
  return value;
}

function csv(value: string | undefined, fallback: string): Set<string> {
  return new Set((value ?? fallback).split(',').map(item => item.trim()).filter(Boolean));
}

export function readOAuthConfig(env: NodeJS.ProcessEnv = process.env): OAuthConfig {
  const rawOrigin = required(env, 'MCP_PUBLIC_ORIGIN');
  let url: URL;
  try { url = new URL(rawOrigin); } catch { throw new OAuthError('server_configuration_error', 'MCP_PUBLIC_ORIGIN must be an HTTPS origin.', 503); }
  if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash) {
    throw new OAuthError('server_configuration_error', 'MCP_PUBLIC_ORIGIN must be an HTTPS origin without a path.', 503);
  }
  const secret = required(env, 'MCP_TOKEN_SECRET');
  const key = Buffer.from(secret, 'base64url');
  if (key.length !== 32 || key.toString('base64url') !== secret.replace(/=+$/, '')) {
    throw new OAuthError('server_configuration_error', 'MCP_TOKEN_SECRET must be a base64url-encoded 32-byte value.', 503);
  }
  const origin = url.origin;
  return {
    origin,
    resource: `${origin}/api/mcp`,
    asanaClientId: required(env, 'ASANA_OAUTH_CLIENT_ID'),
    asanaClientSecret: required(env, 'ASANA_OAUTH_CLIENT_SECRET'),
    key,
    allowedClientIds: csv(env.MCP_ALLOWED_CLIENT_IDS, DEFAULT_OPENAI_CLIENT_ID),
    allowedRedirectUris: csv(env.MCP_ALLOWED_REDIRECT_URIS, DEFAULT_OPENAI_REDIRECT),
    supportedScopes: env.READ_ONLY_MODE === 'false' ? [READ_SCOPE, WRITE_SCOPE] : [READ_SCOPE],
  };
}

export function runtimeConfigurationError(env: NodeJS.ProcessEnv = process.env): string | undefined {
  try {
    readOAuthConfig(env);
    const projects = new Set((env.ASANA_ALLOWED_PROJECTS ?? '').split(',').map(x => x.trim()).filter(Boolean));
    if (!projects.size || [...projects].some(x => !/^\d+$/.test(x))) return 'ASANA_ALLOWED_PROJECTS must contain explicit comma-separated project GIDs.';
    if (env.READ_ONLY_MODE !== undefined && !['true', 'false'].includes(env.READ_ONLY_MODE)) return 'READ_ONLY_MODE must be true or false.';
    return undefined;
  } catch (error) {
    return error instanceof Error ? error.message : 'OAuth configuration is invalid.';
  }
}

export function metadata(config: OAuthConfig) {
  return {
    issuer: config.origin,
    authorization_endpoint: `${config.origin}/oauth/authorize`,
    token_endpoint: `${config.origin}/oauth/token`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
    scopes_supported: config.supportedScopes,
  };
}

export function protectedResourceMetadata(config: OAuthConfig) {
  return {
    resource: config.resource,
    authorization_servers: [config.origin],
    scopes_supported: config.supportedScopes,
    resource_documentation: `${config.origin}/`,
  };
}

function parseScopes(raw: string | null | undefined, supported: string[]): string[] {
  const requested = (raw ?? supported.join(' ')).split(/\s+/).filter(Boolean);
  if (!requested.length || requested.some(scope => !supported.includes(scope))) {
    throw new OAuthError('invalid_scope', 'Requested scope is not supported.');
  }
  return [...new Set(requested)];
}

function assertClient(config: OAuthConfig, clientId: string, redirectUri?: string): void {
  if (!config.allowedClientIds.has(clientId)) throw new OAuthError('unauthorized_client', 'OAuth client is not allowed.', 401);
  if (redirectUri && !config.allowedRedirectUris.has(redirectUri)) throw new OAuthError('invalid_request', 'redirect_uri is not allowed.');
}

function b64url(bytes: Uint8Array): string { return Buffer.from(bytes).toString('base64url'); }
export function s256(value: string): string { return createHash('sha256').update(value).digest('base64url'); }
function secureEqual(left: string, right: string | undefined): boolean {
  if (right === undefined) return false;
  const a = Buffer.from(left); const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

async function encrypt(config: OAuthConfig, claims: BridgeClaims, audience: string, ttlSeconds: number): Promise<string> {
  return new EncryptJWT(claims)
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', typ: 'JWT' })
    .setIssuer(config.origin).setAudience(audience).setIssuedAt().setJti(b64url(randomBytes(18)))
    .setExpirationTime(`${ttlSeconds}s`).encrypt(config.key);
}

async function decrypt(config: OAuthConfig, token: string, audience: string, kind: BridgeClaims['kind']): Promise<BridgeClaims> {
  try {
    const { payload } = await jwtDecrypt(token, config.key, { issuer: config.origin, audience, clockTolerance: 5 });
    if (payload.kind !== kind) throw new OAuthError('invalid_grant', 'Token has the wrong purpose.');
    return payload as BridgeClaims;
  } catch (error) {
    if (error instanceof OAuthError) throw error;
    if (error instanceof joseErrors.JOSEError) throw new OAuthError('invalid_grant', 'Token is invalid or expired.');
    throw error;
  }
}

export async function createAsanaAuthorizationRedirect(requestUrl: URL, config: OAuthConfig): Promise<string> {
  const p = requestUrl.searchParams;
  if (p.get('response_type') !== 'code') throw new OAuthError('unsupported_response_type', 'Only response_type=code is supported.');
  const clientId = p.get('client_id') ?? '';
  const redirectUri = p.get('redirect_uri') ?? '';
  assertClient(config, clientId, redirectUri);
  if (p.get('resource') !== config.resource) throw new OAuthError('invalid_target', 'resource must match this MCP server.');
  const challenge = p.get('code_challenge') ?? '';
  if (!challenge || p.get('code_challenge_method') !== 'S256') throw new OAuthError('invalid_request', 'PKCE S256 is required.');
  const scopes = parseScopes(p.get('scope'), config.supportedScopes);
  const asanaVerifier = b64url(randomBytes(48));
  const state = await encrypt(config, {
    kind: 'asana_state', client_id: clientId, redirect_uri: redirectUri, resource: config.resource,
    scope: scopes.join(' '), oauth_state: p.get('state') ?? undefined, code_challenge: challenge,
    asana_code_verifier: asanaVerifier,
  }, `${config.origin}/oauth/callback`, 600);
  const upstream = new URL(`${ASANA_ISSUER}/-/oauth_authorize`);
  upstream.search = new URLSearchParams({
    client_id: config.asanaClientId,
    redirect_uri: `${config.origin}/oauth/callback`,
    response_type: 'code',
    state,
    code_challenge: s256(asanaVerifier),
    code_challenge_method: 'S256',
  }).toString();
  return upstream.toString();
}

interface AsanaTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  data?: { gid?: string; id?: number | string };
}

async function asanaToken(config: OAuthConfig, fields: Record<string, string>): Promise<AsanaTokenResponse> {
  const response = await fetch(`${ASANA_ISSUER}/-/oauth_token`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({ client_id: config.asanaClientId, client_secret: config.asanaClientSecret, ...fields }),
    cache: 'no-store',
  });
  if (!response.ok) throw new OAuthError('invalid_grant', 'Asana rejected the authorization grant.', 401);
  const value = await response.json() as Partial<AsanaTokenResponse>;
  if (typeof value.access_token !== 'string' || !value.access_token) throw new OAuthError('server_error', 'Asana returned no access token.', 502);
  return value as AsanaTokenResponse;
}

async function asanaUserId(accessToken: string): Promise<string> {
  const response = await fetch('https://app.asana.com/api/1.0/users/me?opt_fields=gid', {
    headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' }, cache: 'no-store',
  });
  if (!response.ok) throw new OAuthError('invalid_grant', 'Asana identity could not be verified.', 401);
  const body = await response.json() as { data?: { gid?: string } };
  if (!body.data?.gid || !/^\d+$/.test(body.data.gid)) throw new OAuthError('server_error', 'Asana returned an invalid identity.', 502);
  return body.data.gid;
}

export async function finishAsanaAuthorization(requestUrl: URL, config: OAuthConfig): Promise<string> {
  const stateToken = requestUrl.searchParams.get('state') ?? '';
  const state = await decrypt(config, stateToken, `${config.origin}/oauth/callback`, 'asana_state');
  const redirect = new URL(state.redirect_uri!);
  const upstreamError = requestUrl.searchParams.get('error');
  if (upstreamError) {
    redirect.searchParams.set('error', 'access_denied');
    if (state.oauth_state) redirect.searchParams.set('state', state.oauth_state);
    redirect.searchParams.set('iss', config.origin);
    return redirect.toString();
  }
  const code = requestUrl.searchParams.get('code');
  if (!code) throw new OAuthError('invalid_request', 'Asana returned no authorization code.');
  const token = await asanaToken(config, {
    grant_type: 'authorization_code', code, redirect_uri: `${config.origin}/oauth/callback`,
    code_verifier: state.asana_code_verifier!,
  });
  const subject = String(token.data?.gid ?? token.data?.id ?? await asanaUserId(token.access_token));
  const asanaExpiresAt = token.expires_in ? Math.floor(Date.now() / 1000) + token.expires_in : undefined;
  const bridgeCode = await encrypt(config, {
    kind: 'authorization_code', sub: subject, client_id: state.client_id, redirect_uri: state.redirect_uri,
    resource: state.resource, scope: state.scope, code_challenge: state.code_challenge,
    asana_access_token: token.access_token, asana_refresh_token: token.refresh_token, asana_expires_at: asanaExpiresAt,
  }, `${config.origin}/oauth/token`, 120);
  redirect.searchParams.set('code', bridgeCode);
  if (state.oauth_state) redirect.searchParams.set('state', state.oauth_state);
  redirect.searchParams.set('iss', config.origin);
  return redirect.toString();
}

function positiveLifetime(upstreamExpiresAt?: number): number {
  const now = Math.floor(Date.now() / 1000);
  if (upstreamExpiresAt !== undefined && upstreamExpiresAt <= now + 30) {
    throw new OAuthError('invalid_grant', 'The upstream Asana token has expired.', 401);
  }
  return Math.min(3600, upstreamExpiresAt ? upstreamExpiresAt - now : 3600);
}

async function issueTokens(config: OAuthConfig, claims: BridgeClaims) {
  const ttl = positiveLifetime(claims.asana_expires_at);
  const common: BridgeClaims = {
    kind: 'access_token', sub: claims.sub, client_id: claims.client_id, resource: config.resource,
    scope: claims.scope, asana_access_token: claims.asana_access_token, asana_expires_at: claims.asana_expires_at,
  };
  const accessToken = await encrypt(config, common, config.resource, ttl);
  const refreshToken = await encrypt(config, {
    ...common, kind: 'refresh_token', asana_refresh_token: claims.asana_refresh_token,
  }, `${config.origin}/oauth/token`, 60 * 60 * 24 * 30);
  return { access_token: accessToken, token_type: 'Bearer', expires_in: ttl, refresh_token: refreshToken, scope: claims.scope };
}

export async function exchangeToken(form: URLSearchParams, config: OAuthConfig) {
  const grantType = form.get('grant_type');
  const clientId = form.get('client_id') ?? '';
  assertClient(config, clientId);
  if (form.get('resource') !== config.resource) throw new OAuthError('invalid_target', 'resource must match this MCP server.');
  if (grantType === 'authorization_code') {
    const code = await decrypt(config, form.get('code') ?? '', `${config.origin}/oauth/token`, 'authorization_code');
    if (code.client_id !== clientId || code.redirect_uri !== form.get('redirect_uri') || code.resource !== config.resource) {
      throw new OAuthError('invalid_grant', 'Authorization code binding does not match.');
    }
    const verifier = form.get('code_verifier') ?? '';
    if (!verifier || !secureEqual(s256(verifier), code.code_challenge)) throw new OAuthError('invalid_grant', 'PKCE verification failed.');
    return issueTokens(config, code);
  }
  if (grantType === 'refresh_token') {
    let refresh = await decrypt(config, form.get('refresh_token') ?? '', `${config.origin}/oauth/token`, 'refresh_token');
    if (refresh.client_id !== clientId || refresh.resource !== config.resource) throw new OAuthError('invalid_grant', 'Refresh token binding does not match.');
    if (refresh.asana_refresh_token) {
      const renewed = await asanaToken(config, { grant_type: 'refresh_token', refresh_token: refresh.asana_refresh_token });
      refresh = {
        ...refresh,
        asana_access_token: renewed.access_token,
        asana_refresh_token: renewed.refresh_token ?? refresh.asana_refresh_token,
        asana_expires_at: renewed.expires_in ? Math.floor(Date.now() / 1000) + renewed.expires_in : undefined,
      };
    } else if (refresh.asana_expires_at !== undefined && refresh.asana_expires_at <= Math.floor(Date.now() / 1000) + 30) {
      throw new OAuthError('invalid_grant', 'Asana supplied no usable refresh token.', 401);
    }
    return issueTokens(config, refresh);
  }
  throw new OAuthError('unsupported_grant_type', 'Only authorization_code and refresh_token grants are supported.');
}

export async function verifyMcpBearerToken(token: string | undefined, config: OAuthConfig): Promise<AuthInfo | undefined> {
  if (!token) return undefined;
  const claims = await decrypt(config, token, config.resource, 'access_token');
  if (claims.resource !== config.resource || !claims.asana_access_token || !claims.sub) throw new OAuthError('invalid_token', 'Access token is incomplete.', 401);
  const scopes = parseScopes(claims.scope, config.supportedScopes);
  return {
    token,
    clientId: claims.client_id,
    scopes,
    expiresAt: claims.exp,
    resource: new URL(config.resource),
    extra: { asanaAccessToken: claims.asana_access_token, asanaUserGid: claims.sub },
  };
}

export function jsonOAuthError(error: unknown): Response {
  const known = error instanceof OAuthError ? error : new OAuthError('server_error', 'OAuth request failed.', 500);
  return Response.json({ error: known.code, error_description: known.message }, {
    status: known.status,
    headers: { ...oauthCorsHeaders, 'cache-control': 'no-store', pragma: 'no-cache' },
  });
}

export const oauthCorsHeaders = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type',
};
