import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { AsanaClientWrapper } from './asana-client-wrapper.js';
import { createHardenedTools } from './hardened-tools.js';
import { readSecurityConfig, SafeError } from './security.js';

interface RegistrationOptions { requestOAuth?: boolean; resourceMetadataUrl?: string }

/** Register the same project-scoped tool surface on stdio and HTTP servers. */
export function registerAsanaTools(
  server: Server,
  env: NodeJS.ProcessEnv = process.env,
  options: RegistrationOptions = {},
): void {
  const config = readSecurityConfig(env);
  const environmentToken = env.ASANA_ACCESS_TOKEN;
  if (!options.requestOAuth && !environmentToken) throw new SafeError('ASANA_ACCESS_TOKEN is required.');

  // Tool definitions do not perform network requests. HTTP calls receive the
  // decrypted, per-user Asana token through the authenticated request context.
  const catalogue = createHardenedTools(new AsanaClientWrapper(environmentToken ?? 'oauth-required'), config);
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: catalogue.tools }));
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const requestToken = extra.authInfo?.extra?.asanaAccessToken;
    const token = options.requestOAuth && typeof requestToken === 'string' ? requestToken : environmentToken;
    if (!token) throw new SafeError('A valid Asana OAuth connection is required.');
    const requiredScopes = catalogue.scopesFor(request.params.name);
    if (options.requestOAuth && requiredScopes?.some(scope => !extra.authInfo?.scopes.includes(scope))) {
      const challenge = `Bearer${options.resourceMetadataUrl ? ` resource_metadata="${options.resourceMetadataUrl}"` : ''} scope="${requiredScopes.join(' ')}"`;
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: 'The OAuth connection does not grant the scopes required by this tool.' }) }],
        isError: true,
        _meta: { 'mcp/www_authenticate': [challenge] },
      };
    }
    return createHardenedTools(new AsanaClientWrapper(token), config).call(request);
  });
}
