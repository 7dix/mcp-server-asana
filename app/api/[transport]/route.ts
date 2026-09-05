import { createMcpHandler, withMcpAuth } from 'mcp-handler';
import { registerAsanaTools } from '../../../src/mcp-server.js';
import { readOAuthConfig, runtimeConfigurationError, verifyMcpBearerToken } from '../../../src/oauth.js';
import { VERSION } from '../../../src/version.js';

export const runtime = 'nodejs';
export const maxDuration = 60;

const handler = createMcpHandler(
  server => registerAsanaTools(server.server, process.env, {
    requestOAuth: true,
    resourceMetadataUrl: `${process.env.MCP_PUBLIC_ORIGIN}/.well-known/oauth-protected-resource`,
  }),
  {
    capabilities: { tools: {} },
    serverInfo: { name: 'Asana MCP (project scoped)', version: VERSION },
  },
  {
    basePath: '/api',
    disableSse: true,
    sessionIdGenerator: undefined,
    maxDuration,
    verboseLogs: false,
  },
);

const authenticated = withMcpAuth(
  handler,
  async (_request, token) => verifyMcpBearerToken(token, readOAuthConfig()),
  { required: true },
);

async function configured(request: Request): Promise<Response> {
  const error = runtimeConfigurationError();
  if (error) return Response.json({ error: 'service_not_configured', error_description: error }, { status: 503 });
  return authenticated(request);
}

export { configured as GET, configured as POST, configured as DELETE };
