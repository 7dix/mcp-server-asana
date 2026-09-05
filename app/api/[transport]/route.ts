import { createMcpHandler } from 'mcp-handler';
import { registerAsanaTools } from '../../../src/mcp-server.js';
import { VERSION } from '../../../src/version.js';

export const runtime = 'nodejs';
export const maxDuration = 60;

const handler = createMcpHandler(
  server => registerAsanaTools(server.server),
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

export { handler as GET, handler as POST, handler as DELETE };
