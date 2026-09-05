import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { AsanaClientWrapper } from './asana-client-wrapper.js';
import { createHardenedTools } from './hardened-tools.js';
import { readSecurityConfig, SafeError } from './security.js';

/** Register the same project-scoped tool surface on stdio and HTTP servers. */
export function registerAsanaTools(server: Server, env: NodeJS.ProcessEnv = process.env): void {
  const config = readSecurityConfig(env);
  const token = env.ASANA_ACCESS_TOKEN;
  if (!token) throw new SafeError('ASANA_ACCESS_TOKEN is required.');

  const handlers = createHardenedTools(new AsanaClientWrapper(token), config);
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: handlers.tools }));
  server.setRequestHandler(CallToolRequestSchema, handlers.call);
}
