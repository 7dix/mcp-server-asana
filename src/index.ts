#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { VERSION } from './version.js';
import { AsanaClientWrapper } from './asana-client-wrapper.js';
import { createHardenedTools } from './hardened-tools.js';
import { readSecurityConfig, publicError, SafeError } from './security.js';
async function main() {
  const config = readSecurityConfig();
  const token = process.env.ASANA_ACCESS_TOKEN;
  if (!token) throw new SafeError('ASANA_ACCESS_TOKEN is required.');
  const handlers = createHardenedTools(new AsanaClientWrapper(token), config);
  const server = new Server({ name: 'Asana MCP (project scoped)', version: VERSION }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: handlers.tools }));
  server.setRequestHandler(CallToolRequestSchema, handlers.call);
  // Legacy prompts/resources bypass project authorization and are not registered.
  await server.connect(new StdioServerTransport());
}
main().catch(error => { console.error(JSON.stringify(publicError(error))); process.exitCode = 1; });
