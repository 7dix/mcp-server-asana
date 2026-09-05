#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { VERSION } from './version.js';
import { registerAsanaTools } from './mcp-server.js';
import { publicError } from './security.js';
async function main() {
  const server = new Server({ name: 'Asana MCP (project scoped)', version: VERSION }, { capabilities: { tools: {} } });
  registerAsanaTools(server);
  // Legacy prompts/resources bypass project authorization and are not registered.
  await server.connect(new StdioServerTransport());
}
main().catch(error => { console.error(JSON.stringify(publicError(error))); process.exitCode = 1; });
