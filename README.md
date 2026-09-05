# Project-scoped Asana MCP

A maintained fork starting from [roychri/mcp-server-asana](https://github.com/roychri/mcp-server-asana), upstream commit `c4508aac54e210d49dbc9d7d8ad1fa98b9090a82` (MIT). Adds custom task types/statuses and a smaller, project-authorized tool surface. It supports both a local stdio transport and a stateless Streamable HTTP transport for Vercel.

## Run locally (stdio)

Requires Node.js **24.15 or newer**. Connect the stdio build to a client that can launch a local process.

```sh
npm ci --ignore-scripts
npm run typecheck
npm run build
npm test
npm audit --omit=dev
```

Configure these environment variables in the MCP client's secret/environment settings:

| Variable | Required | Meaning |
|---|---|---|
| `ASANA_ACCESS_TOKEN` | Yes | Asana PAT; keep it outside source control and chat. |
| `ASANA_ALLOWED_PROJECTS` | Yes | Comma-separated numeric project GIDs. No wildcard; empty configuration refuses startup. |
| `READ_ONLY_MODE` | No | Defaults to `true`. Only exact `false` enables supported writes. |

Launch `node /absolute/path/to/dist/index.js` with those variables. No environment file is loaded automatically. Do not copy the upstream unversioned `npx` command: it runs the upstream server, not this fork.

## Deploy on Vercel (Streamable HTTP)

The Next.js route at `/api/mcp` uses stateless Streamable HTTP; SSE and Redis are disabled. `/api/health` is an unauthenticated liveness check.

```sh
npm ci --ignore-scripts
npm run build:web
vercel deploy
```

Configure `ASANA_ALLOWED_PROJECTS`, `READ_ONLY_MODE`, and the Asana credential as Vercel environment variables, never in the repository. The deployed MCP URL is `https://<deployment>/api/mcp`.

**Authentication status:** the current HTTP route accepts the same single `ASANA_ACCESS_TOKEN` as the stdio server and does not yet authenticate its caller. Do not add a real Asana token to a public deployment. The safe preview deployment intentionally omits that token and therefore fails closed. Per-user Asana OAuth must wrap the route before production use.

## Custom task types and statuses

1. Call `asana_get_custom_types` for the target project. The response includes type IDs and status IDs, names, enabled flags and completion states.
2. Pass the IDs as `custom_type` and `custom_type_status_option` when creating/updating a task. To change only a status, `asana_set_task_type_status` uses the task's current type.
3. The server checks that the type belongs to an authorized project in the task's ancestry and the status is an enabled option of that type.
4. Updates send these fields **directly under `data`**, with `resource_subtype: "custom"`. They are not entries in `custom_fields`.
5. Creation validates the selection, creates a normal task via POST, then applies the custom type/status via PUT. A failed second step returns `partial_success` and `created_task_id`; reuse that task instead of creating a duplicate.
6. The server reads back custom type/status IDs and checks they match the request. Failed verification is reported explicitly. The UI's default type is not assumed to apply through the API.

Example tool arguments (replace these illustrative IDs with values returned by Asana):

```json
{
  "task_id": "12345",
  "custom_type": "67890",
  "custom_type_status_option": "67891"
}
```

Subtasks use the same type/status workflow. They do not gain direct project membership merely to satisfy authorization. Completing a custom task requires selecting its completion status; the generic `completed` boolean is rejected for such tasks.

Sources: [custom types](https://developers.asana.com/reference/custom-types), [list project types](https://developers.asana.com/reference/getcustomtypes), [task updates](https://developers.asana.com/reference/updatetask), [Asana discussion of POST/PUT behavior](https://forum.asana.com/t/create-tasks-and-update-tasks-dont-support-custom-task-types-request-to-extend-api-support/1137197).

## Supported tools

Read: `asana_list_allowed_projects`, `asana_get_project`, `asana_get_project_sections`, `asana_get_tasks_for_project`, `asana_get_task`, `asana_get_multiple_tasks_by_gid`, `asana_get_subtasks`, `asana_get_task_stories`, `asana_get_custom_types`.

Write (only when enabled): `asana_create_task`, `asana_create_subtask`, `asana_update_task`, `asana_set_task_type_status`, `asana_create_task_story`, `asana_set_parent_for_task`, `asana_add_task_dependencies`, `asana_create_section`, `asana_update_section`, `asana_add_task_to_section`.

Paginated lists return `{ "data": [...], "next_page": { "offset": "..." } }`. Continue with that offset until `next_page` is null. Custom-type discovery follows pagination automatically. Bulk reads accept up to 100 IDs; bulk writes are deliberately individual calls so successes/failures can be tracked per task. Do not blindly repeat a creation after a timeout: the API may have accepted it.

## Security boundary

- Read-only and tool availability are enforced at execution, not just hidden from `tools/list`.
- No deletion tools, global workspace/tag/task search, project creation or project membership changes are exposed. Legacy prompt/resource handlers are not registered.
- Task access checks every project membership and walks the parent chain (maximum 50 levels). At least one allowed project is required. Any membership in an unlisted project, even on an ancestor, denies access; this also blocks tasks multi-homed outside the configured scope.
- Relevant target parents, sections and dependency tasks are checked. Membership is reread per call; no persistent authorization cache is used.
- Arguments are schema-validated, unknown top-level parameters are rejected, and body sizes are capped.
- The active server does not log request bodies, tokens or raw API exceptions. Errors expose a generic message and HTTP status where available. Task data is still intentionally returned to the connected AI client.
- Each server client has its own Asana SDK client/token. There is no shared SDK authentication singleton. Requests time out after 30 seconds.
- Production dependencies are exact versions with a committed lockfile. The build leaves dependencies external, avoiding hidden copies of an old SDK inside the bundle. This package is marked private to prevent accidental npm publication.

The allowlist is an application check, not a replacement for Asana permissions. Use an account with only the access this integration needs. Concurrent membership changes between the check and the API request cannot be made atomic by this MCP. Authorized task responses can include related metadata and links; this is not a field-level data-loss-prevention filter. Treat task text and comments as untrusted content, and keep the AI client's action approvals enabled. The server does not itself prevent a model from misunderstanding a legitimate tool request.

## Validation and limitations

The test suite exercises real Asana SDK requests against a local HTTP fixture: project/ancestor authorization, read-only enforcement, disabled operations, malformed input, status validation, pagination, POST→PUT, partial failure and readback mismatch. It also launches the built stdio server and verifies its advertised capabilities and write blocking. The Vercel build and MCP `initialize`/`tools/list` handshake are checked separately.

No test uses a real Asana credential. Live custom-type permissions and behavior must still be verified on a disposable task before migrating existing projects. A clean dependency audit is not a complete security certification.

Upstream code remains in the repository for reference, but only `src/index.ts` and `src/hardened-tools.ts` define the active MCP surface.
