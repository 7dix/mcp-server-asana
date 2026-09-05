export class SafeError extends Error {
  constructor(message: string, public readonly details?: Record<string, unknown>) { super(message); }
}
export interface SecurityConfig { projects: Set<string>; readOnly: boolean }
export function readSecurityConfig(env: NodeJS.ProcessEnv = process.env): SecurityConfig {
  const projects = new Set((env.ASANA_ALLOWED_PROJECTS ?? '').split(',').map(x => x.trim()).filter(Boolean));
  if (!projects.size || [...projects].some(x => !/^\d+$/.test(x))) throw new SafeError('ASANA_ALLOWED_PROJECTS must contain explicit comma-separated project GIDs.');
  if (env.READ_ONLY_MODE !== undefined && !['true', 'false'].includes(env.READ_ONLY_MODE)) throw new SafeError('READ_ONLY_MODE must be true or false.');
  return { projects, readOnly: env.READ_ONLY_MODE !== 'false' };
}
export function publicError(error: unknown): Record<string, unknown> {
  if (error instanceof SafeError) return { error: error.message, ...error.details };
  const status = (error as { status?: unknown })?.status;
  return { error: 'Asana request failed. Check permissions, supplied IDs and API availability.',
    ...(typeof status === 'number' && status >= 400 && status <= 599 ? { status } : {}) };
}
interface ScopeClient {
  getTask(id: string, opts: Record<string, unknown>): Promise<any>;
  getSection(id: string): Promise<any>;
}
/** Endpoint authorization, independent of what the MCP client chooses to display. */
export class ProjectScope {
  constructor(private readonly client: ScopeClient, readonly config: SecurityConfig) {}
  project(id: string): string {
    if (!/^\d+$/.test(id) || !this.config.projects.has(id)) throw new SafeError('Project is outside the configured scope.');
    return id;
  }
  async task(id: string): Promise<{ task: any; projects: string[] }> {
    const projects = new Set<string>(); const visited = new Set<string>();
    let current: string | undefined = id; let original: any;
    // No long-lived authorization cache: memberships may change between calls.
    while (current) {
      if (!/^\d+$/.test(current) || visited.has(current) || visited.size >= 50) throw new SafeError('Task ancestry could not be authorized.');
      visited.add(current);
      const task = await this.client.getTask(current, { opt_fields: 'projects.gid,parent.gid,custom_type.gid,custom_type_status_option.gid,completed' });
      if (!task || !Array.isArray(task.projects) || !Object.hasOwn(task, 'parent')) throw new SafeError('Task membership could not be verified.');
      original ??= task;
      for (const project of task.projects) projects.add(this.project(project.gid));
      current = task.parent?.gid;
    }
    if (!projects.size) throw new SafeError('Task has no allowed project or ancestor.');
    return { task: original, projects: [...projects] };
  }
  async section(id: string): Promise<void> {
    if (!/^\d+$/.test(id)) throw new SafeError('Invalid section GID.');
    const section = await this.client.getSection(id);
    this.project(section?.project?.gid ?? '');
  }
}
