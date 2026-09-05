import { finishAsanaAuthorization, jsonOAuthError, readOAuthConfig } from '../../../src/oauth.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: Request): Promise<Response> {
  try {
    return Response.redirect(await finishAsanaAuthorization(new URL(request.url), readOAuthConfig()), 302);
  } catch (error) { return jsonOAuthError(error); }
}
