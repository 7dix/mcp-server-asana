import { jsonOAuthError, metadata, oauthCorsHeaders, readOAuthConfig } from '../../../src/oauth.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export function GET(): Response {
  try {
    return Response.json(metadata(readOAuthConfig()), {
      headers: { ...oauthCorsHeaders, 'cache-control': 'public, max-age=3600' },
    });
  } catch (error) { return jsonOAuthError(error); }
}

export function OPTIONS(): Response { return new Response(null, { status: 204, headers: oauthCorsHeaders }); }
