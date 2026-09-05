import { exchangeToken, jsonOAuthError, oauthCorsHeaders, readOAuthConfig } from '../../../src/oauth.js';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request: Request): Promise<Response> {
  try {
    const form = new URLSearchParams(await request.text());
    return Response.json(await exchangeToken(form, readOAuthConfig()), {
      headers: { ...oauthCorsHeaders, 'cache-control': 'no-store', pragma: 'no-cache' },
    });
  } catch (error) { return jsonOAuthError(error); }
}

export function OPTIONS(): Response { return new Response(null, { status: 204, headers: oauthCorsHeaders }); }
