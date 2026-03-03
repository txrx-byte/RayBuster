import { Env } from '../types';
import { hashIp, decryptIp } from '../lib/crypto';
import { isValidIp } from '../lib/utils';
import { BLOCK_CACHE, CACHE_TTL } from '../lib/cache';

export async function handleApiStats(request: Request, env: Env) {
  try {
    const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: `SELECT SUM(_sample_interval) as request_count, AVG(double1) as avg_tcp_rtt, AVG(double2) as avg_app_rtt, index1 as verdict FROM raybuster_metrics WHERE timestamp > NOW() - INTERVAL '1 HOUR' GROUP BY index1 ORDER BY request_count DESC`
      })
    });
    if (!response.ok) return new Response(`API Error: ${response.statusText}`, { status: 502 });
    const result = await response.json() as { data: any[] };
    return Response.json(result.data || []);
  } catch (e) { return new Response(`Internal Error: ${e}`, { status: 500 }); }
}

export async function handleApiAnomalies(request: Request, env: Env) {
  try {
    const { results } = await env.DB.prepare(`SELECT * FROM telemetry ORDER BY created_at DESC LIMIT 100`).all();
    return Response.json(results);
  } catch (e) { return new Response(`DB Error: ${e}`, { status: 500 }); }
}

export async function handleApiBlocklist(request: Request, env: Env) {
  try {
    const body = await request.json() as { identifier: string; type?: string; reason?: string };
    if (!body.identifier) return new Response('Missing identifier', { status: 400 });

    let finalIdentifier = body.identifier;
    let identifierType = body.type || 'IP';

    if (identifierType === 'IP') {
      if (!isValidIp(body.identifier)) {
        return new Response('Invalid IP address', { status: 400 });
      }
      finalIdentifier = await hashIp(body.identifier, env.IP_HASHING_SALT);
    }

    await env.DB.prepare("INSERT OR IGNORE INTO blocklist (identifier, identifier_type, reason) VALUES (?, ?, ?)")
      .bind(finalIdentifier, identifierType, body.reason || 'Manual Admin Block').run();
    BLOCK_CACHE.set(finalIdentifier, { blocked: true, expires: Date.now() + CACHE_TTL * 60 });
    return new Response('OK', { status: 200 });
  } catch (e) { return new Response(`DB Error: ${e}`, { status: 500 }); }
}

export async function handleApiBlocklistBulk(request: Request, env: Env) {
  try {
    const body = await request.json() as { identifiers: string[] };
    if (!body.identifiers || !Array.isArray(body.identifiers) || body.identifiers.length === 0) {
      return new Response('Missing or empty identifiers array', { status: 400 });
    }
    
    const statements = await Promise.all(body.identifiers.map(async (identifier) => {
      if (!isValidIp(identifier)) {
        console.warn(`Invalid identifier in bulk blocklist: ${identifier}`);
        return null;
      }
      const hashedIdentifier = await hashIp(identifier, env.IP_HASHING_SALT);
      BLOCK_CACHE.set(hashedIdentifier, { blocked: true, expires: Date.now() + CACHE_TTL * 60 });
      return env.DB.prepare("INSERT OR IGNORE INTO blocklist (identifier, identifier_type, reason) VALUES (?, 'IP', 'Bulk Admin Block')").bind(hashedIdentifier);
    }));

    const validStatements = statements.filter(s => s !== null) as any[];

    if (validStatements.length > 0) {
      const chunkSize = 50;
      for (let i = 0; i < validStatements.length; i += chunkSize) {
        await env.DB.batch(validStatements.slice(i, i + chunkSize));
      }
    } else {
      return new Response('No valid identifiers to block', { status: 400 });
    }
    
    return new Response('OK', { status: 200 });
  } catch (e) { return new Response(`DB Error: ${e}`, { status: 500 }); }
}

export async function handleApiDecryptIp(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as { encryptedIp: string; iv: string };
    if (!body.encryptedIp || !body.iv) {
      return new Response('Missing encryptedIp or iv', { status: 400 });
    }

    const decryptedIp = await decryptIp(body.encryptedIp, body.iv, env);
    return Response.json({ decryptedIp });
  } catch (e) {
    return new Response(`Decryption Error: ${(e as Error).message}`, { status: 500 });
  }
}
