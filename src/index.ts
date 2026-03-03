// src/index.ts
import { analyzePhysics, TelemetryData, Verdict } from './heuristics';
import dashboardHtml from './dashboard.html';

export interface Env {
  DB: D1Database;
  ANALYTICS: AnalyticsEngineDataset;
  ADMIN_TOKEN: string;
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
}

// Global in-memory cache for blocklist
const BLOCK_CACHE = new Map<string, { blocked: boolean, expires: number }>();
const CACHE_TTL = 60000; // 60 seconds

// --- CRYPTO UTILITIES ---

async function signPayload(payload: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  const sigHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${btoa(payload)}.${sigHex}`;
}

async function verifyPayload(token: string, secret: string): Promise<string | null> {
  try {
    const [b64Payload, sigHex] = token.split('.');
    if (!b64Payload || !sigHex) return null;
    const payload = atob(b64Payload);
    const expected = await signPayload(payload, secret);
    if (token === expected) return payload;
    return null;
  } catch { return null; }
}

async function hashIp(ip: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(ip);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

// --- MAIN WORKER ---

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
    const rayId = request.headers.get('cf-ray') || 'unknown';
    const cf = request.cf as any;
    const tcpRtt = cf?.clientTcpRtt || 0;
    const asn = cf?.asn || 0;

    // 1. PRE-FETCH BLOCKING
    if (!url.pathname.startsWith('/admin') && !url.pathname.startsWith('/api/')) {
      const cached = BLOCK_CACHE.get(ip);
      if (cached && cached.expires > Date.now()) {
        if (cached.blocked) return new Response('Forbidden: RayBuster Blocked', { status: 403 });
      } else {
        const blockedRow = await env.DB.prepare(
          'SELECT 1 FROM blocklist WHERE identifier = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) LIMIT 1'
        ).bind(ip).first();
        BLOCK_CACHE.set(ip, { blocked: !!blockedRow, expires: Date.now() + CACHE_TTL });
        if (blockedRow) return new Response('Forbidden: RayBuster Blocked', { status: 403 });
      }
    }

    // 2. DASHBOARD / API AUTH
    const tokenParams = url.searchParams.get('token');
    const authHeader = request.headers.get('Authorization');
    const isAuthenticated = (authHeader === `Bearer ${env.ADMIN_TOKEN}`) || (tokenParams === env.ADMIN_TOKEN);

    if (url.pathname.startsWith('/api/') || url.pathname === '/admin') {
      if (!isAuthenticated) return new Response('Unauthorized', { status: 401 });
      
      if (url.pathname === '/admin') {
        return new Response(dashboardHtml, { 
          headers: { 
            'content-type': 'text/html;charset=UTF-8',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; connect-src 'self';",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff'
          } 
        });
      }
      if (url.pathname === '/api/stats') return await handleApiStats(request, env);
      if (url.pathname === '/api/anomalies') return await handleApiAnomalies(request, env);
      if (url.pathname === '/api/blocklist') return await handleApiBlocklist(request, env);
      if (url.pathname === '/api/blocklist/bulk') return await handleApiBlocklistBulk(request, env);
    }

    // 3. TELEMETRY INGEST (The Beacon Return)
    if (url.pathname === '/__telemetry-log' && request.method === 'POST') {
      return await handleTelemetryIngest(request, env, ctx, ip, cf);
    }

    // 4. ZERO-TRUST SESSION CHECK
    const cookieHeader = request.headers.get('Cookie') || '';
    const sessionMatch = cookieHeader.match(/rb_session=([^;]+)/);
    let hasValidSession = false;

    if (sessionMatch) {
      const sessionPayload = await verifyPayload(sessionMatch[1], env.ADMIN_TOKEN);
      if (sessionPayload) {
         const [sessIp, expiryStr] = sessionPayload.split('|');
         if (sessIp === ip && parseInt(expiryStr, 10) > Date.now()) {
            hasValidSession = true;
         }
      }
    }

    // Bypass Challenge for SEO Bots (They still get TCP Physics checked inline)
    const ua = (request.headers.get('User-Agent') || '').toLowerCase();
    const isSeoBotUa = /googlebot|bingbot|yandex|baiduspider|twitterbot|facebookexternalhit|linkedinbot/.test(ua);
    const asOrg = (cf?.asOrganization || '').toLowerCase();
    const SEO_ASNS = new Set([15169, 396982, 8075, 32934, 22822, 32392, 45102]);
    const isVerifiedBotAsn = /google|bing|microsoft|yahoo|yandex|baidu|twitter|facebook|meta|linkedin/i.test(asOrg) || SEO_ASNS.has(asn);
    const isSeoBot = isSeoBotUa && isVerifiedBotAsn;

    const secFetchDest = request.headers.get('Sec-Fetch-Dest');
    const secFetchMode = request.headers.get('Sec-Fetch-Mode');
    const isHtmlRequest = secFetchDest === 'document' || secFetchMode === 'navigate' || (request.headers.get('Accept') || '').includes('text/html');

    // 5. INTERSTITIAL CHALLENGE (The "No Free Hits" mechanism)
    if (!hasValidSession && isHtmlRequest && !isSeoBot) {
      const ts = Date.now();
      const payload = `${rayId}|${tcpRtt}|${ts}|${asn}`;
      const challengeToken = await signPayload(payload, env.ADMIN_TOKEN);
      
      const challengeHtml = `
      <!DOCTYPE html><html><head><meta charset="utf-8"><title>Security Check</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>body{background:#0a0a0a;color:#0f8;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}</style>
      </head><body><div id="msg">RayBuster: Verifying network physics...</div>
      <script>
        setTimeout(function(){
          fetch('/__telemetry-log',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:'${challengeToken}'})})
          .then(r=>{if(r.ok)location.reload();else document.getElementById('msg').innerText='Access Denied: Anomaly Detected.'})
          .catch(()=>document.getElementById('msg').innerText='Connection Failed.');
        }, 500);
      </script></body></html>`;
      
      return new Response(challengeHtml, {
        status: 200, // Return 200 so browsers don't panic, but don't cache it
        headers: { 'Content-Type': 'text/html', 'Cache-Control': 'no-store, no-cache, must-revalidate', 'CF-Ray': rayId }
      });
    }

    // 6. INLINE TCP PHYSICS (For APIs, Assets, and SEO Bots that bypass the interstitial)
    if (!hasValidSession) {
      const country = cf?.country || 'XX';
      const colo = cf?.colo || 'UNK';
      const lat = cf?.latitude ? parseFloat(cf.latitude) : undefined;
      const lon = cf?.longitude ? parseFloat(cf.longitude) : undefined;
      const preliminaryVerdict = analyzePhysics({ ip, country, colo, tcpRtt, appRtt: 0, asn, lat, lon });
      
      // Async DB logging
      ctx.waitUntil(processTelemetry(request, env, rayId, ip, cf, tcpRtt));

      // Instant block for impossible travel even on APIs
      if (preliminaryVerdict.status !== 'CLEAN') {
         return new Response('Forbidden: Network Anomaly', { status: 403 });
      }
    }

    // 7. PROXY TO ORIGIN (User is verified!)
    const workerRequest = new Request(request);
    const response = await fetch(workerRequest);
    const newHeaders = new Headers(response.headers);
    newHeaders.set('X-RayBuster-Status', hasValidSession ? 'Verified' : 'Bypass-TCP-Checked');
    return new Response(response.body, { status: response.status, headers: newHeaders });
  },
};

// --- HANDLERS ---

async function handleTelemetryIngest(request: Request, env: Env, ctx: ExecutionContext, ip: string, cf: any) {
  try {
    const { token } = await request.json() as any;
    if (!token) return new Response('Bad Request', { status: 400 });

    const payload = await verifyPayload(token, env.ADMIN_TOKEN);
    if (!payload) {
      // SPOOFING ATTEMPT: Cryptographic failure. Instant ban.
      await env.DB.prepare("INSERT OR IGNORE INTO blocklist (identifier, identifier_type, reason) VALUES (?, 'IP', 'TAMPERING: Invalid Telemetry Signature')").bind(ip).run();
      BLOCK_CACHE.set(ip, { blocked: true, expires: Date.now() + CACHE_TTL * 60 });
      return new Response('Forbidden: Tampering Detected', { status: 403 });
    }

    const [reqRayId, reqTcpRttStr, reqTsStr, reqAsnStr] = payload.split('|');
    const reqTcpRtt = parseInt(reqTcpRttStr, 10);
    const reqTs = parseInt(reqTsStr, 10);
    const reqAsn = parseInt(reqAsnStr, 10);

    // SERVER-SIDE RTT CALCULATION
    const totalTime = Date.now() - reqTs;
    const appRtt = Math.max(0, totalTime - reqTcpRtt); 
    
    const colo = cf?.colo || 'UNK';
    const country = cf?.country || 'XX';
    const lat = cf?.latitude ? parseFloat(cf.latitude) : undefined;
    const lon = cf?.longitude ? parseFloat(cf.longitude) : undefined;
    const ipHash = await hashIp(ip);

    const verdict = analyzePhysics({ ip, country, colo, tcpRtt: reqTcpRtt, appRtt, asn: reqAsn, lat, lon });

    env.ANALYTICS.writeDataPoint({
      blobs: [reqRayId, ipHash, colo, country],
      doubles: [reqTcpRtt, appRtt],
      indexes: [verdict.status]
    });

    if (verdict.status !== 'CLEAN') {
      ctx.waitUntil((async () => {
        await env.DB.prepare(
          `INSERT INTO telemetry (ray_id, ip_raw, ip_hash, country_code, colo_code, asn, tcp_rtt, app_rtt, verdict, reason, created_at) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
        ).bind(reqRayId, ip, ipHash, country, colo, reqAsn, reqTcpRtt, appRtt, verdict.status, verdict.reason || '').run();
        await checkAutoMitigate(ip, env);
      })());
      return new Response('Blocked', { status: 403 });
    }

    // ISSUE VERIFIED SESSION COOKIE (Valid for 1 Hour)
    const sessionExpiry = Date.now() + (60 * 60 * 1000);
    const sessionCookieToken = await signPayload(`${ip}|${sessionExpiry}`, env.ADMIN_TOKEN);
    const headers = new Headers();
    headers.set('Set-Cookie', `rb_session=${sessionCookieToken}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax`);
    
    return new Response('OK', { status: 200, headers });
  } catch (e) {
    return new Response('Invalid Beacon', { status: 400 });
  }
}

async function processTelemetry(request: Request, env: Env, rayId: string, ip: string, cf: any, tcpRtt: number) {
  const colo = cf?.colo || 'UNK';
  const country = cf?.country || 'XX';
  const asn = cf?.asn || 0;
  const lat = cf?.latitude ? parseFloat(cf.latitude) : undefined;
  const lon = cf?.longitude ? parseFloat(cf.longitude) : undefined;
  const ipHash = await hashIp(ip);

  const preliminaryVerdict = analyzePhysics({ ip, country, colo, tcpRtt, appRtt: 0, asn, lat, lon });

  try {
    env.ANALYTICS.writeDataPoint({ blobs: [rayId, ipHash, colo, country], doubles: [tcpRtt, 0], indexes: [preliminaryVerdict.status] });
  } catch (e) { console.error("AE Write Failed", e); }

  if (preliminaryVerdict.status !== 'CLEAN') {
    try {
      await env.DB.prepare(
        `INSERT INTO telemetry (ray_id, ip_raw, ip_hash, country_code, colo_code, asn, tcp_rtt, verdict, reason, created_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
      ).bind(rayId, ip, ipHash, country, colo, asn, tcpRtt, preliminaryVerdict.status, preliminaryVerdict.reason || '').run();
      await checkAutoMitigate(ip, env);
    } catch (e) { console.error("D1 Insert Failed", e); }
  }
}

async function checkAutoMitigate(ip: string, env: Env) {
  try {
    const { count } = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM telemetry WHERE ip_raw = ? AND verdict IN ('ANOMALY', 'BOT') AND created_at > datetime('now', '-1 hour')"
    ).bind(ip).first() as { count: number };

    if (count >= 5) {
      await env.DB.prepare("INSERT OR IGNORE INTO blocklist (identifier, identifier_type, reason) VALUES (?, 'IP', 'AUTONOMOUS_MITIGATION: High Frequency')").bind(ip).run();
      BLOCK_CACHE.set(ip, { blocked: true, expires: Date.now() + CACHE_TTL * 60 });
    }
  } catch (e) {}
}

async function handleApiStats(request: Request, env: Env) {
  try {
    const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.CF_API_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: `SELECT SUM(_sample_interval) as request_count, AVG(double1) as avg_tcp_rtt, AVG(double2) as avg_app_rtt, index1 as verdict FROM sentinel_metrics WHERE timestamp > NOW() - INTERVAL '1 HOUR' GROUP BY index1 ORDER BY request_count DESC`
      })
    });
    if (!response.ok) return new Response(`API Error: ${response.statusText}`, { status: 502 });
    const result = await response.json() as { data: any[] };
    return Response.json(result.data || []);
  } catch (e) { return new Response(`Internal Error: ${e}`, { status: 500 }); }
}

async function handleApiAnomalies(request: Request, env: Env) {
  try {
    const { results } = await env.DB.prepare(`SELECT * FROM telemetry ORDER BY created_at DESC LIMIT 100`).all();
    return Response.json(results);
  } catch (e) { return new Response(`DB Error: ${e}`, { status: 500 }); }
}

async function handleApiBlocklist(request: Request, env: Env) {
  try {
    const body = await request.json() as { identifier: string; type?: string; reason?: string };
    if (!body.identifier) return new Response('Missing identifier', { status: 400 });
    await env.DB.prepare("INSERT OR IGNORE INTO blocklist (identifier, identifier_type, reason) VALUES (?, ?, ?)")
      .bind(body.identifier, body.type || 'IP', body.reason || 'Manual Admin Block').run();
    BLOCK_CACHE.set(body.identifier, { blocked: true, expires: Date.now() + CACHE_TTL * 60 });
    return new Response('OK', { status: 200 });
  } catch (e) { return new Response(`DB Error: ${e}`, { status: 500 }); }
}

async function handleApiBlocklistBulk(request: Request, env: Env) {
  try {
    const body = await request.json() as { identifiers: string[] };
    if (!body.identifiers || !Array.isArray(body.identifiers)) return new Response('Missing identifiers', { status: 400 });
    
    const statements = body.identifiers.map(ip => {
      BLOCK_CACHE.set(ip, { blocked: true, expires: Date.now() + CACHE_TTL * 60 });
      return env.DB.prepare("INSERT OR IGNORE INTO blocklist (identifier, identifier_type, reason) VALUES (?, 'IP', 'Bulk Admin Block')").bind(ip);
    });

    if (statements.length > 0) {
      // Chunk batches to avoid D1 limits (max 100 statements per batch usually, but let's be safe)
      const chunkSize = 50;
      for (let i = 0; i < statements.length; i += chunkSize) {
        await env.DB.batch(statements.slice(i, i + chunkSize));
      }
    }
    
    return new Response('OK', { status: 200 });
  } catch (e) { return new Response(`DB Error: ${e}`, { status: 500 }); }
}
