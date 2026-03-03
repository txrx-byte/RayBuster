// src/index.ts
import { analyzePhysics, TelemetryData, Verdict } from './heuristics';
import dashboardHtml from './dashboard.html';

export interface Env {
  DB: D1Database;
  ANALYTICS: AnalyticsEngineDataset;
  ADMIN_TOKEN: string;
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
  IP_HASHING_SALT: string; // Add this for salted IP hashing
  ENCRYPTION_KEY: string;
  ADMIN_IP_ALLOWLIST?: string; // Optional: Comma-separated list of IPs/CIDR for admin access
}

// Placeholder for the actual key derived from env.ENCRYPTION_KEY
let ENCRYPTION_KEY_CACHE: CryptoKey | null = null;

async function getEncryptionKey(env: Env): Promise<CryptoKey> {
  if (ENCRYPTION_KEY_CACHE) {
    return ENCRYPTION_KEY_CACHE;
  }
  // The env.ENCRYPTION_KEY should be a base64 encoded AES key
  const keyBuffer = Uint8Array.from(atob(env.ENCRYPTION_KEY), c => c.charCodeAt(0));
  ENCRYPTION_KEY_CACHE = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    'AES-GCM',
    true,
    ['encrypt', 'decrypt']
  );
  return ENCRYPTION_KEY_CACHE;
}

async function encryptIp(ip: string, env: Env): Promise<{ encryptedIp: string; iv: string }> {
  const key = await getEncryptionKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM recommended IV length is 12 bytes
  const encodedIp = new TextEncoder().encode(ip);

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encodedIp
  );

  const encryptedIp = btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
  const ivString = btoa(String.fromCharCode(...iv));

  return { encryptedIp, iv: ivString };
}

async function decryptIp(encryptedIp: string, ivString: string, env: Env): Promise<string> {
  const key = await getEncryptionKey(env);
  const encryptedBuffer = Uint8Array.from(atob(encryptedIp), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivString), c => c.charCodeAt(0));

  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encryptedBuffer
  );

  return new TextDecoder().decode(decryptedBuffer);
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

// Constant-time string comparison to prevent timing attacks
function constantTimeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) {
        return false;
    }
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

async function verifyPayload(token: string, secret: string): Promise<string | null> {
  try {
    const [b64Payload, sigHex] = token.split('.');
    if (!b64Payload || !sigHex) return null;
    
    const payload = atob(b64Payload);
    const expectedToken = await signPayload(payload, secret);

    if (constantTimeEquals(token, expectedToken)) {
      return payload;
    }
    return null;
  } catch { return null; }
}

async function hashIp(ip: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(ip + salt);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

// --- POW UTILITIES ---

const POW_DIFFICULTY = 6;

async function generatePoWChallenge(ip: string, rayId: string, secret: string): Promise<string> {
  const nonce = `${ip}|${rayId}|${Date.now()}`;
  return await signPayload(nonce, secret);
}

async function verifyPoW(token: string, solution: string, difficulty: number, secret: string): Promise<{ip: string, rayId: string} | null> {
  try {
    const payload = await verifyPayload(token, secret);
    if (!payload) return null;
    
    const [ip, rayId, ts] = payload.split('|');
    if (Date.now() - parseInt(ts, 10) > 600000) return null; // 10 min expiry

    const encoder = new TextEncoder();
    const data = encoder.encode(token + solution);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hashBuffer);
    
    let zeros = 0;
    for (let i = 0; i < hashArray.length; i++) {
      if (hashArray[i] === 0) { zeros += 2; }
      else if (hashArray[i] < 16) { zeros += 1; break; }
      else break;
    }
    if (zeros >= difficulty) return { ip, rayId };
    return null;
  } catch { return null; }
}

async function serveChallenge(request: Request, env: Env, ip: string, rayId: string, cf: any): Promise<Response> {
  const ts = Date.now();
  const tcpRtt = cf?.clientTcpRtt || 0;
  const asn = cf?.asn || 0;
  const payload = `${ip}|${rayId}|${tcpRtt}|${ts}|${asn}`;
  const challengeToken = await signPayload(payload, env.ADMIN_TOKEN);
  
  const challengeHtml = `
      <!DOCTYPE html><html><head><meta charset="utf-8"><title>Security Check</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>body{background:#0a0a0a;color:#0f8;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}</style>
      </head><body><div id="msg">RayBuster: Verifying network physics...</div>
      <script>
        const POW_DIFF = ${POW_DIFFICULTY};
        async function solvePoW(nonce, difficulty) {
          const encoder = new TextEncoder();
          let solution = 0;
          const msg = document.getElementById('msg');
          msg.innerText = 'RayBuster: Solving PoW challenge...';
          while (true) {
            const data = encoder.encode(nonce + solution);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = new Uint8Array(hashBuffer);
            let zeros = 0;
            for (let b of hashArray) {
              if (b === 0) zeros += 2;
              else if (b < 16) { zeros += 1; break; }
              else break;
            }
            if (zeros >= difficulty) return solution;
            solution++;
            if (solution % 1000 === 0) {
              msg.innerText = 'RayBuster: High-security PoW challenge active (' + solution + ')...';
              await new Promise(r => setTimeout(r, 0));
            }
          }
        }

        setTimeout(function(){
          fetch('/__telemetry-log',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:'${challengeToken}'})})
          .then(async r=>{
            const text = await r.text();
            let data = {};
            try { data = JSON.parse(text); } catch(e) { }
            
            if(r.ok && !data.pow) {
              location.reload();
            } else if (data.pow) {
              const sol = await solvePoW(data.nonce, data.difficulty);
              fetch('/__telemetry-log',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pow_nonce: data.nonce, pow_solution: sol})})
              .then(r2 => { if(r2.ok) location.reload(); else document.getElementById('msg').innerText='Access Denied: PoW Verification Failed.'; });
            } else {
              document.getElementById('msg').innerText='Access Denied: ' + (data.reason || 'Anomaly Detected.');
            }
          })
          .catch(()=>document.getElementById('msg').innerText='Connection Failed.');
        }, 500);
      </script></body></html>`;
      
  return new Response(challengeHtml, {
    status: 200,
    headers: { 'Content-Type': 'text/html', 'Cache-Control': 'no-store, no-cache, must-revalidate', 'CF-Ray': rayId }
  });
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

    const ipHash = await hashIp(ip, env.IP_HASHING_SALT); // Calculate ipHash once

    // 1. PRE-FETCH BLOCKING (with Negative Caching)
    if (!url.pathname.startsWith('/admin') && !url.pathname.startsWith('/api/')) {
      const cached = BLOCK_CACHE.get(ipHash); // Use ipHash for cache key
      if (cached) { // Cache hit
        if (cached.blocked) return new Response('Forbidden: RayBuster Blocked', { status: 403 });
      } else { // Cache miss
        const blockedRow = await env.DB.prepare(
          'SELECT 1 FROM blocklist WHERE identifier = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) LIMIT 1'
        ).bind(ipHash).first(); // Use ipHash for DB query
        const isBlocked = !!blockedRow;
        BLOCK_CACHE.set(ipHash, { blocked: isBlocked, expires: Date.now() + CACHE_TTL }); // Store ipHash in cache
        if (isBlocked) return new Response('Forbidden: RayBuster Blocked', { status: 403 });
      }
    }

    // 2. DASHBOARD / API AUTH & IP Allowlist
    const authHeader = request.headers.get('Authorization');
    const isAuthenticated = (authHeader === `Bearer ${env.ADMIN_TOKEN}`);

    if (url.pathname.startsWith('/api/') || url.pathname === '/admin') {
      // Enforce IP Allowlist if configured
      if (env.ADMIN_IP_ALLOWLIST) {
        const adminIp = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
        if (!isIpAllowed(adminIp, env.ADMIN_IP_ALLOWLIST)) {
          return new Response('Forbidden: IP not in allowlist', { status: 403 });
        }
      }

      if (!isAuthenticated) return new Response('Unauthorized', { status: 401 });
      
      if (url.pathname === '/admin') {
        return new Response(dashboardHtml, { 
          headers: { 
            'content-type': 'text/html;charset=UTF-8',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com; connect-src 'self' https://api.cloudflare.com https://fonts.gstatic.com;",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff'
          } 
        });
      }
      if (url.pathname === '/api/stats') return await handleApiStats(request, env);
      if (url.pathname === '/api/anomalies') return await handleApiAnomalies(request, env);
      if (url.pathname === '/api/blocklist') return await handleApiBlocklist(request, env);
      if (url.pathname === '/api/blocklist/bulk') return await handleApiBlocklistBulk(request, env);
      if (url.pathname === '/api/decrypt-ip') return await handleApiDecryptIp(request, env);
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

    const secFetchDest = request.headers.get('Sec-Fetch-Dest');
    const secFetchMode = request.headers.get('Sec-Fetch-Mode');
    const isHtmlRequest = secFetchDest === 'document' || secFetchMode === 'navigate' || (request.headers.get('Accept') || '').includes('text/html');

    // 5. INTERSTITIAL CHALLENGE (The "No Free Hits" mechanism)
    if (!hasValidSession && isHtmlRequest) {
      return await serveChallenge(request, env, ip, rayId, cf);
    }

    // 6. INLINE TCP PHYSICS (For APIs, Assets, etc. that bypass the interstitial)
    if (!hasValidSession) {
      const country = cf?.country || 'XX';
      const colo = cf?.colo || 'UNK';
      const lat = cf?.latitude ? parseFloat(cf.latitude) : undefined;
      const lon = cf?.longitude ? parseFloat(cf.longitude) : undefined;
      const preliminaryVerdict = analyzePhysics({ ip, country, colo, tcpRtt, appRtt: 0, asn, lat, lon });
      
      // Async DB logging
      ctx.waitUntil(processTelemetry(request, env, rayId, ip, cf, tcpRtt));

      // Serve challenge or block
      if (preliminaryVerdict.status !== 'CLEAN') {
         if (isHtmlRequest) return await serveChallenge(request, env, ip, rayId, cf);
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
    const body = await request.json() as any;
    const { token, pow_nonce, pow_solution } = body;

    // --- 1. HANDLE POW SOLUTION ---
    if (pow_nonce && pow_solution !== undefined) {
      const powResult = await verifyPoW(pow_nonce, pow_solution.toString(), POW_DIFFICULTY, env.ADMIN_TOKEN);
      if (powResult && powResult.ip === ip) {
        const ipHash = await hashIp(ip, env.IP_HASHING_SALT);
        const { encryptedIp, iv } = await encryptIp(ip, env);
        ctx.waitUntil(env.DB.prepare(
          "INSERT INTO telemetry (ray_id, ip_encrypted, ip_iv, ip_hash, country_code, colo_code, asn, verdict, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ).bind(powResult.rayId, encryptedIp, iv, ipHash, cf?.country || 'XX', cf?.colo || 'UNK', cf?.asn || 0, 'POW_SOLVED', 'Solved PoW challenge').run());
        await checkAutoMitigate(ipHash, env);

        const sessionExpiry = Date.now() + (60 * 60 * 1000);
        const sessionCookieToken = await signPayload(`${ip}|${sessionExpiry}`, env.ADMIN_TOKEN);
        const headers = new Headers();
        headers.set('Set-Cookie', `rb_session=${sessionCookieToken}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax`);
        return Response.json({ status: 'OK' }, { headers });
      }
      return new Response('Invalid PoW', { status: 403 });
    }

    // --- 2. HANDLE STANDARD TELEMETRY ---
    if (!token) return new Response('Bad Request', { status: 400 });

    const ipHash = await hashIp(ip, env.IP_HASHING_SALT);
    const payload = await verifyPayload(token, env.ADMIN_TOKEN);
    if (!payload) {
      // SPOOFING ATTEMPT: Cryptographic failure. Instant ban.
      await env.DB.prepare("INSERT OR IGNORE INTO blocklist (identifier, identifier_type, reason) VALUES (?, 'IP', 'TAMPERING: Invalid Telemetry Signature')").bind(ipHash).run();
      BLOCK_CACHE.set(ipHash, { blocked: true, expires: Date.now() + CACHE_TTL * 60 });
      return new Response('Forbidden: Tampering Detected', { status: 403 });
    }

    const [tokenIp, reqRayId, reqTcpRttStr, reqTsStr, reqAsnStr] = payload.split('|');
    
    // Verify the IP in the token matches the request IP
    if (tokenIp !== ip) {
      await env.DB.prepare("INSERT OR IGNORE INTO blocklist (identifier, identifier_type, reason) VALUES (?, 'IP', 'TAMPERING: IP Mismatch')").bind(ipHash).run();
      BLOCK_CACHE.set(ipHash, { blocked: true, expires: Date.now() + CACHE_TTL * 60 });
      return new Response('Forbidden: IP Mismatch', { status: 403 });
    }

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
    const { encryptedIp, iv } = await encryptIp(ip, env);

    const verdict = analyzePhysics({ ip, country, colo, tcpRtt: reqTcpRtt, appRtt, asn: reqAsn, lat, lon });

    env.ANALYTICS.writeDataPoint({
      blobs: [reqRayId, ipHash, colo, country],
      doubles: [reqTcpRtt, appRtt],
      indexes: [verdict.status]
    });

    if (verdict.status !== 'CLEAN') {
      ctx.waitUntil((async () => {
        await env.DB.prepare(
          `INSERT INTO telemetry (ray_id, ip_encrypted, ip_iv, ip_hash, country_code, colo_code, asn, tcp_rtt, app_rtt, verdict, reason, created_at) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
        ).bind(reqRayId, encryptedIp, iv, ipHash, country, colo, reqAsn, reqTcpRtt, appRtt, 'POW_ISSUED', verdict.reason || '').run();
      })());
      
      const nonce = await generatePoWChallenge(ip, reqRayId, env.ADMIN_TOKEN);
      return Response.json({ pow: true, nonce, difficulty: POW_DIFFICULTY, reason: verdict.reason });
    }

    // ISSUE VERIFIED SESSION COOKIE (Valid for 1 Hour)
    const sessionExpiry = Date.now() + (60 * 60 * 1000);
    const sessionCookieToken = await signPayload(`${ip}|${sessionExpiry}`, env.ADMIN_TOKEN);
    const headers = new Headers();
    headers.set('Set-Cookie', `rb_session=${sessionCookieToken}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax`);
    
    return Response.json({ status: 'OK' }, { headers });
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
  const ipHash = await hashIp(ip, env.IP_HASHING_SALT);
  const { encryptedIp, iv } = await encryptIp(ip, env);

  const preliminaryVerdict = analyzePhysics({ ip, country, colo, tcpRtt, appRtt: 0, asn, lat, lon });

  try {
    env.ANALYTICS.writeDataPoint({ blobs: [rayId, ipHash, colo, country], doubles: [tcpRtt, 0], indexes: [preliminaryVerdict.status] });
  } catch (e) { console.error("AE Write Failed", e); }

  if (preliminaryVerdict.status !== 'CLEAN') {
    try {
      await env.DB.prepare(
        `INSERT INTO telemetry (ray_id, ip_encrypted, ip_iv, ip_hash, country_code, colo_code, asn, tcp_rtt, app_rtt, verdict, reason, created_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
      ).bind(rayId, encryptedIp, iv, ipHash, country, colo, asn, tcpRtt, 0, preliminaryVerdict.status, preliminaryVerdict.reason || '').run();
      await checkAutoMitigate(ipHash, env);
    } catch (e) { console.error("D1 Insert Failed", e); }
  }
}

async function checkAutoMitigate(ipHash: string, env: Env) {
  try {
    const { count } = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM telemetry WHERE ip_hash = ? AND verdict IN ('ANOMALY', 'BOT') AND created_at > datetime('now', '-1 hour')"
    ).bind(ipHash).first() as { count: number };

    if (count >= 5) {
      await env.DB.prepare("INSERT OR IGNORE INTO blocklist (identifier, identifier_type, reason) VALUES (?, 'IP', 'AUTONOMOUS_MITIGATION: High Frequency')").bind(ipHash).run();
      BLOCK_CACHE.set(ipHash, { blocked: true, expires: Date.now() + CACHE_TTL * 60 });
    }
  } catch (e) {}
}

async function handleApiStats(request: Request, env: Env) {
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

async function handleApiBlocklistBulk(request: Request, env: Env) {
  try {
    const body = await request.json() as { identifiers: string[] };
    if (!body.identifiers || !Array.isArray(body.identifiers) || body.identifiers.length === 0) {
      return new Response('Missing or empty identifiers array', { status: 400 });
    }
    
    const statements = await Promise.all(body.identifiers.map(async (identifier) => {
      if (!isValidIp(identifier)) {
        // Optionally log invalid identifier or return an error for the whole batch
        console.warn(`Invalid identifier in bulk blocklist: ${identifier}`);
        return null; // Skip invalid identifiers
      }
      const hashedIdentifier = await hashIp(identifier, env.IP_HASHING_SALT);
      BLOCK_CACHE.set(hashedIdentifier, { blocked: true, expires: Date.now() + CACHE_TTL * 60 });
      return env.DB.prepare("INSERT OR IGNORE INTO blocklist (identifier, identifier_type, reason) VALUES (?, 'IP', 'Bulk Admin Block')").bind(hashedIdentifier);
    }));

    const validStatements = statements.filter(s => s !== null);

    if (validStatements.length > 0) {
      // Chunk batches to avoid D1 limits (max 100 statements per batch usually, but let's be safe)
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


async function handleApiDecryptIp(request: Request, env: Env): Promise<Response> {
  try {
    const body = await request.json() as { encryptedIp: string; iv: string };
    if (!body.encryptedIp || !body.iv) {
      return new Response('Missing encryptedIp or iv', { status: 400 });
    }

    const decryptedIp = await decryptIp(body.encryptedIp, body.iv, env);
    return Response.json({ decryptedIp });
  } catch (e) {
    return new Response(`Decryption Error: ${e.message}`, { status: 500 });
  }
}

// Helper function to check if an IP is in a CIDR range
function ipInCidr(ip: string, cidr: string): boolean {
  if (!ip.includes('.') || !cidr.includes('.')) return false; // Basic IPv4 check
  const [range, bits] = cidr.split('/');
  const mask = ~(2**(32 - parseInt(bits, 10)) - 1);
  
  const ipNum = ip.split('.').map(Number).reduce((acc, octet) => (acc << 8) + octet, 0);
  const rangeNum = range.split('.').map(Number).reduce((acc, octet) => (acc << 8) + octet, 0);

  return (ipNum & mask) === (rangeNum & mask);
}

// Helper function to check if an IP is in the allowlist
function isIpAllowed(ip: string, allowlist: string | undefined): boolean {
  if (!allowlist) return false; // If no allowlist is configured, deny by default

  const allowedIps = allowlist.split(',').map(s => s.trim()).filter(Boolean);

  for (const allowed of allowedIps) {
    if (allowed.includes('/')) { // CIDR range
      if (ipInCidr(ip, allowed)) return true;
    } else { // Single IP
      if (ip === allowed) return true;
    }
  }
  return false;
}

// Helper function to validate IP
function isValidIp(identifier: string): boolean {
  // Regex for IPv4 and IPv6
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;
  const ipv6WithCompressRegex = /((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?/;

  return ipv4Regex.test(identifier) || ipv6Regex.test(identifier) || ipv6WithCompressRegex.test(identifier);
}

