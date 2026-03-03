import { Env } from '../types';
import { analyzePhysics } from '../heuristics';
import { signPayload, verifyPayload, hashIp, encryptIp } from '../lib/crypto';
import { verifyPoW, POW_DIFFICULTY, generatePoWChallenge } from '../lib/pow';
import { createSessionCookie } from '../lib/sessions';
import { BLOCK_CACHE, CACHE_TTL } from '../lib/cache';

export async function serveChallenge(request: Request, env: Env, ip: string, rayId: string, cf: any): Promise<Response> {
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

export async function handleTelemetryIngest(request: Request, env: Env, ctx: ExecutionContext, ip: string, cf: any) {
  try {
    const body = await request.json() as any;
    const { token, pow_nonce, pow_solution } = body;

    if (pow_nonce && pow_solution !== undefined) {
      const powResult = await verifyPoW(pow_nonce, pow_solution.toString(), POW_DIFFICULTY, env.ADMIN_TOKEN);
      if (powResult && powResult.ip === ip) {
        const ipHash = await hashIp(ip, env.IP_HASHING_SALT);
        const { encryptedIp, iv } = await encryptIp(ip, env);
        ctx.waitUntil(env.DB.prepare(
          "INSERT INTO telemetry (ray_id, ip_encrypted, ip_iv, ip_hash, country_code, colo_code, asn, verdict, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ).bind(powResult.rayId, encryptedIp, iv, ipHash, cf?.country || 'XX', cf?.colo || 'UNK', cf?.asn || 0, 'POW_SOLVED', 'Solved PoW challenge').run());
        await checkAutoMitigate(ipHash, env);

        const cookie = await createSessionCookie(ip, env.ADMIN_TOKEN);
        const headers = new Headers();
        headers.set('Set-Cookie', cookie);
        return Response.json({ status: 'OK' }, { headers });
      }
      return new Response('Invalid PoW', { status: 403 });
    }

    if (!token) return new Response('Bad Request', { status: 400 });

    const ipHash = await hashIp(ip, env.IP_HASHING_SALT);
    const payload = await verifyPayload(token, env.ADMIN_TOKEN);
    if (!payload) {
      await env.DB.prepare("INSERT OR IGNORE INTO blocklist (identifier, identifier_type, reason) VALUES (?, 'IP', 'TAMPERING: Invalid Telemetry Signature')").bind(ipHash).run();
      BLOCK_CACHE.set(ipHash, { blocked: true, expires: Date.now() + CACHE_TTL * 60 });
      return new Response('Forbidden: Tampering Detected', { status: 403 });
    }

    const [tokenIp, reqRayId, reqTcpRttStr, reqTsStr, reqAsnStr] = payload.split('|');
    if (tokenIp !== ip) {
      await env.DB.prepare("INSERT OR IGNORE INTO blocklist (identifier, identifier_type, reason) VALUES (?, 'IP', 'TAMPERING: IP Mismatch')").bind(ipHash).run();
      BLOCK_CACHE.set(ipHash, { blocked: true, expires: Date.now() + CACHE_TTL * 60 });
      return new Response('Forbidden: IP Mismatch', { status: 403 });
    }

    const reqTcpRtt = parseInt(reqTcpRttStr, 10);
    const reqTs = parseInt(reqTsStr, 10);
    const reqAsn = parseInt(reqAsnStr, 10);
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

    const cookie = await createSessionCookie(ip, env.ADMIN_TOKEN);
    const headers = new Headers();
    headers.set('Set-Cookie', cookie);
    return Response.json({ status: 'OK' }, { headers });
  } catch (e) {
    return new Response('Invalid Beacon', { status: 400 });
  }
}

export async function processTelemetry(request: Request, env: Env, rayId: string, ip: string, cf: any, tcpRtt: number) {
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
