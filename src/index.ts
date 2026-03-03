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

/**
 * HTMLRewriter Class: Injects the telemetry beacon into the response stream.
 * Includes both RayID and TCP RTT to maintain statelessness.
 */
class BeaconInjector {
  private rayId: string;
  private tcpRtt: number;

  constructor(rayId: string, tcpRtt: number) {
    this.rayId = rayId;
    this.tcpRtt = tcpRtt;
  }

  element(element: Element) {
    const script = `
      <script>
        (function(){
          const start = performance.now();
          const rayId = '${this.rayId}';
          const tcpRtt = ${this.tcpRtt};
          
          const sendBeacon = () => {
            const data = JSON.stringify({ 
              appRtt: performance.now() - start, 
              rayId: rayId,
              tcpRtt: tcpRtt
            });
            navigator.sendBeacon('/__telemetry-log', data);
          };

          if(document.readyState === 'complete') sendBeacon();
          else window.addEventListener('load', sendBeacon);
        })();
      </script>
    `;
    element.append(script, { html: true });
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    
    // Extract Cloudflare Metadata
    const rayId = request.headers.get('cf-ray') || 'unknown';
    const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
    const cf = request.cf;
    const tcpRtt = cf?.clientTcpRtt || 0;

    // --- ROUTE: Telemetry Beacon Ingest ---
    if (url.pathname === '/__telemetry-log' && request.method === 'POST') {
      return await handleTelemetryIngest(request, env, ctx, ip, cf);
    }

    // --- ROUTE: Admin Dashboard ---
    if (url.pathname === '/admin') {
      return await handleDashboard(request, env);
    }

    // --- ROUTE: API - Analytics Stats (High Volume Metrics) ---
    if (url.pathname === '/api/stats' && request.method === 'GET') {
      return await handleApiStats(request, env);
    }

    // --- ROUTE: API - Anomaly Feed (Threat Details) ---
    if (url.pathname === '/api/anomalies' && request.method === 'GET') {
      return await handleApiAnomalies(request, env);
    }

    // --- ROUTE: Normal Traffic Proxy ---
    try {
      const workerRequest = new Request(request);
      const response = await fetch(workerRequest);
      const contentType = response.headers.get('content-type') || '';
      
      // Prepare Headers (Security & Cache Control)
      const newHeaders = new Headers(response.headers);
      newHeaders.set('Access-Control-Expose-Headers', 'CF-Ray');
      
      // Force No-Cache for HTML to ensure Worker runs every time
      if (contentType.includes('text/html')) {
        newHeaders.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      }

      // Inject Beacon if HTML
      if (contentType.includes('text/html')) {
        const transformedResponse = new HTMLRewriter()
          .on('body', new BeaconInjector(rayId, tcpRtt))
          .transform(response);
        
        // Process Telemetry Async (Non-blocking)
        ctx.waitUntil(processTelemetry(request, env, rayId, ip, cf, tcpRtt));

        return new Response(transformedResponse.body, { 
          status: transformedResponse.status, 
          headers: newHeaders 
        });
      }

      return new Response(response.body, { 
        status: response.status, 
        headers: newHeaders 
      });

    } catch (err) {
      return new Response(`Error: ${err}`, { status: 500 });
    }
  },
};

/**
 * Initial Telemetry Processing (TCP Level)
 * Runs asynchronously after response is sent.
 */
async function processTelemetry(
  request: Request, 
  env: Env, 
  rayId: string, 
  ip: string, 
  cf: any, 
  tcpRtt: number
) {
  const colo = cf?.colo || 'UNK';
  const country = cf?.country || 'XX';

  // 1. Preliminary Physics Check (TCP Only)
  const preliminaryVerdict = analyzePhysics({ 
    ip, country, colo, tcpRtt, appRtt: 0 
  });

  // 2. Write to Analytics Engine (Always - High Volume Safe)
  try {
    env.ANALYTICS.writeDataPoint({
      blobs: [rayId, ip, colo, country],
      doubles: [tcpRtt, 0], // TCP RTT, App RTT (placeholder)
      indexes: [preliminaryVerdict.status]
    });
  } catch (e) {
    console.error("AE Write Failed", e);
  }

  // 3. Conditional D1 Write (Only Anomalies)
  if (preliminaryVerdict.status !== 'CLEAN') {
    try {
      await env.DB.prepare(
        `INSERT INTO telemetry (ray_id, ip_raw, country_code, colo_code, tcp_rtt, verdict, reason, created_at) 
         VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
      ).bind(rayId, ip, country, colo, tcpRtt, preliminaryVerdict.status, preliminaryVerdict.reason || '').run();
    } catch (e) {
      console.error("D1 Insert Failed", e);
    }
  }
}

/**
 * Handle Beacon POST from Client
 * Receives both TCP and App RTT for full physics check.
 */
async function handleTelemetryIngest(
  request: Request, 
  env: Env, 
  ctx: ExecutionContext, 
  ip: string, 
  cf: any
) {
  try {
    const body = await request.json();
    const appRtt = Math.floor(body.appRtt || 0);
    const tcpRtt = Math.floor(body.tcpRtt || 0);
    const rayId = body.rayId || 'unknown';
    const colo = cf?.colo || 'UNK';
    const country = cf?.country || 'XX';

    // 1. Full Physics Check
    const verdict = analyzePhysics({ ip, country, colo, tcpRtt, appRtt });

    // 2. Update Analytics Engine
    env.ANALYTICS.writeDataPoint({
      blobs: [rayId, ip, colo, country],
      doubles: [tcpRtt, appRtt],
      indexes: [verdict.status]
    });

    // 3. Conditional D1 Write/Update
    if (verdict.status !== 'CLEAN') {
      ctx.waitUntil((async () => {
        try {
          // Try to update existing anomaly row
          const { success } = await env.DB.prepare(
            `UPDATE telemetry SET app_rtt = ?, verdict = ?, reason = ? WHERE ray_id = ?`
          ).bind(appRtt, verdict.status, verdict.reason || '', rayId).run();

          // If no row existed (TCP was clean, but App is bad), INSERT new anomaly
          if (!success) {
            await env.DB.prepare(
              `INSERT INTO telemetry (ray_id, ip_raw, colo_code, tcp_rtt, app_rtt, verdict, reason, created_at) 
               VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
            ).bind(rayId, ip, colo, tcpRtt, appRtt, verdict.status, verdict.reason || '').run();
          }
        } catch (e) {
          console.error("D1 Update Failed", e);
        }
      })());
    }

    return new Response('OK', { status: 200 });
  } catch (e) {
    return new Response('Invalid Beacon', { status: 400 });
  }
}

/**
 * API: Get Stats from Analytics Engine via Cloudflare HTTP API
 */
async function handleApiStats(request: Request, env: Env) {
  const authHeader = request.headers.get('Authorization');
  if (authHeader !== `Bearer ${env.ADMIN_TOKEN}`) {
    return new Response('Unauthorized', { status: 401 });
  }

  try {
    const accountId = env.CF_ACCOUNT_ID;
    const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/analytics_engine/sql`;
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.CF_API_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        query: `
          SELECT 
            SUM(_sample_interval) as request_count,
            AVG(double_1) as avg_tcp_rtt,
            AVG(double_2) as avg_app_rtt,
            index_1 as verdict
          FROM sentinel_metrics 
          WHERE timestamp > NOW() - INTERVAL '1 HOUR'
          GROUP BY index_1
          ORDER BY request_count DESC
        `
      })
    });

    if (!response.ok) {
      return new Response(`Cloudflare API Error: ${response.statusText}`, { status: 502 });
    }

    const result = await response.json();
    return Response.json(result.data || []);
  } catch (e) {
    return new Response(`Internal Error: ${e}`, { status: 500 });
  }
}

/**
 * API: Get Anomaly Details from D1
 */
async function handleApiAnomalies(request: Request, env: Env) {
  const authHeader = request.headers.get('Authorization');
  if (authHeader !== `Bearer ${env.ADMIN_TOKEN}`) {
    return new Response('Unauthorized', { status: 401 });
  }

  try {
    const { results } = await env.DB.prepare(
      `SELECT * FROM telemetry ORDER BY created_at DESC LIMIT 100`
    ).all();

    return Response.json(results);
  } catch (e) {
    return new Response(`DB Error: ${e}`, { status: 500 });
  }
}

/**
 * Serve Admin Dashboard
 */
async function handleDashboard(request: Request, env: Env) {
  const authHeader = request.headers.get('Authorization');
  // Allow direct browser access without Auth header for dashboard UI itself, 
  // but API calls within it require auth. Or enforce auth here.
  // For simplicity, we enforce auth here via Query Param or Header.
  // Let's enforce Header for consistency.
  if (authHeader !== `Bearer ${env.ADMIN_TOKEN}`) {
    return new Response('Unauthorized', { status: 401 });
  }

  return new Response(dashboardHtml, { 
    headers: { 'content-type': 'text/html;charset=UTF-8' } 
  });
}
