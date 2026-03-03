import { Env } from './types';
import { analyzePhysics } from './heuristics';
import { hashIp } from './lib/crypto';
import { BLOCK_CACHE, CACHE_TTL } from './lib/cache';
import { isIpAllowed } from './lib/utils';
import { verifySession } from './lib/sessions';
import * as api from './handlers/api';
import * as waf from './handlers/waf';
import dashboardHtml from './dashboard.html';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const ip = request.headers.get('CF-Connecting-IP') || '0.0.0.0';
    const rayId = request.headers.get('cf-ray') || 'unknown';
    const cf = request.cf as any;
    const tcpRtt = cf?.clientTcpRtt || 0;
    const asn = cf?.asn || 0;

    const ipHash = await hashIp(ip, env.IP_HASHING_SALT);

    // 1. PRE-FETCH BLOCKING (with Negative Caching)
    if (!url.pathname.startsWith('/admin') && !url.pathname.startsWith('/api/')) {
      const cached = BLOCK_CACHE.get(ipHash);
      if (cached) {
        if (cached.blocked) return new Response('Forbidden: RayBuster Blocked', { status: 403 });
      } else {
        const blockedRow = await env.DB.prepare(
          'SELECT 1 FROM blocklist WHERE identifier = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) LIMIT 1'
        ).bind(ipHash).first();
        const isBlocked = !!blockedRow;
        BLOCK_CACHE.set(ipHash, { blocked: isBlocked, expires: Date.now() + CACHE_TTL });
        if (isBlocked) return new Response('Forbidden: RayBuster Blocked', { status: 403 });
      }
    }

    // 2. DASHBOARD / API AUTH & IP Allowlist
    const authHeader = request.headers.get('Authorization');
    const isAuthenticated = (authHeader === `Bearer ${env.ADMIN_TOKEN}`);

    if (url.pathname.startsWith('/api/') || url.pathname === '/admin') {
      if (env.ADMIN_IP_ALLOWLIST && !isIpAllowed(ip, env.ADMIN_IP_ALLOWLIST)) {
        return new Response('Forbidden: IP not in allowlist', { status: 403 });
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
      if (url.pathname === '/api/stats') return await api.handleApiStats(request, env);
      if (url.pathname === '/api/anomalies') return await api.handleApiAnomalies(request, env);
      if (url.pathname === '/api/blocklist') return await api.handleApiBlocklist(request, env);
      if (url.pathname === '/api/blocklist/bulk') return await api.handleApiBlocklistBulk(request, env);
      if (url.pathname === '/api/decrypt-ip') return await api.handleApiDecryptIp(request, env);
    }

    // 3. TELEMETRY INGEST (The Beacon Return)
    if (url.pathname === '/__telemetry-log' && request.method === 'POST') {
      return await waf.handleTelemetryIngest(request, env, ctx, ip, cf);
    }

    // 4. ZERO-TRUST SESSION CHECK
    const cookieHeader = request.headers.get('Cookie') || '';
    const hasValidSession = await verifySession(cookieHeader, ip, env.ADMIN_TOKEN);

    const secFetchDest = request.headers.get('Sec-Fetch-Dest');
    const secFetchMode = request.headers.get('Sec-Fetch-Mode');
    const isHtmlRequest = secFetchDest === 'document' || secFetchMode === 'navigate' || (request.headers.get('Accept') || '').includes('text/html');

    // 5. INTERSTITIAL CHALLENGE (The "No Free Hits" mechanism)
    if (!hasValidSession && isHtmlRequest) {
      return await waf.serveChallenge(request, env, ip, rayId, cf);
    }

    // 6. INLINE TCP PHYSICS (For APIs, Assets, etc. that bypass the interstitial)
    if (!hasValidSession) {
      const country = cf?.country || 'XX';
      const colo = cf?.colo || 'UNK';
      const lat = cf?.latitude ? parseFloat(cf.latitude) : undefined;
      const lon = cf?.longitude ? parseFloat(cf.longitude) : undefined;
      const preliminaryVerdict = analyzePhysics({ ip, country, colo, tcpRtt, appRtt: 0, asn, lat, lon });
      
      ctx.waitUntil(waf.processTelemetry(request, env, rayId, ip, cf, tcpRtt));

      if (preliminaryVerdict.status !== 'CLEAN') {
         if (isHtmlRequest) return await waf.serveChallenge(request, env, ip, rayId, cf);
         return new Response('Forbidden: Network Anomaly', { status: 403 });
      }
    }

    // 7. PROXY TO ORIGIN (User is verified!)
    const response = await fetch(new Request(request));
    const newHeaders = new Headers(response.headers);
    newHeaders.set('X-RayBuster-Status', hasValidSession ? 'Verified' : 'Bypass-TCP-Checked');
    return new Response(response.body, { status: response.status, headers: newHeaders });
  },
};
