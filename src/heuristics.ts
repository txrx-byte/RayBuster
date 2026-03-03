// src/heuristics.ts

/**
 * Minimum expected TCP RTT (in milliseconds) for specific Cloudflare Colo codes.
 * These values represent the approximate speed-of-light floor for traffic 
 * originating from distant regions connecting to these specific Edge nodes.
 * 
 * In production, this should be a comprehensive matrix of Geo <-> Colo distances.
 * For this implementation, we map Colo codes to their region's typical minimum latency.
 */
const PHYSICS_LIMITS: Record<string, number> = {
  // North America
  "EWR": 15,   // New York
  "LAX": 20,   // Los Angeles
  "ORD": 25,   // Chicago
  "DFW": 30,   // Dallas
  "YVR": 35,   // Vancouver
  "MEX": 40,   // Mexico City
  
  // Europe
  "LHR": 75,   // London
  "FRA": 80,   // Frankfurt
  "AMS": 80,   // Amsterdam
  "CDG": 80,   // Paris
  "MAD": 90,   // Madrid
  
  // Asia Pacific
  "NRT": 140,  // Tokyo
  "ICN": 150,  // Seoul
  "SIN": 190,  // Singapore
  "SYD": 160,  // Sydney
  "BOM": 200,  // Mumbai
  
  // South America
  "GRU": 150,  // Sao Paulo
  "SCL": 120,  // Santiago
};

// Fallback minimum RTT if Colo code is unknown
const DEFAULT_MIN_RTT = 50;

// Safety margin for network variance (60% of expected minimum)
// If RTT is below this threshold, it's physically impossible without a proxy
const SAFETY_MARGIN = 0.6;

export interface TelemetryData {
  ip: string;
  country: string;
  colo: string;
  tcpRtt: number;
  appRtt: number;
}

export interface Verdict {
  status: 'CLEAN' | 'ANOMALY' | 'BOT';
  reason?: string;
  confidence?: 'LOW' | 'MEDIUM' | 'HIGH';
}

/**
 * Analyzes network telemetry against physics-based constraints.
 * 
 * @param data - Telemetry tuple from Worker
 * @returns Verdict object with status and reason
 */
export function analyzePhysics(data: TelemetryData): Verdict {
  // 1. Validate Data
  if (data.tcpRtt <= 0) {
    return { 
      status: 'CLEAN', 
      reason: 'INVALID_DATA: TCP RTT missing or zero',
      confidence: 'LOW'
    };
  }

  // 2. Get Expected Minimum RTT for this Edge Node
  const minExpectedRtt = PHYSICS_LIMITS[data.colo] || DEFAULT_MIN_RTT;
  const threshold = minExpectedRtt * SAFETY_MARGIN;

  // 3. Check: Impossible Travel (Proxy/VPN/Spoofed Geo)
  // If the TCP handshake is faster than physics allows for this location
  if (data.tcpRtt < threshold) {
    return {
      status: 'ANOMALY',
      reason: `IMPOSSIBLE_TRAVEL: ${data.colo} RTT ${data.tcpRtt}ms < physical min ${threshold}ms`,
      confidence: 'HIGH'
    };
  }

  // 4. Check: Headless Browser / Automation
  // TCP connection is fast (local or optimized), but App rendering is suspiciously slow
  // This indicates JS execution lag typical of Puppeteer/Selenium or slow botnet proxies
  if (data.tcpRtt < 50 && data.appRtt > 800) {
    return {
      status: 'BOT',
      reason: `HEADLESS_SIGNATURE: Low TCP (${data.tcpRtt}ms) + High App RTT (${data.appRtt}ms)`,
      confidence: 'MEDIUM'
    };
  }

  // 5. Check: Extreme App Latency (Potential DoS or Slowloris)
  if (data.appRtt > 5000) {
    return {
      status: 'ANOMALY',
      reason: `EXCESSIVE_LATENCY: App RTT ${data.appRtt}ms exceeds threshold`,
      confidence: 'LOW'
    };
  }

  // 6. Default: Clean
  return { 
    status: 'CLEAN', 
    confidence: 'HIGH' 
  };
}

/**
 * Calculates the physical minimum RTT for a given Colo code.
 * Useful for debugging or dynamic threshold adjustment.
 */
export function getMinimumRtt(colo: string): number {
  return PHYSICS_LIMITS[colo] || DEFAULT_MIN_RTT;
}
