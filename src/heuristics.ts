// src/heuristics.ts
import colos from './colos_slim.json';
import { TelemetryData, Verdict } from './types';

// Known High-Latency Networks (Starlink, Mobile Carriers with high jitter)
const HIGH_LATENCY_ASNS = new Set([
  14593,  // Starlink
  132203, // Starlink
  394362, // Starlink
  27277,  // Starlink
  393282, // Starlink
  262589, // Starlink
  12715,  // HughesNet
  3257,   // GTT Communications (can have high jitter/satellite paths)
]);

const SPEED_OF_LIGHT_FIBER_KM_PER_MS = 200; 
const DEFAULT_MIN_RTT = 3; 
const SAFETY_MARGIN = 0.5;

/**
 * Calculates the Great Circle distance (in kilometers) between two coordinates.
 */
function haversine(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371; // Earth radius in km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

/**
 * Analyzes network telemetry against physical kinematic constraints.
 */
export function analyzePhysics(data: TelemetryData): Verdict {
  // 1. Validate Data
  if (data.tcpRtt <= 0 && data.appRtt <= 0) {
    return { 
      status: 'CLEAN', 
      reason: 'INVALID_DATA: TCP and App RTT missing',
      confidence: 'LOW'
    };
  }

  const isStarlink = data.asn ? HIGH_LATENCY_ASNS.has(data.asn) : false;
  
  // 2. Geospatial RTT Auditing (Dynamic Time-of-Flight)
  let minExpectedRtt = DEFAULT_MIN_RTT;
  
  // If we have both the client's GeoIP coordinates and the Colo's physical coordinates
  if (data.lat !== undefined && data.lon !== undefined) {
    const coloCoords = (colos as unknown as Record<string, [number, number]>)[data.colo];
    if (coloCoords) {
      const [coloLat, coloLon] = coloCoords;
      const distanceKm = haversine(data.lat, data.lon, coloLat, coloLon);
      
      // Time to travel there and back
      const physicalRtt = (distanceKm / SPEED_OF_LIGHT_FIBER_KM_PER_MS) * 2;
      minExpectedRtt = Math.max(DEFAULT_MIN_RTT, physicalRtt);
    }
  }

  // Dynamic Margin: Starlink/Satellite has high jitter, so we use a much looser floor
  const margin = isStarlink ? 0.2 : SAFETY_MARGIN; 
  const physicalFloor = minExpectedRtt * margin;

  // 3. Check: Impossible Travel
  // Support HTTP/3 where tcpRtt is 0 by checking appRtt (minus the 500ms timeout)
  let checkRtt = data.tcpRtt;
  if (checkRtt <= 0 && data.appRtt > 500) {
    checkRtt = data.appRtt - 500;
  }

  if (checkRtt > 0 && checkRtt < physicalFloor) {
    return {
      status: 'ANOMALY',
      reason: `IMPOSSIBLE_TRAVEL: ${data.colo} RTT ${checkRtt.toFixed(1)}ms < physical floor ${physicalFloor.toFixed(1)}ms`,
      confidence: 'HIGH'
    };
  }

  // 4. Check: Execution Profiling (App vs TCP RTT Ratio)
  const appThreshold = isStarlink ? 4000 : 3000; 
  
  if (data.tcpRtt > 0 && data.tcpRtt < 150 && data.appRtt > appThreshold) {
    const deltaRatio = data.appRtt / data.tcpRtt;
    
    if (deltaRatio > 60) {
      return {
        status: 'BOT',
        reason: `HEADLESS_SIGNATURE: Ratio ${deltaRatio.toFixed(1)}x exceeding limit`,
        confidence: 'MEDIUM'
      };
    }
  }

  // 5. Check: Extreme App Latency
  const maxLeeway = isStarlink ? 12000 : 6000;
  if (data.appRtt > maxLeeway) {
    return {
      status: 'ANOMALY',
      reason: `EXCESSIVE_LATENCY: App RTT ${data.appRtt}ms`,
      confidence: 'LOW'
    };
  }
  
  // 6. Check: Fast Execution (cURL / Bot bypass)
  // Our challenge has a 500ms setTimeout. If appRtt < 400ms, it means the client parsed the HTML and sent the token without waiting.
  // Note: AppRtt might be 0 for inline API checks, so we only apply this if appRtt > 0.
  // Wait, if it's an inline check, appRtt is explicitly passed as 0. 
  // We need to differentiate between inline (0) and extremely fast appRtt (> 0 but < 400).
  if (data.appRtt > 0 && data.appRtt < 400) {
    return {
      status: 'BOT',
      reason: `FAST_EXECUTION: App RTT ${data.appRtt}ms < 400ms minimum timeout`,
      confidence: 'HIGH'
    };
  }

  return { status: 'CLEAN', confidence: 'HIGH' };
}
