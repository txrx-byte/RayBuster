import { describe, it, expect } from 'vitest';
import { analyzePhysics } from './heuristics';

describe('Heuristics Engine', () => {
  it('should flag impossible travel (TCP RTT < floor)', () => {
    const result = analyzePhysics({
      ip: '1.2.3.4',
      country: 'US',
      colo: 'EWR',
      tcpRtt: 1, // Physical floor is 5ms * 0.6 = 3ms
      appRtt: 100
    });
    expect(result.status).toBe('ANOMALY');
    expect(result.reason).toContain('IMPOSSIBLE_TRAVEL');
  });

  it('should pass clean traffic', () => {
    const result = analyzePhysics({
      ip: '1.2.3.4',
      country: 'US',
      colo: 'EWR', // Newark
      tcpRtt: 25,
      appRtt: 550
    });
    expect(result.status).toBe('CLEAN');
  });

  it('should flag headless browsers (Low TCP + High App RTT)', () => {
    const result = analyzePhysics({
      ip: '1.2.3.4',
      country: 'US',
      colo: 'EWR',
      tcpRtt: 20,
      appRtt: 1200 // > 800ms
    });
    expect(result.status).toBe('BOT');
    expect(result.reason).toContain('HEADLESS_SIGNATURE');
  });

  it('should flag extreme ratio as bot', () => {
    const result = analyzePhysics({
      ip: '1.2.3.4',
      country: 'US',
      colo: 'EWR',
      tcpRtt: 50,
      appRtt: 6000 // 120x ratio
    });
    expect(result.status).toBe('BOT');
    expect(result.reason).toContain('HEADLESS_SIGNATURE');
  });

  it('should flag excessive latency', () => {
    const result = analyzePhysics({
      ip: '1.2.3.4',
      country: 'US',
      colo: 'EWR',
      tcpRtt: 200, // Make TCP high enough so ratio (6000/200 = 30) doesn't trigger BOT
      appRtt: 6000 
    });
    expect(result.status).toBe('ANOMALY');
    expect(result.reason).toContain('EXCESSIVE_LATENCY');
  });

  it('should handle Starlink gracefully with relaxed thresholds', () => {
    const result = analyzePhysics({
      ip: '1.2.3.4',
      country: 'US',
      colo: 'EWR',
      tcpRtt: 100,
      appRtt: 2000, // Normally a bot, but fine for Starlink
      asn: 14593 // Starlink ASN
    });
    expect(result.status).toBe('CLEAN');
  });

  it('should catch extreme latency even on Starlink', () => {
    const result = analyzePhysics({
      ip: '1.2.3.4',
      country: 'US',
      colo: 'EWR',
      tcpRtt: 250,
      appRtt: 11000, // > 10000ms threshold for Starlink
      asn: 132203 // Starlink ASN
    });
    expect(result.status).toBe('ANOMALY');
  });

  it('should flag missing or zero TCP RTT and app RTT', () => {
    const result = analyzePhysics({
      ip: '1.2.3.4',
      country: 'US',
      colo: 'EWR',
      tcpRtt: 0,
      appRtt: 0
    });
    expect(result.status).toBe('CLEAN');
    expect(result.reason).toContain('INVALID_DATA');
  });

  it('should pass HTTP/3 traffic if appRtt is physically valid', () => {
    const result = analyzePhysics({
      ip: '1.2.3.4',
      country: 'US',
      colo: 'EWR',
      tcpRtt: 0,
      appRtt: 550
    });
    expect(result.status).toBe('CLEAN');
  });

  it('should calculate dynamic Haversine distance (Sydney to London is ~17000km, RTT > 170ms)', () => {
    const result = analyzePhysics({
      ip: '1.2.3.4',
      country: 'AU', 
      colo: 'LHR',   
      lat: -33.8688, // Sydney Lat
      lon: 151.2093, // Sydney Lon
      tcpRtt: 20,    // 20ms is impossible for 17,000km (fiber takes ~170ms)
      appRtt: 100
    });
    expect(result.status).toBe('ANOMALY');
    expect(result.reason).toContain('IMPOSSIBLE_TRAVEL');
  });

  it('should pass reasonable dynamic Haversine distance', () => {
    const result = analyzePhysics({
      ip: '1.2.3.4',
      country: 'AU', 
      colo: 'LHR',   
      lat: -33.8688, 
      lon: 151.2093, 
      tcpRtt: 250,   // 250ms is reasonable for AU to UK
      appRtt: 400
    });
    expect(result.status).toBe('CLEAN');
  });
});
