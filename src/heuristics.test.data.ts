import { TelemetryData, Verdict } from './types';

interface TestCase {
  description: string;
  input: TelemetryData;
  expected: Partial<Verdict>;
}

export const testCases: TestCase[] = [
  // --- Geospatial RTT Auditing ---
  {
    description: 'should flag impossible travel (static RTT floor)',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 1, appRtt: 100 },
    expected: { status: 'ANOMALY', reason: 'IMPOSSIBLE_TRAVEL' },
  },
  {
    description: 'should flag impossible travel (dynamic Haversine distance)',
    input: { ip: '1.2.3.4', country: 'AU', colo: 'LHR', lat: -33.86, lon: 151.2, tcpRtt: 20, appRtt: 100 },
    expected: { status: 'ANOMALY', reason: 'IMPOSSIBLE_TRAVEL' },
  },
  {
    description: 'should pass legitimate travel (dynamic Haversine distance)',
    input: { ip: '1.2.3.4', country: 'AU', colo: 'LHR', lat: -33.86, lon: 151.2, tcpRtt: 250, appRtt: 400 },
    expected: { status: 'CLEAN' },
  },
  {
    description: 'should pass with valid RTT (HTTP/3 with high app RTT)',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 0, appRtt: 600 },
    expected: { status: 'CLEAN' },
  },
  {
    description: 'should handle unknown colo gracefully',
    input: { ip: '1.2.3.4', country: 'US', colo: 'XXX', tcpRtt: 10, appRtt: 500 },
    expected: { status: 'CLEAN' },
  },


  // --- Execution Profiling ---
  {
    description: 'should flag headless browsers (low TCP RTT, high App RTT)',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 20, appRtt: 3100 },
    expected: { status: 'BOT', reason: 'HEADLESS_SIGNATURE' },
  },
  {
    description: 'should flag extreme RTT ratio as bot',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 50, appRtt: 6000 },
    expected: { status: 'BOT', reason: 'HEADLESS_SIGNATURE' },
  },
  {
    description: 'should pass with high TCP RTT and high App RTT',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 200, appRtt: 3000 },
    expected: { status: 'CLEAN' },
  },
  {
    description: 'should pass with a high but acceptable RTT ratio',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 100, appRtt: 5000 },
    expected: { status: 'CLEAN' },
  },

  // --- Latency Checks ---
  {
    description: 'should flag excessively high app latency',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 200, appRtt: 6100 },
    expected: { status: 'ANOMALY', reason: 'EXCESSIVE_LATENCY' },
  },
  {
    description: 'should flag excessively high app latency on Starlink',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 250, appRtt: 12100, asn: 14593 },
    expected: { status: 'ANOMALY', reason: 'EXCESSIVE_LATENCY' },
  },
  {
    description: 'should flag fast execution (appRtt < 400ms)',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 50, appRtt: 350 },
    expected: { status: 'BOT', reason: 'FAST_EXECUTION' },
  },
  {
    description: 'should pass with appRtt just below maxLeeway',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 200, appRtt: 4999 },
    expected: { status: 'CLEAN' },
  },

  // --- Clean Traffic ---
  {
    description: 'should pass clean traffic',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 25, appRtt: 550 },
    expected: { status: 'CLEAN' },
  },
  {
    description: 'should handle Starlink gracefully with relaxed thresholds',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 100, appRtt: 2000, asn: 14593 },
    expected: { status: 'CLEAN' },
  },

  // --- Input Validation ---
  {
    description: 'should handle missing RTT data gracefully',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: 0, appRtt: 0 },
    expected: { status: 'CLEAN', reason: 'INVALID_DATA' },
  },
  {
    description: 'should handle negative RTT values gracefully',
    input: { ip: '1.2.3.4', country: 'US', colo: 'EWR', tcpRtt: -10, appRtt: -50 },
    expected: { status: 'CLEAN', reason: 'INVALID_DATA' },
  },
];
