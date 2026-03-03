export interface Env {
  DB: D1Database;
  ANALYTICS: AnalyticsEngineDataset;
  ADMIN_TOKEN: string;
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
  IP_HASHING_SALT: string;
  ENCRYPTION_KEY: string;
  ADMIN_IP_ALLOWLIST?: string;
}

export interface TelemetryData {
  ip: string;
  country: string;
  colo: string;
  tcpRtt: number;
  appRtt: number;
  asn?: number;
  lat?: number;
  lon?: number;
}

export interface Verdict {
  status: 'CLEAN' | 'ANOMALY' | 'BOT';
  reason?: string;
  confidence?: 'LOW' | 'MEDIUM' | 'HIGH';
}
