import { verifyPayload, signPayload } from './crypto';

export async function verifySession(cookieHeader: string, ip: string, secret: string): Promise<boolean> {
  const sessionMatch = cookieHeader.match(/rb_session=([^;]+)/);
  if (!sessionMatch) return false;

  const sessionPayload = await verifyPayload(sessionMatch[1], secret);
  if (sessionPayload) {
    const [sessIp, expiryStr] = sessionPayload.split('|');
    if (sessIp === ip && parseInt(expiryStr, 10) > Date.now()) {
      return true;
    }
  }
  return false;
}

export async function createSessionCookie(ip: string, secret: string): Promise<string> {
  const sessionExpiry = Date.now() + (60 * 60 * 1000);
  const sessionCookieToken = await signPayload(`${ip}|${sessionExpiry}`, secret);
  return `rb_session=${sessionCookieToken}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax`;
}
