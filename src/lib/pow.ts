import { signPayload, verifyPayload } from './crypto';

export const POW_DIFFICULTY = 6;

export async function generatePoWChallenge(ip: string, rayId: string, secret: string): Promise<string> {
  const nonce = `${ip}|${rayId}|${Date.now()}`;
  return await signPayload(nonce, secret);
}

export async function verifyPoW(token: string, solution: string, difficulty: number, secret: string): Promise<{ip: string, rayId: string} | null> {
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
