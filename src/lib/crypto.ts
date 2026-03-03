import { Env } from '../types';

let ENCRYPTION_KEY_CACHE: CryptoKey | null = null;

async function getEncryptionKey(env: Env): Promise<CryptoKey> {
  if (ENCRYPTION_KEY_CACHE) {
    return ENCRYPTION_KEY_CACHE;
  }
  const keyBuffer = Uint8Array.from(atob(env.ENCRYPTION_KEY), c => c.charCodeAt(0));
  ENCRYPTION_KEY_CACHE = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    'AES-GCM',
    true,
    ['encrypt', 'decrypt']
  );
  return ENCRYPTION_KEY_CACHE;
}

export async function encryptIp(ip: string, env: Env): Promise<{ encryptedIp: string; iv: string }> {
  const key = await getEncryptionKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedIp = new TextEncoder().encode(ip);

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encodedIp
  );

  const encryptedIp = btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
  const ivString = btoa(String.fromCharCode(...iv));

  return { encryptedIp, iv: ivString };
}

export async function decryptIp(encryptedIp: string, ivString: string, env: Env): Promise<string> {
  const key = await getEncryptionKey(env);
  const encryptedBuffer = Uint8Array.from(atob(encryptedIp), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(ivString), c => c.charCodeAt(0));

  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encryptedBuffer
  );

  return new TextDecoder().decode(decryptedBuffer);
}

export async function signPayload(payload: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  const sigHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${btoa(payload)}.${sigHex}`;
}

export function constantTimeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) {
        return false;
    }
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

export async function verifyPayload(token: string, secret: string): Promise<string | null> {
  try {
    const [b64Payload, sigHex] = token.split('.');
    if (!b64Payload || !sigHex) return null;
    
    const payload = atob(b64Payload);
    const expectedToken = await signPayload(payload, secret);

    if (constantTimeEquals(token, expectedToken)) {
      return payload;
    }
    return null;
  } catch { return null; }
}

export async function hashIp(ip: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(ip + salt);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}
