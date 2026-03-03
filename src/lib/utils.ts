// Helper function to check if an IP is in a CIDR range
export function ipInCidr(ip: string, cidr: string): boolean {
  if (!ip.includes('.') || !cidr.includes('.')) return false; // Basic IPv4 check
  const [range, bits] = cidr.split('/');
  const mask = ~(2**(32 - parseInt(bits, 10)) - 1);
  
  const ipNum = ip.split('.').map(Number).reduce((acc, octet) => (acc << 8) + octet, 0);
  const rangeNum = range.split('.').map(Number).reduce((acc, octet) => (acc << 8) + octet, 0);

  return (ipNum & mask) === (rangeNum & mask);
}

// Helper function to check if an IP is in the allowlist
export function isIpAllowed(ip: string, allowlist: string | undefined): boolean {
  if (!allowlist) return false; // If no allowlist is configured, deny by default

  const allowedIps = allowlist.split(',').map(s => s.trim()).filter(Boolean);

  for (const allowed of allowedIps) {
    if (allowed.includes('/')) { // CIDR range
      if (ipInCidr(ip, allowed)) return true;
    } else { // Single IP
      if (ip === allowed) return true;
    }
  }
  return false;
}

// Helper function to validate IP
export function isValidIp(identifier: string): boolean {
  // Regex for IPv4 and IPv6
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/i;
  const ipv6WithCompressRegex = /((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?/;

  return ipv4Regex.test(identifier) || ipv6Regex.test(identifier) || ipv6WithCompressRegex.test(identifier);
}
