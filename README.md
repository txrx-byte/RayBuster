# RayBuster 

[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-blue.svg)](https://unlicense.org/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/txrx-byte/RayBuster)
[![Coverage Status](https://img.shields.io/badge/coverage-27%25-red)](https://github.com/txrx-byte/RayBuster)
[![Cloudflare](https://img.shields.io/badge/Cloudflare-Deployed-orange)](https://www.cloudflare.com/workers/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3.3-blue)](https://www.typescriptlang.org/)



**A Zero-Trust, Edge-Native WAF that drops bots before they hit your origin using Deterministic Latency Fingerprinting.**

Traditional enterprise Web Application Firewalls (WAFs) and bot-management tools rely on probabilistic AI, massive data lakes, and expensive behavioral heuristics. They cost thousands of dollars a month to guess if a user is a bot.

**RayBuster doesn't guess.** It uses Time-of-Flight (ToF) network constraints and cryptographic server-side validation to drop malicious traffic at the Edge, deterministically.

---

## 🧠 How It Works (The Telemetry Engine)

RayBuster sits on Cloudflare Workers and measures the strict kinematic constraints of every incoming connection using a telemetry pipeline powered by `CF-Ray` Request IDs and protocol-level latency metrics.

1. **Geospatial RTT Auditing (Inline):** If an IP block is registered to London, but the TCP Round Trip Time (RTT) to the New York Edge node is 12ms, the client is lying. Packets cannot travel across the Atlantic that fast. RayBuster flags the proxy/VPN and drops the connection instantly based on absolute latency floors.
2. **Execution Profiling (Zero-Trust Interstitial):** When a user requests a page without a valid session, RayBuster **halts the request before hitting your origin**. It serves a tiny, invisible HTML challenge containing a cryptographically signed token. The client must execute JavaScript to bounce this token back. The Edge server then calculates the Application RTT *server-side*. If the TCP connection is lightning fast (20ms) but the Application RTT is massively delayed (850ms+), it's a headless browser (Puppeteer/Selenium) struggling to execute JavaScript. 
3. **The "Option of Last Resort" (PoW Challenge):** If a user fails the latency audit (verdict `ANOMALY` or `BOT`), RayBuster doesn't immediately issue a 403 Forbidden. Instead, it serves a high-performance **Proof-of-Work (PoW) challenge**. A Hashcash-style SHA-256 puzzle is sent to the browser. Legitimate human users (or high-value scrapers) can solve this in ~1-2 seconds. This prevents "false positives" while forcing a heavy computational cost on botnets.

---

## 🚀 Installation & Deployment

### Prerequisites
*   **Cloudflare Account** with a paid Workers plan (required for Analytics Engine and higher D1 limits).
*   **Node.js & npm** installed locally.
*   **Wrangler CLI** (`npm install -g wrangler`).

### 1. Clone & Install
```bash
git clone https://github.com/txrx-byte/RayBuster.git
cd RayBuster
npm install
```

### 2. Provision Infrastructure
```bash
# Create the D1 Database for persistent anomaly logging
wrangler d1 create raybuster-anomalies
```
Copy the `database_id` from the output and paste it into your `wrangler.toml` under the `[[d1_databases]]` section.

### 3. Configure Secrets & Environment
For production, you **must** set your sensitive keys as secrets:

```bash
# Use a long random string for admin dashboard and token signing
wrangler secret put ADMIN_TOKEN

# Cloudflare API Token (needs Analytics Engine Read permissions)
wrangler secret put CF_API_TOKEN

# 32-byte Base64 encoded key for IP encryption (GDPR compliance)
# Generate one: openssl rand -base64 32
wrangler secret put ENCRYPTION_KEY

# Salt for IP hashing (used in the Analytics Engine firehose)
wrangler secret put IP_HASHING_SALT
```

Update the `[vars]` section in `wrangler.toml`:
*   `CF_ACCOUNT_ID`: Your Cloudflare Account ID.
*   `ADMIN_IP_ALLOWLIST`: (Optional) Comma-separated list of IPs allowed to access the `/admin` dashboard.

### 4. Initialize Database & Deploy
```bash
# Create tables in the remote D1 instance
wrangler d1 execute raybuster-anomalies --file=schema.sql --remote

# Deploy to Cloudflare Edge
npm run deploy
```

---

## 🛠️ Configuration Reference

| Variable | Description | Source |
| :--- | :--- | :--- |
| `ADMIN_TOKEN` | Auth token for `/admin` and signing challenge tokens. | `secret` |
| `ENCRYPTION_KEY` | AES-GCM key for encrypting IPs in D1. | `secret` |
| `IP_HASHING_SALT` | Salt used for anonymizing IPs in Analytics. | `secret` |
| `CF_API_TOKEN` | Token for the dashboard to query Analytics Engine. | `secret` |
| `CF_ACCOUNT_ID` | Your Cloudflare Account ID. | `vars` |
| `ADMIN_IP_ALLOWLIST` | Comma-separated list of IPs for admin access. | `vars` |

---

## 🏗️ Architecture

RayBuster is designed for high-availability and zero-trust security:

*   **In-Memory Cache:** The Worker caches the blocklist locally. 99% of requests never hit the database.
*   **Analytics Engine:** 100% of telemetry is piped to a high-volume firehose for global observability.
*   **D1 SQLite:** Persistent storage for anomalies, PoW issuances, and the permanent blocklist.
*   **Zero "Free Hits":** The interstitial architecture ensures bots never see your origin HTML without passing the latency audit first.

---

## ⚖️ Honest Assessment

### Strengths
*   **Defeats Residential Proxies:** Bypasses IP reputation checks by looking at physical latency. You cannot spoof the speed of light.
*   **Computational Throttling:** Forces attackers to spend CPU cycles via PoW fallbacks.
*   **Edge-Native:** Absorbs L7 attacks at the edge for minimal cost.

### Weaknesses & Limitations

*   **The "Same-City" Proxy Bypass:** Geospatial RTT auditing is most effective when there is a significant geographical distance between the user and the proxy. If an attacker uses a proxy in the same metropolitan area as the edge node (e.g., an AWS instance in Virginia hitting the Ashburn Cloudflare node), the TCP RTT will be very low and the check will likely pass. This is a fundamental limitation of this technique.
*   **Execution Profiling vs. Mobile Devices:** The Application RTT check is designed to detect headless browsers that struggle to execute JavaScript. However, older mobile devices on slow or congested networks can also exhibit high Application RTT. The thresholds have been adjusted to be more lenient, but there is still a risk of false positives for legitimate mobile users.
*   **Worker Memory Isolate Quirks:** The in-memory cache is highly effective at reducing D1 reads for a single user or a concentrated attack. However, it's important to remember that Cloudflare Workers run in separate isolates for each edge node. A distributed botnet attacking from many different locations will hit many different isolates, leading to initial cache misses and a spike in D1 reads.
*   **First-Load Delay:** New users will experience a small delay (typically 500ms) on their first page load while RayBuster performs the initial latency check.
*   **SEO Impact:** Search engine crawlers that do not execute JavaScript will be blocked. If SEO is critical, it is recommended to allowlist known bot IPs.

---

## 🔄 Comparison with Cloudflare Turnstile

Cloudflare Turnstile is a powerful, native feature of the Cloudflare platform that also uses invisible challenges to distinguish between humans and bots. So, why use RayBuster?

*   **Control & Visibility:** RayBuster gives you granular control over the security logic and full visibility into the telemetry data. You can see exactly why a user was flagged and fine-tune the heuristics to your specific needs.
*   **Physics-Based Auditing:** RayBuster's primary innovation is the use of Geospatial RTT auditing, which is a deterministic check that Turnstile does not perform.
*   **Customizable Actions:** With RayBuster, you can define custom actions to be taken when a bot is detected, such as issuing a PoW challenge, logging the request to a database, or redirecting the user to a different page.

In summary, while Turnstile is an excellent general-purpose solution, RayBuster is a specialized tool for high-security applications that require more control, visibility, and a deterministic, physics-based approach to bot detection.

---

## 🚀 Future Improvements

*   **Trust Score Decay:** Instead of a binary ALLOW/BLOCK, a future version of RayBuster could implement a trust score that decays over time. This would allow for more nuanced security decisions, such as issuing a PoW challenge only when the trust score falls below a certain threshold.
*   **WebGPU / WebGL Fingerprinting:** To improve the accuracy of the headless browser detection, a future version could use WebGL or WebGPU fingerprinting to analyze the user's rendering capabilities. Headless browsers often have very different rendering characteristics than real browsers, which can be used to identify them with a high degree of confidence.

---

## 📜 License
Unlicense. Built for the modern, zero-trust web.
