# RayBuster 

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

### Weaknesses
*   **First-Load Delay:** New users experience a ~500ms delay for the initial latency check.
*   **SEO Impact:** Search crawlers that don't execute JS will be blocked. (Recommendation: Allowlist known bot IPs if SEO is critical).
*   **API-Only Clients:** Requests without cookies or JS execution (cURL, scripts) are limited to pure TCP-based physics checks.

---

## 📜 License
MIT License. Built for the modern, zero-trust web.
