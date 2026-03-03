# RayBuster 

**A Zero-Trust, Edge-Native WAF that drops bots before they hit your origin using Deterministic Latency Fingerprinting.**

Traditional enterprise Web Application Firewalls (WAFs) and bot-management tools rely on probabilistic AI, massive data lakes, and expensive behavioral heuristics. They cost thousands of dollars a month to guess if a user is a bot.

**RayBuster doesn't guess.** It uses Time-of-Flight (ToF) network constraints and cryptographic server-side validation to drop malicious traffic at the Edge, deterministically.

## 🧠 How It Works (The Telemetry Engine)

RayBuster sits on Cloudflare Workers and measures the strict kinematic constraints of every incoming connection using a telemetry pipeline powered by `CF-Ray` Request IDs and protocol-level latency metrics.

1. **Geospatial RTT Auditing (Inline):** If an IP block is registered to London, but the TCP Round Trip Time (RTT) to the New York Edge node is 12ms, the client is lying. Packets cannot travel across the Atlantic that fast. RayBuster flags the proxy/VPN and drops the connection instantly based on absolute latency floors.
2. **Execution Profiling (Zero-Trust Interstitial):** When a user requests a page without a valid session, RayBuster **halts the request before hitting your origin**. It serves a tiny, invisible HTML challenge containing a cryptographically signed token. The client must execute JavaScript to bounce this token back. The Edge server then calculates the Application RTT *server-side*. If the TCP connection is lightning fast (20ms) but the Application RTT is massively delayed (850ms+), it's a headless browser (Puppeteer/Selenium) struggling to execute JavaScript. RayBuster bans the IP and drops the request.

## 🛡️ Enterprise-Grade Features

*   **Zero "Free Hits":** Because of the interstitial challenge architecture, bots do not get a single free request to your origin HTML. They must pass the latency audit in the waiting room.
*   **Cryptographic Anti-Spoofing:** Bots cannot spoof their telemetry. The challenge token is signed via `HMAC-SHA256`. The application latency (App RTT) is measured by the server, not the client. Tampering with the token results in an instant ban.
*   **Jitter & Starlink Aware:** The heuristics engine reads Autonomous System Numbers (ASNs). It automatically relaxes thresholds for known high-latency/high-jitter networks like Starlink or mobile carriers, ensuring legitimate users aren't caught in the crossfire.
*   **Autonomous Mitigation:** If an IP triggers 5 latency anomalies within an hour, the "Auto-Hammer" permanently moves the IP to the Cloudflare D1 Blocklist.
*   **Privacy-First Logging:** IP addresses written to the high-volume Analytics Engine are hashed (`SHA-256`) for GDPR compliance.

## 🏗️ The "Funnel" Architecture

RayBuster is designed to withstand Layer 7 DDoS attacks without spiking your database write costs or locking up your infrastructure:

*   **In-Memory Cache (The Shield):** The Edge Worker caches the blocklist in memory. 99% of requests never hit a database.
*   **The Firehose (Analytics Engine):** 100% of traffic telemetry is written to Cloudflare Analytics Engine for high-volume, low-cost global metrics.
*   **The Dropper (D1 SQLite):** Only traffic flagged as `ANOMALY` or `BOT` is persisted to the D1 relational database.

## 🚀 Quick Start Deployment

RayBuster requires a Cloudflare account with Workers paid plan ($5/mo) enabled for Analytics Engine and D1 limits.

**1. Clone & Install**
```bash
git clone https://github.com/txrx-byte/RayBuster.git
cd RayBuster
npm install
```

**2. Provision Infrastructure**
```bash
# Create the Threat Feed Database
wrangler d1 create raybuster-anomalies
# Update wrangler.toml with your new database_id
```

**3. Initialize Schema & Deploy**
```bash
wrangler d1 execute raybuster-anomalies --file=schema.sql --remote
npm run deploy
```

**4. View the Dashboard**
Navigate to `https://raybuster.<your-subdomain>.workers.dev/admin?token=<your-token>` where `<your-token>` is the `ADMIN_TOKEN` you configured in `wrangler.toml`.

## ⚖️ Honest Assessment: Strengths & Weaknesses

**Where RayBuster Shines (Strengths):**
*   **Defeating Residential Proxies:** Botnets use compromised smart fridges to get "clean" IP reputations. RayBuster ignores reputation and looks at physical latency. You cannot spoof the speed of light.
*   **Cost-Efficiency:** It absorbs massive Layer 7 attacks for pennies using Edge compute and in-memory caching.
*   **Scraper Protection:** Completely halts basic cURL scripts, Puppeteer, and Selenium instances targeting your HTML content.

**Where RayBuster Struggles (Weaknesses):**
*   **Pure APIs:** The Headless Bot (App RTT) check relies on an HTML interstitial challenge. If you are protecting a pure JSON API (e.g., a mobile app backend), bots won't execute the JS challenge. *Note: The TCP "Impossible Travel" check still works on pure APIs.*
*   **The "First Load" Penalty:** Legitimate human users will experience a minor delay on their *very first* visit as the invisible challenge page executes and reloads. After that, they receive a 1-hour session cookie and experience zero latency.
*   **Advanced Replay Attacks:** While the token is cryptographically secure, a highly sophisticated, state-sponsored attacker could theoretically build a custom headless browser tuned specifically to delay the TCP handshake artificially to perfectly match the application execution time. 

## 📜 Philosophy

The cybersecurity industry has spent the last decade building massive, VC-funded moats made of machine learning models to solve problems that can be handled by deterministic logic at the network edge. RayBuster is built on the premise that what one engineer can do in an afternoon with TypeScript and the speed of light can outperform a $10,000/mo enterprise SaaS contract.
