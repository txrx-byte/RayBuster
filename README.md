---

# ⚡ RayBuster

**An edge-native, physics-based WAF that drops bots before they hit your origin.**

Traditional enterprise Web Application Firewalls (WAFs) and bot-management tools rely on probabilistic AI, massive data lakes, and expensive behavioral heuristics. They cost thousands of dollars a month to guess if a user is a bot.

**RayBuster doesn't guess.** It uses the fundamental laws of physics to drop malicious traffic at the Edge, deterministically.

## 🧠 How It Works

RayBuster sits on Cloudflare Workers and measures the "Speed of Light" constraints of every incoming connection using a 1:1 correlated telemetry pipeline powered by `CF-Ray` Request IDs.

1. **The Impossible Travel Check:** If an IP block is registered to London, but the TCP Round Trip Time (RTT) to the New York Edge node is 12ms, the client is lying. Packets cannot travel across the Atlantic that fast. RayBuster flags the proxy/VPN and drops the connection.
2. **The Headless Bot Check:** RayBuster measures the TCP Handshake latency (Network Layer) and uses a streaming `HTMLRewriter` beacon to measure the Application rendering latency (Browser Layer). If the TCP connection is lightning fast (20ms) but the Application RTT is massively delayed (850ms+), it's a headless browser (Puppeteer/Selenium) struggling to execute JavaScript. RayBuster drops it.

## 🏗️ The "Funnel" Architecture

RayBuster is designed to withstand Layer 7 DDoS attacks without spiking your database write costs or locking up your infrastructure. It uses a **Conditional Persistence** model:

* **In-Memory Heuristics:** The Edge Worker calculates the physics matrix in sub-milliseconds.
* **The Firehose (Analytics Engine):** 100% of traffic telemetry is written to Cloudflare Analytics Engine for high-volume, low-cost global metrics.
* **The Dropper (D1 SQLite):** Only traffic flagged as `ANOMALY` or `BOT` is persisted to the D1 relational database. This generates your active threat feed and WAF blocklists without database bottlenecks.

## 🚀 Quick Start Deployment

RayBuster requires a Cloudflare account with Workers paid plan ($5/mo) enabled for Analytics Engine and D1 limits.

**1. Clone & Install**

```bash
git clone https://github.com/yourusername/raybuster.git
cd raybuster
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
wrangler deploy

```

**4. View the Dashboard**
Navigate to `https://raybuster.<your-subdomain>.workers.dev/admin` and use your configured `ADMIN_TOKEN` to view the live threat feed.

## ⚙️ Configuration (`wrangler.toml`)

```toml
name = "raybuster"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[[d1_databases]]
binding = "DB"
database_name = "raybuster-anomalies"
database_id = "YOUR_DATABASE_ID"

[[analytics_engine_datasets]]
binding = "ANALYTICS"
dataset = "raybuster_metrics"

[vars]
ADMIN_TOKEN = "your-super-secret-dashboard-token"

```

## 📜 Philosophy & Acknowledgements

The cybersecurity industry has spent the last decade building massive, VC-funded moats made of machine learning models to solve problems that can be handled by deterministic logic at the network edge. RayBuster is built on the premise that what one engineer can do in an afternoon with TypeScript and the speed of light can outperform a $10,000/mo enterprise SaaS contract.

**A Friendly Nod to PunkBuster:**
RayBuster is a spiritual successor to Even Balance's legendary PunkBuster. PB kept the script kiddies and aimbotters out of our *Battlefield 1942* servers in 2002 with unapologetic, deterministic kicks. RayBuster brings that same uncompromising "door slammed in your face" energy to modern web infrastructure. No soft warnings, no probabilistic guessing. If your packets break the laws of physics, you're out.

---

*Built for the Edge. Zero race conditions. Zero AI bloat.*
