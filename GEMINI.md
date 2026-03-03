# GEMINI.md

## Project Overview

This project, "RayBuster," is a Web Application Firewall (WAF) implemented as a Cloudflare Worker. It is designed to protect web applications from malicious bots by using a deterministic, physics-based approach to bot detection. Rather than relying on traditional probabilistic methods, RayBuster analyzes network-level latency metrics (like TCP RTT) and employs cryptographic validation to identify and block bots at the edge, before they can reach the origin server.

The core technologies used are:

*   **TypeScript:** The primary programming language.
*   **Cloudflare Workers:** The serverless execution environment.
*   **Cloudflare D1:** A serverless SQLite database used for storing anomaly and blocklist data.
*   **Cloudflare Analytics Engine:** Used for high-volume telemetry data collection.
*   **Vitest:** The testing framework.

## Building and Running

The project is managed using npm and the Cloudflare `wrangler` CLI.

### Prerequisites

*   Node.js and npm
*   A Cloudflare account with a Workers paid plan.
*   `wrangler` CLI installed and configured.

### Installation

```bash
npm install
```

### Key Commands

The following commands are defined in `package.json`:

*   **Development:** To run the worker in a local development environment:
    ```bash
    npm run dev
    ```

*   **Deployment:** To deploy the worker to your Cloudflare account:
    ```bash
    npm run deploy
    ```

*   **Testing:** To run the test suite:
    ```bash
    npm run test
    ```

*   **Type Checking:** To perform a static type check of the code:
    ```bash
    npm run typecheck
    ```

### Database Setup

The project uses a Cloudflare D1 database. The schema is defined in `schema.sql`. To create and initialize the database, use the following `wrangler` commands:

1.  **Create the database:**
    ```bash
    wrangler d1 create raybuster-anomalies
    ```
    After running this, you will need to update `wrangler.toml` with the `database_id`.

2.  **Apply the schema:**
    ```bash
    wrangler d1 execute raybuster-anomalies --file=schema.sql --remote
    ```

## Development Conventions

*   **Language:** The project is written in TypeScript. Adhere to the existing coding style and patterns.
*   **Configuration:** The primary configuration for the worker is in `wrangler.toml`. This file defines bindings to Cloudflare services (D1, Analytics Engine) and environment variables.
*   **Database:** All database schema changes should be reflected in `schema.sql`. The application interacts with the D1 database through the `DB` binding available in the worker environment.
*   **Business Logic:** The core bot detection heuristics are located in `src/heuristics.ts`.
*   **Entry Point:** The main worker entry point is `src/index.ts`.
*   **Testing:** The project uses `vitest`. New features should be accompanied by relevant tests.
