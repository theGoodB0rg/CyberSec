# CyberSec – Web SQLi Scanner & Reporting

A practical, developer-friendly web app for running focused SQL injection assessments with SQLMap, recon-assisted targeting, real‑time output, and client‑ready reports. Now multi‑user with JWT auth, target ownership verification, usage quotas, and structured exports.

> Masters project context: This project originated as a Masters-level learning tool to teach SQL injection safely to non‑technical users by abstracting SQLMap complexity and providing explainable results. It also evolves into a developer‑friendly, team‑ready tool with integrations and pricing. The README highlights both tracks.

## 🚀 What’s Included (Current State)

### Core
- SQLMap orchestration with prebuilt profiles (basic, deep, enumeration, dump, custom)
- Real‑time scan output over WebSockets; start/terminate from the UI
- Structured results parsing (CSV dumps, session DB, traffic logs)
- Report generation with evidence, risk summary, and multi‑format export (JSON/HTML/PDF)
- Lightweight recon/parameter discovery to prioritize likely injection points
 - Per‑user scan settings and reusable profiles (save, load, set default; last‑used profile remembered)

### Security & Multi‑Tenancy
- JWT auth (REST + Socket.io) with per‑user/org scoping
- Target ownership verification (HTTP file or DNS TXT) enforced by default
- Rate limiting, input validation/sanitization, and command whitelisting
- Per‑user concurrency caps and monthly scan quotas
- Audit/event logs for scan lifecycle and security events

### UX
- Modern React + Tailwind UI (Dashboard, Targets, Reports, Report Details, Terminal, Usage, Settings)
- Dark theme, responsive layout, scan history and details
 - Settings page with collapsible sections: My Defaults, Custom Builder (live server validation), Preconfigured Types, Saved Profiles

### Technical
- Node/Express + Socket.io backend; SQLite persistence with indices/migrations
- Winston logging to files (combined, error, security, exceptions, rejections)
- Puppeteer‑based PDF export with HTML fallback
- Daily retention cleanup for old scan output dirs

## 🛠️ Tech Stack
## 🎓 Learning Track vs Pro Track

- Learning Mode (Masters focus)
   - Guided wizard (no flags), Practice Mode with simulated outputs (no SQLMap required), explainability panels (Why/Signals/Verify/Fix), safe defaults and enforced target verification.
- Pro/Team Mode (Product focus)
   - Real scans with SQLMap orchestration, multi-user quotas, PDF/CSV exports, Slack/Jira (planned), scheduler/queue, and team audit.

Both tracks share the same backend, so you can start in Learning Mode for education and later enable Pro features for production use.


### Backend
- Express.js, Socket.io, SQLite, Winston, Helmet, Rate‑limit, sanitize‑html, validator

### Frontend
- React 18 + TypeScript, Vite, Tailwind, Zustand, React Router, xterm.js

### Security
- Input sanitization, URL validation, CORS/Helmet, rate limiting, error handling

## 📦 Installation & Dev

### Prerequisites
- Node.js (v16 or higher)
- npm (v8 or higher)
- SQLMap installed on the system
- Git for version control

### Quick Start

1. Clone
   ```bash
   git clone https://github.com/theGoodB0rg/CyberSec.git
   cd CyberSec
   ```

2. Install
   ```bash
   npm run install-all
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. Start dev (runs server and client together)
   ```bash
   npm run dev
   ```

5. **Access the application**
   - Open your browser to `http://localhost:5173`
   - The backend API runs on `http://localhost:3001`

### Production
1) Build client and prepare server bundle
```bash
npm run build
```
2) Start
```bash
npm start
```

## 🌍 Deployment

The repository now ships with a Dockerfile, Fly launch configuration (`fly.toml`), and an automated workflow for deploying the backend to Fly.io. See [`docs/deployment/fly.md`](docs/deployment/fly.md) for a full walkthrough.

### Fly.io quick start

1. Install and authenticate the Fly CLI: `fly auth login`.
2. Initialize the app (non-destructive):
   ```powershell
   fly launch --name cybersec-backend --no-deploy
   ```
3. Provision persistent storage for SQLite, temp artifacts, and evidence bundles:
   ```powershell
   fly volumes create app_data --region <your-region> --size 1
   ```
4. Update `fly.toml` to mount the volume at `/data` and set:
   - `DB_PATH = "/data/cybersecurity.db"`
   - `TEMP_DIR = "/data/temp"`
   - `EVIDENCE_DIR = "/data/evidence"`
   - `SQLMAP_PATH = "/usr/bin/sqlmap"`
   - `PUPPETEER_EXECUTABLE_PATH = "/usr/bin/chromium"`
5. Configure secrets for the initial admin and JWT signing key:
   ```powershell
   fly secrets set JWT_SECRET=<secure-value> ADMIN_EMAIL=<admin-email> ADMIN_PASSWORD=<strong-password>
   ```
6. Deploy and tail logs to confirm the service boots and the health checks pass:
   ```powershell
   fly deploy
   fly logs
   ```

The `/api/health` endpoint returns a JSON object with status for SQLite, job queue, and SQLMap. If any dependency is unavailable, the endpoint returns `status: "degraded"` and Fly will mark the instance unhealthy for auto-recovery.

## �🎯 Usage (Typical Flow)

### Basic Workflow

1) Login (register first if needed). The UI attaches your JWT to API and socket connections.

2) Verify target ownership (Targets page) via HTTP file or DNS TXT; non‑verified targets are blocked unless admin allows.

3) Start a scan (Dashboard/Terminal)
- Choose profile (basic/deep/enumeration/dump/custom)
- Optional options: cookie, headers, data, method, proxy, timeout/delay
- See real‑time `scan-output`, completion status, and link to report

4) Review results
- Report includes parsed findings, CSV dumps, session DB path, traffic log, risk summary
- Export as JSON/HTML/PDF; CSV files downloadable via signed file route

4. **Manage Reports**
   - Browse historical scan reports
   - Filter and search capabilities
   - Export and share findings

### Scan Profiles (preconfigured)

#### Basic Scan
```bash
sqlmap -u <target> --batch --random-agent --level=1 --risk=1
```

#### Deep Scan
```bash
sqlmap -u <target> --batch --random-agent --level=3 --risk=2 --threads=2
```

#### Database Enumeration
```bash
sqlmap -u <target> --batch --random-agent --dbs --tables --columns
```

#### Data Extraction
```bash
sqlmap -u <target> --batch --random-agent --dump --exclude-sysdbs
```

### Custom Builder & Validation

The Settings page includes a Custom Builder powered by a server‑side validator. It safely parses and normalizes allowed flags (no sqlmap spawn) and returns:

- ok, disallowed, warnings
- normalizedArgs (flags that will be applied)
- commandPreview (what would run)
- description and impact (speed/stealth/exfil heuristics)

API:
```http
POST /api/sqlmap/validate
Body: { target?: string, profile: string, customFlags?: string, options?: object }
```
The UI shows syntax feedback and blocks saving disallowed flags.

### User Settings & Profiles

- Per‑user settings: default_profile, defaults (level/risk/threads/tamper), last_used_profile
- Reusable profiles (per user): name, description, flags[]; unique by name
- The Terminal auto‑selects your last_used_profile (fallback to default_profile) on load

APIs:
```http
GET  /api/user/scan-settings
PUT  /api/user/scan-settings         # { default_profile, defaults, last_used_profile? }

GET  /api/user/profiles              # list
POST /api/user/profiles              # { name, description?, flags[] }
PUT  /api/user/profiles/:id          # { name?, description?, flags? }
DEL  /api/user/profiles/:id

GET  /api/sqlmap/profiles            # server preconfigured profiles (list for UI)
```

### Terminal Commands (whitelisted)
- `sqlmap-help`, `sqlmap-version`, `list-profiles`, `validate-target <url>`

## 📄 Reports & Structured Output

The application now provides comprehensive structured output from SQLMap scans:

### Output

### Exports and Downloads

You can export reports in multiple formats from the UI or via REST endpoints:

- GET `/api/reports/:id/export/json` → JSON
- GET `/api/reports/:id/export/html` → HTML
- GET `/api/reports/:id/export/csv` → CSV (findings table)
- GET `/api/reports/:id/export/pdf` → PDF

If the server cannot render a PDF (Chromium/Puppeteer unavailable), it returns a PDF-styled HTML instead with header `X-PDF-Fallback: true` and the UI will save it as `*.html`. You can print it to PDF via the browser (Ctrl+P → Save as PDF).

For csv dumps produced by sqlmap (tables content), use:
`GET /api/reports/:id/files/:filename` (ownership enforced) to download individual CSV artifacts located under the scan output directory. The server recognizes both `results.csv` and `results-*.csv` naming patterns.

---
### 📤 **Report Export & Download – Professional Usage & Troubleshooting**

#### **Export Endpoints**

- `GET /api/reports/:id/export/json` – Download full report as JSON
- `GET /api/reports/:id/export/html` – Download full report as HTML
- `GET /api/reports/:id/export/pdf` – Download full report as PDF (uses Puppeteer; falls back to HTML if headless Chromium is unavailable)
- `GET /api/reports/:id/export/csv` – Download findings table as CSV (not raw SQLMap dump)
- `GET /api/reports/:id/files/:filename` – Download raw SQLMap CSV dump or other artifacts (ownership enforced)

#### **How to Export Reports**

- **From the UI**: On the Reports list or Report Details page, use the download buttons to export in your preferred format. PDF, HTML, JSON, and CSV are available. CSV (findings) is distinct from raw SQLMap CSV dumps.
- **From the API**: Use the endpoints above with your JWT token. For file downloads, ensure you have access rights to the report.

#### **PDF Export Details**

- PDF export uses Puppeteer (headless Chromium). If Puppeteer is not available or fails, the server returns a styled HTML with header `X-PDF-Fallback: true`. The UI will save this as `.html` and prompt you to print to PDF via your browser.
- A legacy Markdown-to-PDF workflow powered by `markdown-pdf`/PhantomJS is still bundled for future use. The Docker image now installs the PhantomJS prerequisites (`bzip2`, font libraries, GTK stack) so this path can be re-enabled without additional setup.
- All binary downloads set correct `Content-Type` and `Content-Disposition` headers for professional compatibility.

#### **CSV Export Details**

- The `/export/csv` endpoint provides a clean, findings-only CSV (not a raw SQLMap dump).
- For raw SQLMap CSVs (table dumps), use `/files/:filename` with the correct filename (e.g., `results.csv`, `results-20240629_0929pm.csv`).
- The server detects all `results-*.csv` files in the scan output directory.

#### **Troubleshooting PDF/CSV Exports**

- **Malformed PDF or unopenable file?**
   - Ensure Puppeteer/Chromium is installed and accessible on the server.
   - If you receive an HTML file instead of PDF, check for the `X-PDF-Fallback: true` header. Open in browser and print to PDF.
   - If you reinstate the Markdown/PhantomJS export, keep the Dockerfile’s `bzip2`/font stack in place so `phantomjs-prebuilt` can extract successfully during image builds.
- **Empty CSV file?**
   - Ensure the scan produced findings. The `/export/csv` endpoint only exports findings, not raw dumps.
   - For raw SQLMap CSVs, verify the file exists in the scan output directory and use the `/files/:filename` endpoint.
- **Download fails or file is corrupt?**
   - Ensure you are authenticated and have access to the report.
   - Check that your client handles binary downloads correctly (the UI uses Blob and detects PDF/HTML fallback automatically).

#### **Client/Server Download Behavior**

- The client detects PDF fallbacks and saves as `.html` if needed.
- All downloads use proper headers for browser compatibility.
- Ownership and path traversal are enforced on all file downloads.

---

### Report Features
- **Professional Formatting**: Clean, organized vulnerability reports
- **Downloadable Files**: Access to all generated CSV and log files
- **Structured Findings**: Parsed vulnerability data with:
  - Parameter names and injection points
  - SQL injection techniques detected
  - Database version and system information
  - Risk classifications and severity levels

### File Access
Secure route to download CSV dumps for your scan only:
`GET /api/reports/:id/files/:filename` (ownership enforced; path traversal protected)

This ensures you have access to well-formatted, professional results suitable for:
- Security audit documentation
- Client reporting
- Further analysis and research
- Integration with other security tools

## � Quick Verify & Evidence Capture

Quick Verify replays lightweight boolean/time/error probes (and, when safe, your strongest SQLMap payload) to validate findings without a full SQLMap rerun. The workflow now captures forensic evidence with explicit user consent:

- **Consent-aware prompt** – When you verify a finding (single or bulk), the Report Details UI asks whether to store raw HTTP responses. You can store or skip, and optionally remember the decision for future runs.
- **Evidence vault** – When storage is allowed, the backend writes JSON bundles under `server/temp/quick-verify-evidence/<report>/<finding>/<timestamp>/`. Each bundle contains headers, payload metadata, a base64-encoded body, and integrity hashes.
- **Per-run feedback** – The verification panel shows whether raw responses were stored, highlights the latest consent preference, and lists the captured evidence with status codes, timings, hashes, and download links.
- **Safer previews** – Proof-of-concept cards now display compact response snapshots (status, latency, size, hash, optional excerpt) and download buttons that pull the full JSON via an authenticated route. If storage was skipped, the UI makes that explicit.

### Managing consent preferences

Preferences are persisted per user. You can adjust them directly via the API:

```http
GET    /api/quick-verify/preferences           # fetch your current preference
POST   /api/quick-verify/preferences           # body: { storeEvidence, rememberChoice?, promptVersion?, source? }
DELETE /api/quick-verify/preferences           # clears the saved preference
```

Skipping storage keeps Quick Verify fast and ephemeral. Allowing storage creates an audit trail you can download or share later.

### Working with stored evidence programmatically

List or download stored responses for a finding:

```http
GET /api/reports/:reportId/findings/:findingId/quick-verify/evidence?limit=50
GET /api/quick-verify/evidence/:evidenceId/download
```

Both routes enforce user/org ownership unless the caller is an admin. Downloads stream the exact JSON blob written during verification (headers, metadata, base64 body, SHA-256 digest).

## �🔧 Configuration

### Environment Variables

Create a `.env` in the repo root (values shown are examples; see server/index.js for defaults):

```env
# Server Configuration
NODE_ENV=development
PORT=3001
LOG_LEVEL=info

# Database Configuration
DB_PATH=./server/data/cybersecurity.db

# Security Configuration
# JWT secret for auth tokens
JWT_SECRET=change-me
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100

# SQLMap Configuration
SQLMAP_PATH=sqlmap
# Optional: enforce proxy usage for scans
REQUIRE_PROXY=false
# Retain scan output dirs for N days (cleanup scheduled daily at 03:30)
OUTPUT_RETENTION_DAYS=7

# Multi-user Controls
# Max concurrent scans allowed per non-admin user
MAX_CONCURRENT_SCANS_PER_USER=2
# Monthly scan quota per non-admin user (YYYY-MM buckets)
MAX_SCANS_PER_MONTH=100
# Require target domain verification before scanning (recommended true)
ALLOW_UNVERIFIED_TARGETS=false

# Scheduler / Queue
ENABLE_JOB_QUEUE=true
JOB_POLL_INTERVAL_MS=3000
JOB_FETCH_BATCH=10
JOB_BACKOFF_BASE_SECONDS=10
JOB_BACKOFF_FACTOR=2.0
JOB_BACKOFF_MAX_SECONDS=600
```

### Application Settings

Settings can be configured through the web interface:

- **Theme**: Dark/Light mode
- **Terminal Font Size**: Adjustable font size
- **Notifications**: Enable/disable notifications
- **Auto-save**: Automatic saving of scans
- **Concurrent Scans**: Maximum simultaneous scans

## 📊 API (REST)

### Health Check
```http
GET /api/health
```

Returns `200 OK` when core subsystems (SQLite, job queue, SQLMap integration) are healthy and responds with `503 Service Unavailable` plus `status: "degraded"` when any dependency is offline. Example response:

```json
{
   "status": "healthy",
   "uptimeSeconds": 123,
   "environment": "production",
   "timestamp": "2025-10-02T22:28:16.000Z",
   "database": { "ok": true },
   "queue": {
      "enabled": true,
      "running": true,
      "timerActive": true,
      "pollIntervalMs": 3000,
      "ok": true
   },
   "sqlmap": {
      "available": true,
      "path": "/usr/bin/sqlmap",
      "ok": true
   }
}
```

When `sqlmap.available` is `false` or the queue is paused, the endpoint reports `status: "degraded"` so load balancers can mark the instance unhealthy.

### Auth
```http
POST /api/auth/register
POST /api/auth/login
GET  /api/auth/me
```

### Targets (ownership verification)
```http
GET    /api/targets
POST   /api/targets                 # { hostname, method: http-file|dns-txt } -> token issued
POST   /api/targets/:id/verify      # performs file/DNS check; sets verified_at
DELETE /api/targets/:id
```

### Recon
```http
POST /api/recon  # { target }
GET  /api/recon?target=...
```

### Reports
```http
GET /api/reports
GET /api/reports/:id
GET /api/reports/:id/export/:format
GET /api/reports/:id/files/:filename   # secure CSV download
DELETE /api/reports/:id
```

### Usage and Quotas
```http
GET /api/usage  # returns current period usage and configured limits for the authenticated user
```

### Scans
```http
GET /api/scans           # list scans for current user (admin may see all)
GET /api/scans/running   # list only running scans for current user
GET /api/scans/:id/events # audit/event stream for a scan (ownership enforced)
```

### WebSocket Events
- `start-sqlmap-scan`  { target, options, scanProfile, userProfileId?, userProfileName? }
-  • If a saved profile is provided, the server merges its flags and uses `custom` as the effective profile; it remembers it as `last_used_profile`.
- `terminate-scan`     { scanId? }
- `execute-command`    { command, args }
- `scan-output`        { scanId, type, output }
- `scan-completed`     { scanId, status, reportId, hasStructuredResults }
- `scan-error`         { message }
- `auth-ok`            { userId, role, orgId }

## 🛡️ Security Considerations

### Input Validation
- All user inputs are validated and sanitized
- URL validation prevents access to internal networks
- Command whitelisting ensures only safe commands are executed

### Rate Limiting
- API requests are limited to prevent abuse
- Scan requests are limited per hour per IP
- WebSocket connections are monitored and limited

### Process Security
- Per‑user output directories in OS temp; daily cleanup by retention policy
- Background scans continue on socket disconnect; server restart marks running as interrupted
 - Server‑side flag whitelist/normalization on `/api/sqlmap/validate` and safe merging of saved profile flags when starting scans

### Data Protection
- Sensitive data is masked in reports
- Database queries are parameterized
- Error messages don't leak system information

## 🧪 Dev Tips
- Lint backend: `npm run lint`
- Lint client: `npm run client:lint`
- Build all: `npm run build`
 - Validate flags (no sqlmap spawn): POST `/api/sqlmap/validate`

## 📱 Mobile Support

The application is fully responsive and supports:
- Touch interactions for mobile devices
- Responsive terminal interface
- Mobile-optimized navigation
- Gesture support for common actions

## 🔍 Troubleshooting

### Common Issues

1. **SQLMap not found**
   - Ensure SQLMap is installed and in PATH
   - Update SQLMAP_PATH in environment variables

2. **Connection issues**
   - Check if backend server is running
   - Verify firewall settings
   - Check network connectivity

3. **Permission errors**
   - Ensure proper file permissions
   - Check SQLMap execution permissions
   - Verify output directory write access

### Windows-specific tips

- Client OOM or sudden crash at startup:
   - Ensure the client does not depend on the repo root. We removed a local file dependency to prevent Vite from crawling the entire workspace.
   - Vite watch ignores heavy folders (server/, logs/, temp/, data/) via `client/vite.config.ts` to reduce file watcher load.
   - Tailwind content is scoped to `client/` only.
- Port conflicts (EADDRINUSE: :3001 or Vite port bump):
   - Make sure you run `npm run dev` once from the repo root. If you accidentally start multiple sessions, kill stray Node processes or close duplicate terminals.
   - Nodemon is configured via `nodemon.json` to watch only `server/**`.
- Proxy errors in Vite (`/api/health` ECONNREFUSED):
   - This is transient while the server boots. It should clear once the backend is listening on 3001.

### Proxy and trust-proxy configuration

You can configure whether scans must use an outbound proxy, and how Express calculates client IPs (trust proxy):

- REQUIRE_PROXY: if set to `true`/`1`/`yes`/`on`, scans must include a valid proxy URL (http(s):// or socks5:// host:port). Example:
   - `REQUIRE_PROXY=false` (default)

- TRUST_PROXY: controls Express "trust proxy". Accepts:
   - `auto` (default; trusts loopback/linklocal/uniquelocal)
   - `true` (trust all)
   - `false` (trust none)
   - or a comma-separated list of IP/CIDR values

Admin overrides: As an admin, you can change these sitewide at runtime in Admin → Site Settings. Changes are persisted in the DB and applied immediately; they override env at runtime. If you see an express-rate-limit error about X-Forwarded-For in dev, set TRUST_PROXY to `auto` or `true`.

### Debug Mode

Enable debug mode by setting:
```env
LOG_LEVEL=debug
NODE_ENV=development
```

## 📈 Notes & Caveats
- SQLMap must be installed and reachable (PATH or SQLMAP_PATH). On Windows, `py -m sqlmap` may be detected automatically.
- PDF export uses Puppeteer; when headless is unavailable, the server falls back to HTML export and sets `X-PDF-Fallback: true`.
- Scanning non‑verified targets is blocked unless ALLOW_UNVERIFIED_TARGETS=true or you’re admin.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Guidelines
- Follow TypeScript best practices
- Use ESLint and Prettier for code formatting
- Write comprehensive tests
- Update documentation as needed

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- SQLMap team for the excellent security testing tool
- React and Node.js communities
- XTerm.js for the terminal interface
- Tailwind CSS for the design system

## 📞 Support
- Open an issue on GitHub
- Check Troubleshooting below

---

**⚠️ Legal Notice**: Use only on assets you own or are authorized to test. Target ownership verification is enforced by default.

**🔒 Security Disclosure**: If you discover a security vulnerability, please report it responsibly to the maintainers.
