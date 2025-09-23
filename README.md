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

### Security & Multi‑Tenancy
- JWT auth (REST + Socket.io) with per‑user/org scoping
- Target ownership verification (HTTP file or DNS TXT) enforced by default
- Rate limiting, input validation/sanitization, and command whitelisting
- Per‑user concurrency caps and monthly scan quotas
- Audit/event logs for scan lifecycle and security events

### UX
- Modern React + Tailwind UI (Dashboard, Targets, Reports, Report Details, Terminal, Usage, Settings)
- Dark theme, responsive layout, scan history and details

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

## 🎯 Usage (Typical Flow)

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

### Terminal Commands (whitelisted)
- `sqlmap-help`, `sqlmap-version`, `list-profiles`, `validate-target <url>`

## 📄 Reports & Structured Output

The application now provides comprehensive structured output from SQLMap scans:

### Output
- CSV dumps, session.sqlite, traffic.log
- JSON/HTML/PDF report exports (PDF via Puppeteer; auto HTML fallback if headless fails)

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

## 🔧 Configuration

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
- `start-sqlmap-scan`  { target, options, scanProfile }
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

### Data Protection
- Sensitive data is masked in reports
- Database queries are parameterized
- Error messages don't leak system information

## 🧪 Dev Tips
- Lint backend: `npm run lint`
- Lint client: `npm run client:lint`
- Build all: `npm run build`

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
