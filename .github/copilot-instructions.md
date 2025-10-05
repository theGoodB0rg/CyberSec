# GitHub Copilot Instructions for CyberSec

## Project Overview

CyberSec is a web-based SQL injection scanner and reporting platform that integrates SQLMap for security testing. It originated as a Masters-level learning tool to teach SQL injection safely and has evolved into a developer-friendly, team-ready application with multi-user support, JWT authentication, and comprehensive reporting capabilities.

### Key Capabilities
- SQLMap orchestration with prebuilt profiles (basic, deep, enumeration, dump, custom)
- Real-time scan output over WebSockets
- Target ownership verification to ensure authorized testing
- Multi-user JWT authentication with role-based access control
- Report generation with evidence and multi-format export (JSON/HTML/PDF)
- Per-user scan quotas and concurrency limits
- Lightweight reconnaissance and parameter discovery

### Target Users
- **Learning Track**: Masters-level students learning SQL injection safely
- **Pro Track**: Security professionals conducting authorized penetration testing

## Architecture

### Technology Stack

**Backend:**
- Node.js/Express.js for REST API
- Socket.io for real-time WebSocket communication
- SQLite with migrations for data persistence
- Winston for structured logging
- Helmet and express-rate-limit for security
- Puppeteer for PDF report generation

**Frontend:**
- React 18 with TypeScript
- Vite for build tooling
- Tailwind CSS for styling
- Zustand for state management
- React Router for navigation
- xterm.js for terminal interface

**Security:**
- JWT authentication for REST and Socket.io
- Input sanitization with sanitize-html and validator
- CORS and Helmet for request security
- Rate limiting per user/IP
- Command whitelisting for SQLMap integration

### Project Structure
```
├── server/                 # Backend Node.js/Express application
│   ├── index.js           # Main server entry point
│   ├── database.js        # SQLite operations and migrations
│   ├── sqlmap.js          # SQLMap orchestration
│   ├── routes/            # API route handlers
│   ├── middleware/        # Auth, validation, rate limiting
│   ├── helpers/           # Utility functions
│   └── __tests__/         # Server tests
├── client/                # Frontend React/TypeScript application
│   ├── src/
│   │   ├── pages/         # Page components
│   │   ├── components/    # Reusable components
│   │   ├── lib/           # API client and utilities
│   │   └── store/         # Zustand state management
│   └── vite.config.ts     # Vite configuration
├── scripts/               # Utility scripts
└── docs/                  # Documentation (if any)
```

## Development Guidelines

### Code Style and Standards

**TypeScript/JavaScript:**
- Follow TypeScript best practices in client code
- Use ESLint and Prettier for code formatting
- Prefer functional components with hooks in React
- Use async/await over promises for cleaner async code
- Avoid `any` types where possible; use proper typing

**Naming Conventions:**
- Use camelCase for variables and functions
- Use PascalCase for React components and TypeScript types
- Use UPPER_SNAKE_CASE for environment variables and constants
- Prefix unused variables with underscore (e.g., `_unusedVar`)

**Comments:**
- Add comments for complex business logic
- Document security-sensitive code sections
- Use JSDoc for public API functions
- Keep comments concise and up-to-date

### Testing

**Backend Tests:**
- Located in `server/__tests__/`
- Run with: `npm test`
- Write tests for API endpoints, database operations, and SQLMap integration
- Mock external dependencies (SQLMap, file system)

**Frontend Tests:**
- Use Jest for unit tests
- Test critical user flows and state management
- Mock API calls in tests

### Linting and Building

**Commands:**
- `npm run lint` - Lint server code
- `npm run client:lint` - Lint client code
- `npm run lint:all` - Lint both server and client
- `npm run build` - Build both client and server
- `npm run check` - Run linting and build (CI check)

**ESLint Configuration:**
- Root `.eslintrc.cjs` for server (Node.js environment)
- `client/.eslintrc.cjs` for client (browser environment with React/TypeScript)
- Unused variables are warnings, not errors
- `no-console` is allowed in server code

### Development Workflow

**Starting Development:**
```bash
# Install all dependencies
npm run install-all

# Start dev servers (both client and server)
npm run dev
```

**Key Environment Variables:**
- `JWT_SECRET` - Secret for JWT token signing (required)
- `DB_PATH` - Path to SQLite database
- `SQLMAP_PATH` - Path to SQLMap executable
- `ALLOW_UNVERIFIED_TARGETS` - Allow scanning without target verification (default: false)
- `LOG_LEVEL` - Winston log level (info, debug, error)

**Port Configuration:**
- Backend API: port 3001
- Frontend dev server (Vite): port 5173
- WebSocket: shares backend port (3001)

### Security Considerations

**Critical Security Rules:**
1. **Never disable target verification in production** without explicit authorization
2. **Always validate and sanitize user inputs** before database operations
3. **Use parameterized queries** to prevent SQL injection in our own database
4. **Whitelist SQLMap commands** - never pass unsanitized user input to SQLMap
5. **Respect rate limits and quotas** - enforce per-user concurrency and monthly limits
6. **Secure file operations** - validate file paths to prevent directory traversal
7. **JWT tokens must be verified** on both REST and Socket.io endpoints

**Sensitive Areas:**
- `server/sqlmap.js` - Command construction and execution
- `server/middleware/auth.js` - Authentication logic
- `server/routes/` - API input validation
- `server/database.js` - SQL query construction

### Common Patterns

**API Error Handling:**
```javascript
try {
  // Operation
  res.json({ success: true, data });
} catch (error) {
  console.error('Operation failed:', error);
  res.status(500).json({ error: 'Operation failed' });
}
```

**Socket.io Authentication:**
- Verify JWT token in Socket.io middleware
- Emit errors with `socket.emit('error', { message })`
- Emit progress updates with `socket.emit('scan-output', { data })`

**Database Operations:**
- Use prepared statements: `db.prepare(sql).run(params)`
- Handle database migrations in `database.js`
- Close statements after use

**React State Management:**
- Use Zustand stores for global state (auth, settings)
- Use local state with useState for component-specific state
- Prefer controlled components for forms

### File Organization

**When adding new features:**
- Backend routes go in `server/routes/`
- Middleware goes in `server/middleware/`
- React pages go in `client/src/pages/`
- Reusable components go in `client/src/components/`
- API client code goes in `client/src/lib/api.ts`

**When modifying existing code:**
- Keep changes minimal and focused
- Update related tests
- Update documentation if API changes
- Consider backward compatibility

## Contributing Guidelines

### Before Submitting a PR:
1. Run `npm run check` to verify linting and builds pass
2. Add tests for new features
3. Update README.md if adding user-facing features
4. Ensure no security vulnerabilities are introduced
5. Test with actual SQLMap if modifying scan functionality

### Code Review Focus Areas:
- Security implications of changes
- Error handling and edge cases
- User experience and accessibility
- Performance impact (especially for database queries)
- Compatibility with both Learning and Pro tracks

### Documentation:
- Update README.md for user-facing changes
- Update this file for architectural changes
- Add inline comments for complex logic
- Document environment variables in .env.example

## Known Caveats

- **SQLMap must be installed** and accessible via PATH or SQLMAP_PATH environment variable
- **Windows compatibility**: SQLMap may be invoked as `py -m sqlmap`
- **PDF export**: Requires Puppeteer; falls back to HTML if unavailable
- **Target verification**: Enforced by default to prevent unauthorized scanning
- **Vite watch optimization**: Heavy folders (server/, logs/, temp/, data/) are ignored to reduce memory usage
- **Port conflicts**: Kill existing processes on port 3001/5173 before starting dev servers

## Resources

- SQLMap Documentation: https://github.com/sqlmapproject/sqlmap/wiki
- React Documentation: https://react.dev/
- Express.js Guide: https://expressjs.com/
- Socket.io Documentation: https://socket.io/docs/

## Legal and Ethical Considerations

**This tool must only be used on authorized targets.** The application enforces target ownership verification by default. Contributors should:
- Never circumvent security controls
- Respect the legal notice regarding authorized testing only
- Report security vulnerabilities responsibly
- Consider ethical implications of new features
