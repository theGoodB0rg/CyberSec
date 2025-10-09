# Third-Party Notices

CyberSec orchestrates or depends on the following third-party components. Each
component is licensed separately by its respective authors. You must comply with
the applicable licenses before installing, executing, or redistributing any of
these components.

## Runtime / Tooling Integrations

| Component | License | Notes |
|-----------|---------|-------|
| SQLMap | GPLv2 | Docker builds clone the latest SQLMap dev branch (`https://github.com/sqlmapproject/sqlmap.git`) and wrap it with `python3 /opt/sqlmap/sqlmap.py`. For other environments CyberSec shells out to whatever SQLMap binary you configure. Ensure you comply with the GPLv2 license terms when using or redistributing SQLMap. |
| Puppeteer / Chromium | Apache 2.0 / BSD-like | Required for PDF exports. Installed via npm when building the project. |

## Backend Libraries (npm)

These packages are referenced in `package.json` and are typically published under
permissive licenses. Verify the license text in the package metadata before
shipping a commercial build.

- Express (MIT)
- Socket.io (MIT)
- Winston (MIT)
- bcrypt (MIT)
- sqlite3 (BSD)
- sanitize-html (MIT)
- validator (MIT)
- cors (MIT)
- helmet (MIT)
- express-rate-limit (MIT)
- multer (MIT)
- uuid (MIT)
- axios (MIT)
- cheerio (MIT)

## Frontend Libraries (client/package.json)

- React / React DOM (MIT)
- Vite (MIT)
- Tailwind CSS (MIT)
- Zustand (MIT)
- date-fns (MIT)
- Headless UI (MIT)
- Lucide Icons (ISC)
- React Hot Toast (MIT)
- React Router (MIT)
- XTerm.js (MIT)

This list is provided for convenience and may be incomplete. Always review the
current dependency tree (`npm ls --json`) and consult each package’s license file
before distributing a build.
