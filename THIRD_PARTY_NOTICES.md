# Third-Party Notices

CyberSec orchestrates or depends on the following third-party components. Each
component is licensed separately by its respective authors. You must comply with
the applicable licenses before installing, executing, or redistributing any of
these components.

## Runtime / Tooling Integrations

| Component | License | Notes |
|-----------|---------|-------|
| SQLMap | GPLv2 | CyberSec shells out to a system installation of SQLMap. The SQLMap project is not bundled with this repository. You must obtain SQLMap separately and comply with the GPLv2 license terms when using it. |
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
