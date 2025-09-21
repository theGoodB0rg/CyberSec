# Cybersecurity Web App - SQLMap Integration

A comprehensive, professional cybersecurity web application featuring an interactive terminal interface and seamless SQLMap integration for SQL injection testing and security assessments.

## 🚀 Features

### Core Functionality
- **Interactive Web Terminal**: Real-time command execution with full terminal experience
- **SQLMap Integration**: Simplified interface for complex security testing
- **Intelligent Reporting**: Automated report generation with comprehensive analysis and structured CSV output
- **Well-Formatted Results**: Professional SQLMap output parsing with downloadable CSV files
- **Real-time Communication**: WebSocket-based live updates and process control
- **Mobile Responsive**: Fully responsive design for all device sizes

### Security Features
- **Input Validation & Sanitization**: Comprehensive security middleware
- **Rate Limiting**: API and scan rate limiting protection
- **Secure Command Execution**: Whitelisted commands and sanitized inputs
- **Attack Detection**: Built-in security scanning and threat detection
- **Audit Logging**: Comprehensive security event logging

### User Experience
- **Modern UI/UX**: Clean, professional cybersecurity-themed interface
- **Dark Mode**: Optimized for security professionals
- **Resizable Panels**: Customizable workspace layout
- **Command History**: Terminal command history with arrow key navigation
- **Ctrl+C Support**: Process termination and interrupt handling

### Technical Capabilities
- **Multiple Scan Profiles**: Pre-configured SQLMap scanning profiles
- **Custom Scan Options**: Advanced users can specify custom SQLMap flags
- **Report Export**: PDF, HTML, Markdown, and JSON export formats
- **Data Persistence**: SQLite database for scans and reports
- **Performance Monitoring**: Built-in performance and health monitoring

## 🛠️ Technology Stack

### Backend
- **Node.js** with Express.js for the web server
- **Socket.io** for real-time communication
- **SQLite** for data persistence
- **Winston** for comprehensive logging
- **Helmet** for security headers
- **Rate limiting** and input validation

### Frontend
- **React 18** with TypeScript
- **Vite** for fast development and building
- **Tailwind CSS** for modern styling
- **Zustand** for state management
- **XTerm.js** for terminal interface
- **React Router** for navigation

### Security
- **Input sanitization** with sanitize-html
- **URL validation** with validator.js
- **Command whitelisting** and validation
- **CORS configuration** and security headers
- **Error handling** and graceful degradation

## 📦 Installation

### Prerequisites
- Node.js (v16 or higher)
- npm (v8 or higher)
- SQLMap installed on the system
- Git for version control

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/theGoodB0rg/CyberSec.git
   cd cybersecurity-web-app
   ```

2. **Install dependencies**
   ```bash
   npm run install-all
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start the development servers**
   ```bash
   npm run dev
   ```

5. **Access the application**
   - Open your browser to `http://localhost:5173`
   - The backend API runs on `http://localhost:3001`

### Production Deployment

1. **Build the application**
   ```bash
   npm run build
   ```

2. **Start the production server**
   ```bash
   npm start
   ```

## 🎯 Usage

### Basic Workflow

1. **Access the Terminal**
   - Navigate to the Terminal page
   - Use the interactive terminal for SQLMap commands
   - View real-time output and progress

2. **Start a Security Scan**
   - Enter target URL
   - Select scan profile (Basic, Deep, Enumeration, etc.)
   - Configure additional options if needed
   - Monitor progress in real-time

3. **Review Results**
   - Automatic report generation upon completion
   - Structured CSV output with downloadable files
   - Session data preservation for analysis
   - View vulnerabilities and recommendations
   - Export reports in multiple formats

4. **Manage Reports**
   - Browse historical scan reports
   - Filter and search capabilities
   - Export and share findings

### Scan Profiles

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

### Terminal Commands

The application supports various terminal commands:

- `sqlmap-help` - Display SQLMap help information
- `sqlmap-version` - Show SQLMap version
- `list-profiles` - List available scan profiles
- `validate-target <url>` - Validate target URL
- `clear` - Clear terminal output
- `help` - Show available commands

## 📄 Structured Output & Report Generation

The application now provides comprehensive structured output from SQLMap scans:

### Output Formats
- **CSV Files**: Well-formatted data extraction results
- **Session Files**: SQLite database with scan session data
- **Traffic Logs**: HTTP request/response logs for analysis
- **JSON/HTML/PDF Reports**: Structured vulnerability findings

### Report Features
- **Professional Formatting**: Clean, organized vulnerability reports
- **Downloadable Files**: Access to all generated CSV and log files
- **Structured Findings**: Parsed vulnerability data with:
  - Parameter names and injection points
  - SQL injection techniques detected
  - Database version and system information
  - Risk classifications and severity levels

### File Access
Reports include direct download links for:
- Individual CSV dump files
- Session database files
- HTTP traffic logs
- Parsed JSON results

This ensures you have access to well-formatted, professional results suitable for:
- Security audit documentation
- Client reporting
- Further analysis and research
- Integration with other security tools

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Server Configuration
NODE_ENV=development
PORT=3001
LOG_LEVEL=info

# Database Configuration
DB_PATH=./server/data/cybersecurity.db

# Security Configuration
JWT_SECRET=your-jwt-secret-here
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100

# SQLMap Configuration
SQLMAP_PATH=/usr/bin/sqlmap
SQLMAP_OUTPUT_DIR=./server/temp

# Multi-user Controls
# Max concurrent scans allowed per non-admin user
MAX_CONCURRENT_SCANS_PER_USER=2
# Monthly scan quota per non-admin user (YYYY-MM buckets)
MAX_SCANS_PER_MONTH=100
# Require target domain verification before scanning (recommended true)
ALLOW_UNVERIFIED_TARGETS=false
# JWT secret for auth tokens
JWT_SECRET=change-me
```

### Application Settings

Settings can be configured through the web interface:

- **Theme**: Dark/Light mode
- **Terminal Font Size**: Adjustable font size
- **Notifications**: Enable/disable notifications
- **Auto-save**: Automatic saving of scans
- **Concurrent Scans**: Maximum simultaneous scans

## 📊 API Documentation

### Health Check
```http
GET /api/health
```

### Reports
```http
GET /api/reports
GET /api/reports/:id
GET /api/reports/:id/export/:format
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
```

### WebSocket Events
- `start-sqlmap-scan` - Initiate a new scan
- `terminate-scan` - Stop running scan
- `execute-command` - Execute terminal command
- `scan-output` - Receive real-time output
- `scan-completed` - Scan completion notification
 - `scan-error` - Error when starting or running a scan (quota, verification, etc.)
 - `auth-ok` - Emitted on successful socket authentication with { userId, role, orgId }

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
- SQLMap processes run with limited privileges
- Temporary files are cleaned up automatically
- Process termination is handled securely

### Data Protection
- Sensitive data is masked in reports
- Database queries are parameterized
- Error messages don't leak system information

## 🧪 Testing

### Run Tests
```bash
npm test
```

### Linting
```bash
npm run lint
```

### Type Checking
```bash
npm run type-check
```

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

### Debug Mode

Enable debug mode by setting:
```env
LOG_LEVEL=debug
NODE_ENV=development
```

## 📈 Performance

### Optimization Features
- Lazy loading of components
- Code splitting for better load times
- Efficient state management
- Optimized WebSocket communication
- Database query optimization

### Monitoring
- Built-in performance monitoring
- Resource usage tracking
- Error rate monitoring
- Response time metrics

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

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the troubleshooting guide

---

**⚠️ Legal Notice**: This tool is for authorized security testing only. Always ensure you have proper authorization before testing any systems. The developers are not responsible for any misuse of this application.

**🔒 Security Disclosure**: If you discover a security vulnerability, please report it responsibly to the maintainers.
