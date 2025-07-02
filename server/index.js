const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const os = require('os');

// Import custom modules
const Database = require('./database');
const SQLMapIntegration = require('./sqlmap');
const ReportGenerator = require('./reports');
const SecurityMiddleware = require('./middleware/security');
const Logger = require('./utils/logger');

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production' 
      ? false 
      : /http:\/\/localhost:\d+/, // Allow all localhost ports in dev
    methods: ["GET", "POST"]
  }
});

// Configuration
const PORT = process.env.PORT || 3001;
const DB_PATH = path.join(__dirname, 'data', 'cybersecurity.db');

// Ensure data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// CORS configuration (allow any localhost port while developing)
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? false : /http:\/\/localhost:\d+/,
  credentials: true,
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static file serving
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/dist')));
}

// Initialize database
const database = new Database(DB_PATH);
const sqlmapIntegration = new SQLMapIntegration();
const reportGenerator = new ReportGenerator(database);

// Track running scans and their output directories
let scanProcesses = new Map();

// Security middleware
app.use('/api', SecurityMiddleware.validateInput);
app.use('/api', SecurityMiddleware.sanitizeInput);

// API Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Get all scans
app.get('/api/scans', async (req, res) => {
  try {
    const scans = await database.getScans();
    res.json(scans);
  } catch (error) {
    Logger.error('Error fetching scans:', error);
    res.status(500).json({ error: 'Failed to fetch scans' });
  }
});

// Get all scan reports
app.get('/api/reports', async (req, res) => {
  try {
    const reports = await database.getReports();
    res.json(reports);
  } catch (error) {
    Logger.error('Error fetching reports:', error);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

// Get specific report
app.get('/api/reports/:id', async (req, res) => {
  try {
    const report = await database.getReport(req.params.id);
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    res.json(report);
  } catch (error) {
    Logger.error('Error fetching report:', error);
    res.status(500).json({ error: 'Failed to fetch report' });
  }
});

// Export report
app.get('/api/reports/:id/export/:format', async (req, res) => {
  try {
    const { id, format } = req.params;
    const report = await database.getReport(id);
    
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }

    const exportedData = await reportGenerator.exportReport(report, format);
    
    // Handle PDF fallback case
    if (format.toLowerCase() === 'pdf' && typeof exportedData === 'object' && exportedData.length && exportedData[0] === 0x3C) {
      // This looks like HTML content (starts with '<'), so it's likely a fallback
      Logger.warn('PDF export returned HTML fallback', { reportId: id });
      res.setHeader('Content-Disposition', `attachment; filename="report-${id}-fallback.html"`);
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('X-PDF-Fallback', 'true'); // Custom header to indicate fallback
    } else {
      res.setHeader('Content-Disposition', `attachment; filename="report-${id}.${format}"`);
      res.setHeader('Content-Type', reportGenerator.getContentType(format));
    }
    
    res.send(exportedData);
  } catch (error) {
    Logger.error('Error exporting report:', error);
    res.status(500).json({ error: 'Failed to export report' });
  }
});

// Download CSV results file
app.get('/api/reports/:id/files/:filename', async (req, res) => {
  try {
    const { id, filename } = req.params;
    const report = await database.getReport(id);
    
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }

    // Check if the report has structured results with files
    if (!report.outputFiles || !report.outputFiles.dumps) {
      return res.status(404).json({ error: 'No output files found for this report' });
    }

    // Find the requested file
    const file = report.outputFiles.dumps.find(f => f.name === filename);
    if (!file || !fs.existsSync(file.path)) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Security check - ensure file is within temp directory
    const tempDir = path.join(os.tmpdir(), 'cybersec-sqlmap');
    const normalizedPath = path.normalize(file.path);
    if (!normalizedPath.startsWith(tempDir)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'text/csv');
    res.sendFile(file.path);
  } catch (error) {
    Logger.error('Error downloading file:', error);
    res.status(500).json({ error: 'Failed to download file' });
  }
});

// Delete report
app.delete('/api/reports/:id', async (req, res) => {
  try {
    const success = await database.deleteReport(req.params.id);
    if (!success) {
      return res.status(404).json({ error: 'Report not found' });
    }
    res.json({ message: 'Report deleted successfully' });
  } catch (error) {
    Logger.error('Error deleting report:', error);
    res.status(500).json({ error: 'Failed to delete report' });
  }
});

// Test PDF generation endpoint
app.get('/api/test-pdf', async (req, res) => {
  try {
    Logger.info('PDF generation test requested');
    const testPdfBuffer = await reportGenerator.testPDFGeneration();
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="pdf-test.pdf"');
    res.send(testPdfBuffer);
    
  } catch (error) {
    Logger.error('PDF test failed:', error);
    res.status(500).json({ 
      error: 'PDF test failed', 
      details: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Serve React app in production
if (process.env.NODE_ENV === 'production') {
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/dist/index.html'));
  });
}

// Socket.io connection handling
io.on('connection', (socket) => {
  Logger.info(`Client connected: ${socket.id}`);

  // Handle SQLMap scan initiation
  socket.on('start-sqlmap-scan', async (data) => {
    try {
      const { target, options, scanProfile } = data;
      
      // Validate input
      if (!target || !SecurityMiddleware.isValidURL(target)) {
        socket.emit('scan-error', { message: 'Invalid target URL provided' });
        return;
      }

      // Create scan session
      const scanId = await database.createScan({
        target,
        options,
        scanProfile,
        status: 'running',
        start_time: new Date().toISOString()
      });

      // Start SQLMap scan
      const scanProcess = await sqlmapIntegration.startScan(target, options, scanProfile);
      
      // Store the scan process and its output directory for tracking
      scanProcesses.set(scanId, {
        process: scanProcess,
        outputDir: null, // Will be set when we get the output directory from sqlmap
        target,
        scanProfile,
        startTime: new Date()
      });
      
      // Handle real-time output
      scanProcess.stdout.on('data', (data) => {
        const output = data.toString();
        socket.emit('scan-output', { scanId, output, type: 'stdout' });
        database.appendScanOutput(scanId, output, 'stdout');
        
        // Try to extract output directory from SQLMap output
        const outputDirMatch = output.match(/output directory: '([^']+)'/i);
        if (outputDirMatch && scanProcesses.has(scanId)) {
          const processInfo = scanProcesses.get(scanId);
          processInfo.outputDir = outputDirMatch[1];
          scanProcesses.set(scanId, processInfo);
          Logger.info(`Captured output directory for scan ${scanId}: ${outputDirMatch[1]}`);
        }
      });

      scanProcess.stderr.on('data', (data) => {
        const output = data.toString();
        socket.emit('scan-output', { scanId, output, type: 'stderr' });
        database.appendScanOutput(scanId, output, 'stderr');
      });

      scanProcess.on('close', async (code) => {
        const endTime = new Date().toISOString();
        let scanData = await database.getScan(scanId);
        
        // Update scan status
        await database.updateScan(scanId, {
          status: code === 0 ? 'completed' : 'failed',
          end_time: endTime,
          exit_code: code
        });

        // Get updated scan data with end time
        scanData = await database.getScan(scanId);

        // Generate report with structured results
        try {
          let sqlmapResults = null;
          
          // Parse structured SQLMap results from tracked output directory
          if (code === 0) {
            try {
              const processInfo = scanProcesses.get(scanId);
              let outputDir = null;
              
              if (processInfo && processInfo.outputDir) {
                // Use the tracked output directory
                outputDir = processInfo.outputDir;
                Logger.info(`Using tracked output directory for scan ${scanId}: ${outputDir}`);
              } else {
                // Fallback: search for the most recent directory
                const tempDir = path.join(os.tmpdir(), 'cybersec-sqlmap');
                
                if (fs.existsSync(tempDir)) {
                  const sessionDirs = fs.readdirSync(tempDir).filter(dir => {
                    const dirPath = path.join(tempDir, dir);
                    return fs.statSync(dirPath).isDirectory();
                  });
                  
                  if (sessionDirs.length > 0) {
                    const latestDir = sessionDirs
                      .map(dir => ({
                        name: dir,
                        path: path.join(tempDir, dir),
                        mtime: fs.statSync(path.join(tempDir, dir)).mtime
                      }))
                      .sort((a, b) => b.mtime - a.mtime)[0];
                    
                    outputDir = latestDir.path;
                    Logger.warn(`Fallback: using most recent output directory for scan ${scanId}: ${outputDir}`);
                  }
                }
              }
              
              if (outputDir && fs.existsSync(outputDir)) {
                sqlmapResults = await sqlmapIntegration.parseResults(outputDir, scanId);
                Logger.info(`Successfully parsed SQLMap results for scan ${scanId}`);
              } else {
                Logger.warn(`No valid output directory found for scan ${scanId}`);
              }
              
            } catch (parseError) {
              Logger.error('Error parsing SQLMap results:', parseError.message);
              // Continue without structured results
            }
          }

          const reportData = await reportGenerator.generateReport(scanId, scanData, sqlmapResults);
          const reportId = await database.createReport(reportData);
          
          socket.emit('scan-completed', { 
            scanId, 
            status: code === 0 ? 'completed' : 'failed',
            reportId: reportId,
            exit_code: code,
            hasStructuredResults: !!sqlmapResults
          });
          
          Logger.info(`Report generated successfully for scan ${scanId}, report ID: ${reportId}`);
          
        } catch (reportError) {
          Logger.error('Error generating report:', reportError);
          socket.emit('scan-error', { 
            scanId, 
            message: 'Scan completed but failed to generate report' 
          });
        } finally {
          // Clean up the scan process tracking
          scanProcesses.delete(scanId);
        }
      });

      scanProcess.on('error', (error) => {
        Logger.error('SQLMap process error:', error);
        socket.emit('scan-error', { scanId, message: error.message });
        database.updateScan(scanId, { status: 'failed', error: error.message });
        scanProcesses.delete(scanId);
      });

      // Store process reference for potential termination
      socket.scanProcess = scanProcess;
      socket.scanId = scanId;

      socket.emit('scan-started', { scanId });

    } catch (error) {
      Logger.error('Error starting scan:', error);
      socket.emit('scan-error', { message: error.message });
    }
  });

  // Handle scan termination (Ctrl+C functionality)
  socket.on('terminate-scan', () => {
    if (socket.scanProcess) {
      socket.scanProcess.kill('SIGTERM');
      socket.emit('scan-terminated', { scanId: socket.scanId });
      
      // Update scan status
      if (socket.scanId) {
        database.updateScan(socket.scanId, { 
          status: 'terminated',
          end_time: new Date().toISOString()
        });
        scanProcesses.delete(socket.scanId);
      }
    }
  });

  // Handle terminal command execution
  socket.on('execute-command', async (data) => {
    try {
      const { command, args } = data;
      
      // Validate and sanitize command
      if (!SecurityMiddleware.isAllowedCommand(command)) {
        socket.emit('command-error', { message: 'Command not allowed' });
        return;
      }

      // Execute allowed commands
      const result = await sqlmapIntegration.executeCommand(command, args);
      socket.emit('command-output', result);
      
    } catch (error) {
      Logger.error('Error executing command:', error);
      socket.emit('command-error', { message: error.message });
    }
  });

  // Handle disconnect
  socket.on('disconnect', () => {
    Logger.info(`Client disconnected: ${socket.id}`);
    
    // Clean up any running processes
    if (socket.scanProcess) {
      socket.scanProcess.kill('SIGTERM');
    }
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  Logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    database.close();
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  Logger.info('SIGINT received, shutting down gracefully');
  server.close(() => {
    database.close();
    process.exit(0);
  });
});

// Error handling
process.on('uncaughtException', (error) => {
  Logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  Logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start server
server.listen(PORT, () => {
  Logger.info(`Server running on port ${PORT}`);
  Logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
}); 