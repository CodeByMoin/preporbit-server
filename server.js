require('dotenv').config();
const express = require("express");
const multer = require("multer");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");
const compression = require("compression");
const morgan = require("morgan");
const validator = require("validator");
const crypto = require("crypto");
const admin = require("firebase-admin");

// Initialize Firebase Admin using individual env vars
const sa = {
  type:                        process.env.FIREBASE_SA_TYPE,
  project_id:                  process.env.FIREBASE_SA_PROJECT_ID,
  private_key_id:              process.env.FIREBASE_SA_PRIVATE_KEY_ID,
  private_key:                 process.env.FIREBASE_SA_PRIVATE_KEY.replace(/\\n/g, "\n"),
  client_email:                process.env.FIREBASE_SA_CLIENT_EMAIL,
  client_id:                   process.env.FIREBASE_SA_CLIENT_ID,
  auth_uri:                    process.env.FIREBASE_SA_AUTH_URI,
  token_uri:                   process.env.FIREBASE_SA_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_SA_AUTH_PROVIDER_CERT_URL,
  client_x509_cert_url:        process.env.FIREBASE_SA_CLIENT_CERT_URL,
  universe_domain:             process.env.FIREBASE_SA_UNIVERSE_DOMAIN
};

admin.initializeApp({
  credential: admin.credential.cert(sa)
});


const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: "Too many requests from this IP, please try again later."
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs for sensitive endpoints
  message: {
    error: "Too many requests for this operation, please try again later."
  }
});

app.use(limiter);

// Data sanitization
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Compression
app.use(compression());

// Logging
app.use(morgan("combined"));

// CORS with strict configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ["http://localhost:5173"],
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing with size limits
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.json({ limit: '10mb' }));

// File upload configuration with security
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate secure filename
    const uniqueSuffix = crypto.randomBytes(16).toString('hex');
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '');
    cb(null, `${uniqueSuffix}-${sanitizedName}`);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 1
  },
  fileFilter: async (req, file, cb) => {
    try {
      // Check file extension
      const allowedExtensions = ['.tex', '.txt'];
      const ext = path.extname(file.originalname).toLowerCase();
      
      if (!allowedExtensions.includes(ext)) {
        return cb(new Error('Invalid file type. Only .tex files are allowed.'));
      }
      
      // Additional MIME type check
      const allowedMimeTypes = ['text/plain', 'application/x-tex', 'text/x-tex'];
      if (!allowedMimeTypes.includes(file.mimetype)) {
        return cb(new Error('Invalid MIME type.'));
      }
      
      cb(null, true);
    } catch (error) {
      cb(error);
    }
  }
});

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }
    
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Auth error:', error);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Input validation helpers
const validateUrl = (url) => {
  if (!url || typeof url !== 'string') return false;
  
  try {
    const urlObj = new URL(url);
    // Only allow HTTPS URLs
    if (urlObj.protocol !== 'https:') return false;
    
    // Validate domain
    if (!validator.isFQDN(urlObj.hostname)) return false;
    
    // Block localhost and private IPs
    const hostname = urlObj.hostname.toLowerCase();
    if (hostname.includes('localhost') || 
        hostname.includes('127.0.0.1') ||
        hostname.includes('::1') ||
        hostname.match(/^10\./) ||
        hostname.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./) ||
        hostname.match(/^192\.168\./)) {
      return false;
    }
    
    return true;
  } catch {
    return false;
  }
};

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return '';
  return validator.escape(input.trim());
};

// Key rotation indices
let youtubeKeyIndex = 0;
let googleCSEKeyIndex = 0;
let googleCSECXIndex = 0;

// Secure file waiting function
const waitForFile = (filePath, timeout = 5000) =>
  new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      try {
        if (fs.existsSync(filePath)) {
          const stats = fs.statSync(filePath);
          if (stats.size > 0) return resolve(true);
        }
        if (Date.now() - start > timeout) {
          return reject(new Error("File not found in time"));
        }
        setTimeout(check, 100);
      } catch (error) {
        reject(error);
      }
    };
    check();
  });

// Secure file cleanup
const cleanupFiles = (paths) => {
  for (const filePath of paths) {
    try {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`🗑️ Cleaned up: ${path.basename(filePath)}`);
      }
    } catch (error) {
      console.warn(`⚠️ Could not delete ${filePath}:`, error.message);
    }
  }
};

// Secure command execution
const executeCommand = (command, options = {}) => {
  return new Promise((resolve, reject) => {
    // Sanitize command
    const sanitizedCommand = command.replace(/[;&|`$(){}[\]]/g, '');
    
    exec(sanitizedCommand, {
      timeout: 30000, // 30 second timeout
      maxBuffer: 1024 * 1024, // 1MB buffer
      ...options
    }, (error, stdout, stderr) => {
      if (error) {
        console.error(`Command failed: ${error.message}`);
        reject(error);
      } else {
        resolve({ stdout, stderr });
      }
    });
  });
};

// Routes with authentication and validation

app.post("/api/fetch-url", authenticateToken, strictLimiter, async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!validateUrl(url)) {
      return res.status(400).json({ error: "Invalid or insecure URL" });
    }

    console.log(`🌐 Fetching file from URL: ${url} (User: ${req.user.uid})`);

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; Certificate-Fetcher/1.0)',
      },
      timeout: 30000,
      size: 10 * 1024 * 1024, // 10MB limit
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const contentType = response.headers.get('content-type') || '';
    const contentLength = response.headers.get('content-length');
    
    // Strict content type checking
    const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg'];
    if (!allowedTypes.some(type => contentType.includes(type))) {
      return res.status(400).json({ 
        error: "URL must point to a PDF or image file (JPEG, PNG)",
        contentType: contentType
      });
    }

    if (contentLength && parseInt(contentLength) > 10 * 1024 * 1024) {
      return res.status(400).json({ error: "File too large (max 10MB)" });
    }

    const buffer = await response.buffer();
    
    // Use dynamic import for file-type
    const { fileTypeFromBuffer } = await import('file-type');
    const detectedType = await fileTypeFromBuffer(buffer);
    if (!detectedType || !['pdf', 'jpg', 'png', 'jpeg'].includes(detectedType.ext)) {
      return res.status(400).json({ error: "Invalid file type detected" });
    }

    const urlPath = new URL(url).pathname;
    const fileName = path.basename(urlPath) || `file_${Date.now()}`;
    const sanitizedFileName = sanitizeInput(fileName);
    const finalFileName = `${crypto.randomBytes(8).toString('hex')}_${sanitizedFileName}`;

    console.log(`✅ Successfully fetched file: ${finalFileName} (${buffer.length} bytes)`);

    res.json({
      success: true,
      fileName: finalFileName,
      contentType: contentType,
      size: buffer.length,
      data: buffer.toString('base64')
    });

  } catch (error) {
    console.error(`❌ Error fetching URL: ${error.message}`);
    res.status(500).json({ 
      error: "Failed to fetch file from URL",
      details: error.message
    });
  }
});

app.post("/compile", authenticateToken, upload.single("tex"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No .tex file uploaded" });
    }

    const uploadsDir = path.join(__dirname, "uploads");
    const outputDir = path.join(__dirname, "compiled");
    
    // Ensure directories exist
    [uploadsDir, outputDir].forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
      }
    });

    // Generate secure IDs
    const fileId = req.body.id ? sanitizeInput(req.body.id) : crypto.randomBytes(16).toString('hex');
    const secureId = `${req.user.uid}_${fileId}_${Date.now()}`;
    
    const tempPath = req.file.path;
    const texFile = path.join(uploadsDir, `${secureId}.tex`);
    const pdfPath = path.join(outputDir, `${secureId}.pdf`);
    const logPath = path.join(outputDir, `${secureId}.log`);
    const auxPath = path.join(outputDir, `${secureId}.aux`);

    // Validate file content
    const fileContent = fs.readFileSync(tempPath, 'utf8');
    
    // Basic LaTeX content validation
    if (fileContent.length > 1024 * 1024) { // 1MB limit for LaTeX content
      cleanupFiles([tempPath]);
      return res.status(400).json({ error: "LaTeX file too large" });
    }

    // Move file securely
    fs.renameSync(tempPath, texFile);

    // Determine LaTeX engine
    const modernCVVariants = [
      '\\documentclass[11pt, a4paper,sans]{moderncv}',
      '\\documentclass[11pt,a4paper,sans]{moderncv}',
      '\\documentclass[11pt, a4paper]{moderncv}',
      '\\documentclass{moderncv}'
    ];
    
    const usesModernCV = modernCVVariants.some(variant => 
      fileContent.includes(variant)
    );
    
    const engine = usesModernCV ? 'xelatex' : 'pdflatex';
    const command = `${engine} -interaction=nonstopmode -output-directory=${outputDir} ${texFile}`;
    
    console.log(`🔄 Compiling LaTeX (User: ${req.user.uid}): ${command}`);

    // Execute compilation with security measures
    const result = await executeCommand(command);
    
    console.log("LaTeX STDOUT:\n", result.stdout);
    if (result.stderr) console.error("LaTeX STDERR:\n", result.stderr);

    // Wait for PDF creation
    await waitForFile(pdfPath, 10000);
    
    const stats = fs.statSync(pdfPath);
    if (stats.size === 0) {
      throw new Error("Generated PDF is empty");
    }

    console.log(`✅ PDF compiled successfully: ${pdfPath} (${stats.size} bytes)`);
    
    // Schedule cleanup of auxiliary files
    setTimeout(() => {
      cleanupFiles([texFile, logPath, auxPath]);
    }, 2000);
    
    res.json({ 
      success: true, 
      id: secureId,
      message: "PDF compiled successfully",
      size: stats.size
    });

  } catch (error) {
    console.error("❌ Compilation error:", error);
    
    // Cleanup on error
    if (req.file) {
      const tempPath = req.file.path;
      cleanupFiles([tempPath]);
    }
    
    res.status(500).json({ 
      error: "LaTeX compilation failed",
      details: error.message
    });
  }
});

app.get("/download/:id", authenticateToken, (req, res) => {
  try {
    const requestedId = sanitizeInput(req.params.id);
    
    // Verify the user owns this file (ID should start with their UID)
    if (!requestedId.startsWith(req.user.uid)) {
      return res.status(403).json({ error: "Access denied" });
    }
    
    const pdfPath = path.join(__dirname, "compiled", `${requestedId}.pdf`);
    
    console.log(`📁 Download requested for: ${pdfPath} (User: ${req.user.uid})`);
    
    if (!fs.existsSync(pdfPath)) {
      return res.status(404).json({ error: "PDF file not found" });
    }

    // Verify file size and type
    const stats = fs.statSync(pdfPath);
    if (stats.size === 0) {
      return res.status(404).json({ error: "PDF file is empty" });
    }

    console.log(`📤 Serving PDF: ${pdfPath}`);
    
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="resume_${Date.now()}.pdf"`);
    res.setHeader("Content-Length", stats.size);
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    
    const fileStream = fs.createReadStream(pdfPath);
    fileStream.pipe(res);
    
    fileStream.on('end', () => {
      console.log("✅ PDF sent successfully. Scheduling cleanup...");
      setTimeout(() => {
        cleanupFiles([pdfPath]);
      }, 5000);
    });
    
    fileStream.on('error', (error) => {
      console.error("❌ Error streaming PDF:", error);
      if (!res.headersSent) {
        res.status(500).json({ error: "Failed to send PDF" });
      }
    });

  } catch (error) {
    console.error("❌ Download error:", error);
    res.status(500).json({ error: "Failed to process download request" });
  }
});

// Secure API keys (should be in environment variables)
const YOUTUBE_API_KEYS = process.env.YOUTUBE_API_KEYS?.split(',') || [];
const GOOGLE_CSE_KEYS = process.env.GOOGLE_CSE_KEYS?.split(',') || [];
const GOOGLE_CSE_CX_IDS = process.env.GOOGLE_CSE_CX_IDS?.split(',') || [];

app.get('/api/youtube/search', authenticateToken, async (req, res) => {
  try {
    const query = sanitizeInput(req.query.query);
    
    if (!query || query.length < 2) {
      return res.status(400).json({ error: "Search query is required" });
    }

    let lastError = null;
    const totalKeys = YOUTUBE_API_KEYS.length;
    let attempts = 0;

    if (totalKeys === 0) {
      return res.status(503).json({ error: "YouTube search service unavailable" });
    }

    while (attempts < totalKeys) {
      const API_KEY = YOUTUBE_API_KEYS[youtubeKeyIndex];
      try {
        const url = `https://www.googleapis.com/youtube/v3/search?` +
          `part=snippet&maxResults=3&q=${encodeURIComponent(query)}&` +
          `type=video&order=relevance&key=${API_KEY}`;

        const response = await fetch(url, { timeout: 10000 });
        if (!response.ok) throw new Error(`YouTube API error: ${response.status}`);

        const data = await response.json();
        const videos = data.items?.map(item => ({
          title: sanitizeInput(item.snippet.title),
          url: `https://www.youtube.com/watch?v=${item.id.videoId}`,
          type: 'video',
          source: 'YouTube',
          description: sanitizeInput(item.snippet.description?.substring(0, 100) + '...' || '')
        })) || [];

        youtubeKeyIndex = (youtubeKeyIndex + 1) % totalKeys;

        return res.json({ success: true, data: videos });
      } catch (error) {
        console.error(`Failed with YouTube key ${youtubeKeyIndex + 1}:`, error.message);
        lastError = error;
        youtubeKeyIndex = (youtubeKeyIndex + 1) % totalKeys;
        attempts++;
      }
    }

    res.status(500).json({
      success: false,
      error: "YouTube search service temporarily unavailable"
    });
  } catch (error) {
    console.error("YouTube search error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get('/api/google/search', authenticateToken, async (req, res) => {
  try {
    const query = sanitizeInput(req.query.query);
    
    if (!query || query.length < 2) {
      return res.status(400).json({ error: "Search query is required" });
    }

    let lastError = null;
    const keyCount = GOOGLE_CSE_KEYS.length;
    const cxCount = GOOGLE_CSE_CX_IDS.length;
    let attempts = 0;
    const maxAttempts = keyCount * cxCount;

    if (keyCount === 0 || cxCount === 0) {
      return res.status(503).json({ error: "Google search service unavailable" });
    }

    while (attempts < maxAttempts) {
      const API_KEY = GOOGLE_CSE_KEYS[googleCSEKeyIndex];
      const CX = GOOGLE_CSE_CX_IDS[googleCSECXIndex];

      try {
        const url = `https://www.googleapis.com/customsearch/v1?q=${encodeURIComponent(query)}&key=${API_KEY}&cx=${CX}&num=3`;
        const response = await fetch(url, { timeout: 10000 });

        if (!response.ok) throw new Error(`Google CSE error: ${response.status}`);

        const data = await response.json();
        const results = data.items?.map(item => ({
          title: sanitizeInput(item.title),
          url: item.link,
          type: 'documentation',
          source: new URL(item.link).hostname,
          description: sanitizeInput(item.snippet?.substring(0, 100) + '...' || '')
        })) || [];

        googleCSEKeyIndex = (googleCSEKeyIndex + 1) % keyCount;
        googleCSECXIndex = (googleCSECXIndex + 1) % cxCount;

        return res.json({ success: true, data: results });
      } catch (error) {
        console.error(`Failed with Key ${googleCSEKeyIndex + 1} and CX ${googleCSECXIndex + 1}:`, error.message);
        lastError = error;
        googleCSEKeyIndex = (googleCSEKeyIndex + 1) % keyCount;
        googleCSECXIndex = (googleCSECXIndex + 1) % cxCount;
        attempts++;
      }
    }

    res.status(500).json({
      success: false,
      error: "Google search service temporarily unavailable"
    });
  } catch (error) {
    console.error("Google search error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  
  if (error.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: 'File too large' });
  }
  
  if (error.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json({ error: 'Unexpected file field' });
  }
  
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Received SIGTERM, shutting down gracefully...');
  // Clean up any remaining files
  const uploadsDir = path.join(__dirname, 'uploads');
  const compiledDir = path.join(__dirname, 'compiled');
  
  [uploadsDir, compiledDir].forEach(dir => {
    if (fs.existsSync(dir)) {
      const files = fs.readdirSync(dir);
      files.forEach(file => {
        const filePath = path.join(dir, file);
        try {
          fs.unlinkSync(filePath);
        } catch (error) {
          console.error(`Error cleaning up ${filePath}:`, error);
        }
      });
    }
  });
  
  process.exit(0);
});

const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || 'localhost';

app.listen(PORT, HOST, () => {
  console.log("🚀 Secure PDF Compiler server running at http://" + HOST + ":" + PORT);
  console.log("🔒 Security features enabled");
  console.log("📁 Uploads directory: uploads/");
  console.log("📁 Output directory: compiled/");
  console.log("🔥 Firebase Auth enabled");
});