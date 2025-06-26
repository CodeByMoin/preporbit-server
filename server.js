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
const nodemailer = require('nodemailer');
const cron = require('node-cron');
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

// app.use(limiter);
// Apply general rate limiting AFTER CORS and preflight handling
app.use((req, res, next) => {
  // Skip rate limiting for preflight requests
  if (req.method === 'OPTIONS') {
    return next();
  }
  limiter(req, res, next);
});

// Data sanitization
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// Compression
app.use(compression());

// Logging
app.use(morgan("combined"));

// // CORS with strict configuration
// const allowedOrigins = process.env.ALLOWED_ORIGINS
//   ? process.env.ALLOWED_ORIGINS.split(',')
//   : ['http://localhost:5173'];

// app.use(cors({
//   origin: function (origin, callback) {
//     if (!origin || allowedOrigins.includes(origin)) {
//       callback(null, true);
//     } else {
//       callback(new Error('CORS not allowed for this origin'));
//     }
//   },
//   credentials: true,
//   methods: ['GET', 'POST'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
//   optionsSuccessStatus: 200
// }));

// const preflightLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 200,
//   message: "Too many preflight requests, try again later"
// });

// app.options('*', preflightLimiter, cors());
// Improved CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : ['http://localhost:5173'];

// Add debugging to see what's happening
const corsOptions = {
  origin: function (origin, callback) {
    console.log('CORS check - Origin:', origin);
    console.log('CORS check - Allowed origins:', allowedOrigins);
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) {
      console.log('CORS: No origin header, allowing request');
      return callback(null, true);
    }
    
    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
      console.log('CORS: Origin allowed');
      return callback(null, true);
    }
    
    // For development, be more lenient with localhost
    if (process.env.NODE_ENV !== 'production') {
      const isLocalhost = origin.includes('localhost') || origin.includes('127.0.0.1');
      if (isLocalhost) {
        console.log('CORS: Development mode - allowing localhost');
        return callback(null, true);
      }
    }
    
    console.log('CORS: Origin not allowed:', origin);
    callback(new Error('CORS not allowed for this origin'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200,
  preflightContinue: false // Important: handle preflight here
};

// Apply CORS before rate limiting to handle preflight requests properly
app.use(cors(corsOptions));

// Separate preflight handler with its own rate limiting
const preflightLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: "Too many preflight requests, try again later",
  skip: (req) => req.method !== 'OPTIONS' // Only apply to OPTIONS requests
});

// Handle preflight requests explicitly BEFORE general rate limiting
app.options('*', preflightLimiter, (req, res) => {
  console.log('Preflight request received for:', req.path);
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.status(200).end();
});


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
        reject({ error, stdout, stderr });
      } else {
        resolve({ stdout, stderr });
      }
    });
  });
};

// Email configuration (add to your existing code after Firebase setup)
const emailTransporter = nodemailer.createTransport({
  service: 'gmail', // or your preferred email service
  auth: {
    user: process.env.EMAIL_USER, // your email
    pass: process.env.EMAIL_APP_PASSWORD // app-specific password
  },
  pool: true,
  maxConnections: 5,
  maxMessages: 100
});

// Verify email configuration
emailTransporter.verify((error, success) => {
  if (error) {
    console.error('❌ Email configuration error:', error);
  } else {
    console.log('✅ Email server is ready');
  }
});

// Function to check if date is today
const isToday = (dateString) => {
  if (!dateString) return false;
  
  const today = new Date();
  const checkDate = new Date(dateString);
  
  return today.getFullYear() === checkDate.getFullYear() &&
         today.getMonth() === checkDate.getMonth() &&
         today.getDate() === checkDate.getDate();
};

// Email template for coding reminder
const generateReminderEmailHTML = (userName) => {
  const motivationalMessages = [
    "Every expert was once a beginner. Every pro was once an amateur.",
    "The only way to learn programming is by writing programs.",
    "Code is like humor. When you have to explain it, it's bad.",
    "Programming isn't about what you know; it's about what you can figure out.",
    "The best time to plant a tree was 20 years ago. The second best time is now."
  ];
  
  const tips = [
    "Start with just 15 minutes of coding today",
    "Try solving one easy problem to build momentum",
    "Review a concept you learned yesterday",
    "Practice debugging a small piece of code",
    "Write a simple function or algorithm"
  ];
  
  const randomMessage = motivationalMessages[Math.floor(Math.random() * motivationalMessages.length)];
  const randomTip = tips[Math.floor(Math.random() * tips.length)];
  
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Daily Coding Reminder</title>
      <style>
        body { 
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
          line-height: 1.6; 
          margin: 0; 
          padding: 0; 
          background-color: #f5f5f5; 
        }
        .container { 
          max-width: 600px; 
          margin: 20px auto; 
          background: white; 
          border-radius: 12px; 
          overflow: hidden; 
          box-shadow: 0 4px 20px rgba(0,0,0,0.1); 
        }
        .header { 
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
          color: white; 
          padding: 30px 20px; 
          text-align: center; 
        }
        .header h1 { 
          margin: 0; 
          font-size: 24px; 
          font-weight: 600; 
        }
        .header p { 
          margin: 10px 0 0 0; 
          opacity: 0.9; 
          font-size: 16px; 
        }
        .content { 
          padding: 30px 25px; 
        }
        .greeting { 
          font-size: 18px; 
          color: #333; 
          margin-bottom: 20px; 
        }
        .reminder-box { 
          background: #f8f9fa; 
          border-left: 4px solid #667eea; 
          padding: 20px; 
          margin: 20px 0; 
          border-radius: 0 8px 8px 0; 
        }
        .reminder-text { 
          font-size: 16px; 
          color: #495057; 
          margin-bottom: 15px; 
        }
        .motivation-quote { 
          background: linear-gradient(135deg, #667eea15 0%, #764ba215 100%); 
          border-radius: 8px; 
          padding: 20px; 
          margin: 20px 0; 
          text-align: center; 
          font-style: italic; 
          color: #555; 
          font-size: 16px; 
        }
        .tip-box { 
          background: #e8f5e8; 
          border: 1px solid #c3e6c3; 
          border-radius: 8px; 
          padding: 15px; 
          margin: 20px 0; 
        }
        .tip-title { 
          font-weight: 600; 
          color: #2d5a2d; 
          margin-bottom: 8px; 
          font-size: 14px; 
        }
        .tip-text { 
          color: #4a6741; 
          font-size: 14px; 
        }
        .cta-button { 
          display: inline-block; 
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
          color: white; 
          padding: 15px 30px; 
          text-decoration: none; 
          border-radius: 25px; 
          font-weight: 600; 
          margin: 20px 0; 
          text-align: center; 
          font-size: 16px;
        }
        .stats-reminder { 
          background: #fff3cd; 
          border: 1px solid #ffeaa7; 
          border-radius: 8px; 
          padding: 15px; 
          margin: 20px 0; 
          text-align: center; 
        }
        .footer { 
          background: #f8f9fa; 
          color: #6c757d; 
          padding: 20px; 
          text-align: center; 
          font-size: 12px; 
          border-top: 1px solid #dee2e6; 
        }
        .emoji { 
          font-size: 24px; 
          margin-bottom: 10px; 
        }
        @media (max-width: 600px) { 
          .container { margin: 10px; }
          .content { padding: 20px 15px; }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div class="emoji">👨‍💻</div>
          <h1>Daily Coding Reminder</h1>
          <p>Keep your coding momentum going!</p>
        </div>
        
        <div class="content">
          <div class="greeting">
            Hello ${userName || 'Coder'}! 👋
          </div>
          
          <div class="reminder-box">
            <div class="reminder-text">
              We noticed you haven't practiced coding today. Every day of practice counts towards becoming a better developer! 
            </div>
            <div class="reminder-text">
              Even 15-20 minutes of coding can make a significant difference in maintaining your skills and building momentum.
            </div>
          </div>
          
          <div class="motivation-quote">
            "${randomMessage}"
          </div>
          
          <div class="tip-box">
            <div class="tip-title">💡 Quick Tip for Today:</div>
            <div class="tip-text">${randomTip}</div>
          </div>
          
          <div class="stats-reminder">
            <strong>🎯 Remember:</strong> Consistency is key! Small daily efforts lead to big results.
          </div>
          
          <div style="text-align: center; margin-top: 30px;">
            <p><strong>🚀 Ready to code?</strong></p>
            <p>Start with something simple and build from there. You've got this!</p>
          </div>
        </div>
        
        <div class="footer">
          <p>Happy Coding! 🎯</p>
          <p>This is an automated reminder. You can disable these notifications in your profile settings.</p>
        </div>
      </div>
    </body>
    </html>
  `;
};

// Function to send reminder email to individual user
const sendReminderEmail = async (userEmail, userName) => {
  try {
    const mailOptions = {
      from: {
        name: 'Coding Practice Reminder',
        address: process.env.EMAIL_USER
      },
      to: userEmail,
      subject: `⏰ Don't forget to practice coding today, ${userName}!`,
      html: generateReminderEmailHTML(userName),
      text: `Hi ${userName}!\n\nThis is a friendly reminder to practice coding today. Even 15-20 minutes can make a difference!\n\nConsistency is key to improving your programming skills. Keep up the great work!\n\nHappy Coding!`
    };

    const info = await emailTransporter.sendMail(mailOptions);
    console.log(`✅ Reminder email sent to ${userEmail} (${userName}):`, info.messageId);
    return true;
  } catch (error) {
    console.error(`❌ Failed to send reminder email to ${userEmail}:`, error);
    return false;
  }
};

// Main function to check database and send reminders
const checkAndSendReminders = async () => {
  try {
    console.log('🔍 Checking database for users who need coding reminders...');
    
    // Get all users from Firestore
    const usersSnapshot = await admin.firestore().collection('users').get();
    
    if (usersSnapshot.empty) {
      console.log('📭 No users found in database');
      return;
    }

    let remindersSent = 0;
    let usersChecked = 0;
    let usersSkipped = 0;

    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD format
    
    for (const userDoc of usersSnapshot.docs) {
      const userData = userDoc.data();
      const userId = userDoc.id;
      
      usersChecked++;
      
      // Check if user has email notifications enabled
      const emailNotificationsEnabled = userData.settings?.notifications?.email;
      if (!emailNotificationsEnabled) {
        console.log(`⏭️ Skipping user ${userData.name || userId} - email notifications disabled`);
        usersSkipped++;
        continue;
      }

      // Check if user has valid email
      if (!userData.email || !validator.isEmail(userData.email)) {
        console.log(`⏭️ Skipping user ${userData.name || userId} - invalid email`);
        usersSkipped++;
        continue;
      }

      // Check if user has practiced today
      const lastSolvedDate = userData.lastSolvedDate;
      const hasNotPracticedToday = !isToday(lastSolvedDate);
      
      if (hasNotPracticedToday) {
        console.log(`📧 Sending reminder to: ${userData.name || userData.email} (Last solved: ${lastSolvedDate || 'Never'})`);
        
        const emailSent = await sendReminderEmail(
          userData.email, 
          userData.name || userData.fullname || 'Coder'
        );
        
        if (emailSent) {
          remindersSent++;
          
          // Update user's last reminder sent date (optional)
          try {
            await admin.firestore().collection('users').doc(userId).update({
              lastReminderSent: admin.firestore.FieldValue.serverTimestamp()
            });
          } catch (updateError) {
            console.warn(`⚠️ Could not update reminder timestamp for ${userId}:`, updateError.message);
          }
        }
        
        // Add delay between emails to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 2000));
      } else {
        console.log(`✅ User ${userData.name || userData.email} has already practiced today`);
      }
    }

    console.log(`📊 Reminder check completed:`);
    console.log(`   - Users checked: ${usersChecked}`);
    console.log(`   - Reminders sent: ${remindersSent}`);
    console.log(`   - Users skipped: ${usersSkipped}`);
    
  } catch (error) {
    console.error('❌ Error checking database for reminders:', error);
  }
};

// Schedule reminder checks at multiple times during the day
// Morning reminder: 10:00 AM
cron.schedule('0 10 * * *', () => {
  console.log('🌅 Running morning coding reminder check...');
  checkAndSendReminders();
}, {
  scheduled: true,
  timezone: "Asia/Kolkata"
});

// Afternoon reminder: 2:00 PM
cron.schedule('0 14 * * *', () => {
  console.log('🌞 Running afternoon coding reminder check...');
  checkAndSendReminders();
}, {
  scheduled: true,
  timezone: "Asia/Kolkata"
});

// Evening reminder: 6:00 PM
cron.schedule('0 18 * * *', () => {
  console.log('🌆 Running evening coding reminder check...');
  checkAndSendReminders();
}, {
  scheduled: true,
  timezone: "Asia/Kolkata"
});

// API endpoint to manually trigger reminder check (for testing)
app.post('/api/reminders/check', authenticateToken, async (req, res) => {
  try {
    console.log(`🔧 Manual reminder check triggered by user: ${req.user.uid}`);
    await checkAndSendReminders();
    
    res.json({
      success: true,
      message: 'Reminder check completed successfully'
    });
    
  } catch (error) {
    console.error('Manual reminder check error:', error);
    res.status(500).json({ 
      error: 'Failed to check reminders',
      details: error.message 
    });
  }
});

// API endpoint to test email for current user
app.post('/api/reminders/test', authenticateToken, async (req, res) => {
  try {
    // Get current user data from database
    const userDoc = await admin.firestore().collection('users').doc(req.user.uid).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found in database' });
    }
    
    const userData = userDoc.data();
    
    if (!userData.email) {
      return res.status(400).json({ error: 'No email found for user' });
    }
    
    const emailSent = await sendReminderEmail(
      userData.email, 
      userData.name || userData.fullname || 'Coder'
    );
    
    if (emailSent) {
      res.json({
        success: true,
        message: 'Test reminder email sent successfully!',
        email: userData.email
      });
    } else {
      res.status(500).json({ error: 'Failed to send test email' });
    }
    
  } catch (error) {
    console.error('Test reminder email error:', error);
    res.status(500).json({ 
      error: 'Failed to send test email',
      details: error.message 
    });
  }
});

// API endpoint to get reminder statistics
app.get('/api/reminders/stats', authenticateToken, async (req, res) => {
  try {
    const usersSnapshot = await admin.firestore().collection('users').get();
    
    let totalUsers = 0;
    let usersWithEmailEnabled = 0;
    let usersPracticedToday = 0;
    let usersNeedingReminder = 0;
    
    for (const userDoc of usersSnapshot.docs) {
      const userData = userDoc.data();
      totalUsers++;
      
      if (userData.settings?.notifications?.email) {
        usersWithEmailEnabled++;
        
        if (isToday(userData.lastSolvedDate)) {
          usersPracticedToday++;
        } else {
          usersNeedingReminder++;
        }
      }
    }
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        usersWithEmailEnabled,
        usersPracticedToday,
        usersNeedingReminder,
        lastChecked: new Date().toISOString()
      }
    });
    
  } catch (error) {
    console.error('Reminder stats error:', error);
    res.status(500).json({ 
      error: 'Failed to get reminder statistics',
      details: error.message 
    });
  }
});

console.log('📧 Coding reminder system initialized');
console.log('⏰ Reminders scheduled for: 10:00 AM, 2:00 PM, and 6:00 PM IST');
console.log('🔍 System will check database for users who haven\'t practiced coding today');

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

app.post("/compile",
  authenticateToken,
  upload.single("tex"),
  async (req, res) => {
    // base paths
    const uploadsDir = path.join(__dirname, "uploads");
    const outputDir  = path.join(__dirname, "compiled");

    // unique filename pieces
    const fileId   = req.body.id
      ? sanitizeInput(req.body.id)
      : crypto.randomBytes(16).toString("hex");
    const secureId = `${req.user.uid}_${fileId}_${Date.now()}`;

    // full paths
    const tempPath = req.file?.path;
    const texFile  = path.join(uploadsDir,  `${secureId}.tex`);
    const pdfPath  = path.join(outputDir, `${secureId}.pdf`);
    const logPath  = path.join(outputDir, `${secureId}.log`);
    const auxPath  = path.join(outputDir, `${secureId}.aux`);

    try {
      if (!req.file) {
        return res
          .status(400)
          .json({ error: "No .tex file uploaded" });
      }

      // ensure dirs
      [uploadsDir, outputDir].forEach(d => {
        if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
      });

      // move uploaded file into place
      fs.renameSync(tempPath, texFile);

      // pick engine
      const usesModernCV = fs
        .readFileSync(texFile, "utf8")
        .includes("\\documentclass{moderncv}");
      const engine  = usesModernCV ? "xelatex" : "pdflatex";
      const command = `${engine} -interaction=nonstopmode -output-directory=${outputDir} ${texFile}`;

      console.log("→ Compiling:", command);
      await executeCommand(command);

      // wait for pdf
      await waitForFile(pdfPath, 10000);

      // check size
      const stats = fs.statSync(pdfPath);
      if (stats.size === 0) {
        throw new Error("Empty PDF");
      }

      // send it back
      res.setHeader("Content-Type", "application/pdf");
      res.sendFile(pdfPath, err => {
        if (err) console.error("SendFile error:", err);
        // cleanup .tex/.aux/.log after we stream it
        setTimeout(() => {
          [texFile, auxPath, logPath, pdfPath].forEach(p => {
            if (fs.existsSync(p)) fs.unlinkSync(p);
          });
        }, 2000);
      });

    } catch (err) {
      console.error("⚠️ Compilation error:", err);

      // if a PDF got produced anyway, send it
      if (fs.existsSync(pdfPath)) {
        console.log("⚠️ Returning partial PDF anyway");
        res.setHeader("Content-Type", "application/pdf");
        return res.sendFile(pdfPath);
      }

      // otherwise return JSON error
      let details = err.message;
      if (fs.existsSync(logPath)) {
        details += "\n\n" +
          fs.readFileSync(logPath, "utf8")
            .split("\n")
            .slice(-20) // last 20 lines
            .join("\n");
      }

      return res
        .status(500)
        .json({ error: "LaTeX compilation failed", details });
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
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log("🚀 Secure PDF Compiler server running at http://" + HOST + ":" + PORT);
  console.log("🔒 Security features enabled");
  console.log("📁 Uploads directory: uploads/");
  console.log("📁 Output directory: compiled/");
  console.log("🔥 Firebase Auth enabled");
});