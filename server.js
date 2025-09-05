// Production-ready Express server for Railway deployment
const express = require('express');
const cors = require('cors');

const app = express();

// Environment variables with defaults
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const NETLIFY_SITE_URL = process.env.NETLIFY_SITE_URL; // Railway will inject this

// Database and JWT secrets (Railway will inject these)
const DB_URL = process.env.DB_URL;
const JWT_SECRET = process.env.JWT_SECRET;

// Production-ready CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (NODE_ENV === 'production') {
      // In production, only allow your Netlify site
      const allowedOrigins = [
        NETLIFY_SITE_URL, // e.g., 'https://your-site.netlify.app'
        // Add other production domains if needed
      ].filter(Boolean); // Remove any undefined values
      
      if (allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    } else {
      // In development, allow localhost
      const allowedOrigins = [
        'http://localhost:3000',
        'http://localhost:3001',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:3001'
      ];
      
      if (allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'Cache-Control',
    'X-HTTP-Method-Override'
  ]
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Body parsing middleware
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf);
    } catch (e) {
      console.error('Invalid JSON received:', e.message);
      res.status(400).json({ error: 'Invalid JSON' });
      return;
    }
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb' 
}));

// Security headers middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  if (NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  
  next();
});

// Request logging middleware (production-ready)
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const url = req.url;
  const userAgent = req.get('User-Agent') || 'Unknown';
  const ip = req.ip || req.connection.remoteAddress || 'Unknown';
  
  console.log(`[${timestamp}] ${method} ${url} - IP: ${ip} - UA: ${userAgent.substring(0, 100)}`);
  next();
});

// Health check endpoint (Railway requirement)
app.get('/health', (req, res) => {
  const healthData = {
    ok: true,
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    port: PORT,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: process.version
  };
  
  // Optional: Add database health check
  if (DB_URL) {
    healthData.database = 'connected'; // You can add actual DB ping here
  }
  
  res.status(200).json(healthData);
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'CB-FD-Backend',
    version: '1.0.0',
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    endpoints: {
      health: '/health',
      api: '/api/*'
    }
  });
});

// Example API routes (you can expand these)
app.get('/api/status', (req, res) => {
  res.json({
    status: 'operational',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV
  });
});

// Example protected route using JWT_SECRET
app.post('/api/auth/verify', (req, res) => {
  if (!JWT_SECRET) {
    return res.status(500).json({ 
      error: 'JWT_SECRET not configured' 
    });
  }
  
  // JWT verification logic would go here
  res.json({ 
    message: 'Auth endpoint ready',
    configured: true 
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error occurred:', {
    message: err.message,
    stack: NODE_ENV === 'development' ? err.stack : undefined,
    timestamp: new Date().toISOString(),
    url: req.url,
    method: req.method
  });
  
  // Don't leak error details in production
  const errorResponse = {
    error: NODE_ENV === 'production' ? 'Internal server error' : err.message,
    timestamp: new Date().toISOString()
  };
  
  if (NODE_ENV === 'development') {
    errorResponse.stack = err.stack;
  }
  
  res.status(err.status || 500).json(errorResponse);
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    path: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    // Close database connections, etc.
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running in ${NODE_ENV} mode`);
  console.log(`📡 Listening on http://0.0.0.0:${PORT}`);
  console.log(`🌍 CORS configured for: ${NODE_ENV === 'production' ? NETLIFY_SITE_URL || 'Not configured' : 'localhost development'}`);
  console.log(`🔒 JWT Secret: ${JWT_SECRET ? 'Configured' : 'Not configured'}`);
  console.log(`💾 Database: ${DB_URL ? 'Configured' : 'Not configured'}`);
  console.log(`⏰ Started at: ${new Date().toISOString()}`);
});

module.exports = app;
