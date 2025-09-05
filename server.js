// Production-ready Express server for Railway deployment
require('dotenv').config(); // Load environment variables

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const multer = require('multer');

const app = express();
const upload = multer();

// Environment variables with defaults
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const NETLIFY_SITE_URL = process.env.NETLIFY_SITE_URL || 'https://starlit-croissant-5176b3.netlify.app';

// API Configuration
const REKA_API_KEY = process.env.REKA_API_KEY;
const REKA_API_URL = process.env.REKA_API_URL || 'https://api.reka.ai/v1/chat/completions';
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_API_URL = process.env.OPENROUTER_API_URL || 'https://openrouter.ai/api/v1/chat/completions';
const SCANII_API_KEY = process.env.SCANII_API_KEY;
const SCANII_API_SECRET = process.env.SCANII_API_SECRET || '';
const SCANII_API_URL = process.env.SCANII_API_URL || 'https://api-us1.scanii.com/v2.2/files';

// Security secrets
const JWT_SECRET = process.env.JWT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;

// In-memory history (replace with DB for production)
let history = [];

// Production-ready CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (NODE_ENV === 'production') {
      // In production, only allow your Netlify site
      const allowedOrigins = [
        NETLIFY_SITE_URL,
        'https://starlit-croissant-5176b3.netlify.app' // Fallback
      ].filter(Boolean);
      
      if (allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        console.log('CORS blocked origin:', origin);
        callback(new Error('Not allowed by CORS'));
      }
    } else {
      // In development, allow localhost
      const allowedOrigins = [
        'http://localhost:3000',
        'http://localhost:3001',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:3001',
        NETLIFY_SITE_URL
      ].filter(Boolean);
      
      if (allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        console.log('CORS allowed development origin:', origin);
        callback(null, true); // Allow all in development
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

// --- File Analysis Endpoint (using Reka Flash 3 & Scanii) ---
app.post('/analyze/file', upload.single('file'), async (req, res) => {
  console.log('Received file analysis request:', req.file && req.file.originalname);
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });
    
    let risk = 'low';
    let confidence = 0.85;
    let result = {};
    
    // Check if file is text-based for Reka Flash 3 analysis
    const textBasedTypes = ['text/plain', 'text/csv', 'application/json', 'text/html', 'text/xml', 'application/pdf'];
    const isTextBased = textBasedTypes.includes(file.mimetype) || file.originalname.match(/\.(txt|csv|json|html|xml|log|pdf)$/i);
    
    if (isTextBased && REKA_API_KEY) {
      try {
        console.log('Using Reka Flash 3 for text-based file analysis...');
        const fileContent = file.buffer.toString('utf8');
        
        const rekaResponse = await axios.post(REKA_API_URL, {
          model: 'reka-flash-3',
          messages: [{
            role: 'user',
            content: `Analyze the following file content for spam, scam, phishing, fraud, malware, or security risks. 

Instructions:
- Rate the risk level as exactly 'low', 'medium', or 'high'
- Provide a confidence score between 0.1 and 1.0
- Look for suspicious patterns, URLs, email addresses, financial scams, phishing attempts
- Consider bulk document analysis for CSVs and logs
- Be thorough but concise

File name: ${file.originalname}
File type: ${file.mimetype}
File size: ${file.size} bytes

Content to analyze:
${fileContent.substring(0, 30000)}`
          }],
          max_tokens: 800,
          temperature: 0.1
        }, {
          headers: {
            'Authorization': `Bearer ${REKA_API_KEY}`,
            'Content-Type': 'application/json'
          },
          timeout: 20000
        });
        
        const analysis = rekaResponse.data.choices[0].message.content;
        console.log('Reka Flash 3 analysis completed');
        
        // Parse response
        const lowerAnalysis = analysis.toLowerCase();
        if (lowerAnalysis.includes('high risk') || lowerAnalysis.includes('dangerous')) {
          risk = 'high';
          confidence = 0.90;
        } else if (lowerAnalysis.includes('medium risk') || lowerAnalysis.includes('suspicious')) {
          risk = 'medium';
          confidence = 0.80;
        } else {
          risk = 'low';
          confidence = 0.85;
        }
        
        result = {
          analysis: 'reka-flash-3',
          ai_analysis: analysis,
          reason: 'AI-powered analysis using Reka Flash 3',
          details: {
            file_type: file.mimetype,
            file_name: file.originalname,
            file_size: file.size
          }
        };
      } catch (rekaError) {
        console.log('Reka Flash 3 API failed:', rekaError.message);
        risk = 'medium';
        confidence = 0.70;
        result = {
          analysis: 'fallback',
          reason: 'AI analysis unavailable - basic heuristic used',
          error: rekaError.message
        };
      }
    } else {
      // For binary files or when Reka is not available, use Scanii
      if (SCANII_API_KEY) {
        try {
          console.log('Using Scanii for file scanning...');
          const response = await axios.post(SCANII_API_URL, file.buffer, {
            auth: { username: SCANII_API_KEY, password: SCANII_API_SECRET },
            headers: { 'Content-Type': file.mimetype },
            params: { filename: file.originalname },
            timeout: 15000
          });
          
          result = response.data;
          risk = result.findings && result.findings.length > 0 ? 'high' : 'low';
          confidence = 0.90;
        } catch (scaniiError) {
          console.log('Scanii API failed:', scaniiError.message);
          risk = 'medium';
          confidence = 0.60;
          result = {
            analysis: 'basic-fallback',
            reason: 'File scanning services unavailable',
            file_type: file.mimetype,
            file_size: file.size
          };
        }
      } else {
        risk = 'medium';
        confidence = 0.60;
        result = {
          analysis: 'no-api',
          reason: 'No file scanning API configured',
          file_type: file.mimetype,
          file_size: file.size
        };
      }
    }
    
    const historyEntry = {
      id: Date.now(),
      type: 'file',
      filename: file.originalname,
      size: file.size,
      mimetype: file.mimetype,
      risk,
      confidence,
      result,
      timestamp: new Date().toISOString()
    };
    
    history.unshift(historyEntry);
    if (history.length > 100) history = history.slice(0, 100);
    
    res.json({ risk, confidence, result, historyId: historyEntry.id });
    
  } catch (error) {
    console.error('File analysis error:', error);
    res.status(500).json({
      error: 'Analysis failed',
      details: error.message,
      risk: 'unknown',
      confidence: 0.0
    });
  }
});

// --- Text Analysis Endpoint (using OpenRouter DeepSeek) ---
app.post('/analyze/text', async (req, res) => {
  console.log('Received text analysis request');
  try {
    const { text } = req.body;
    if (!text || text.trim().length === 0) {
      return res.status(400).json({ error: 'No text provided' });
    }
    
    let risk = 'low';
    let confidence = 0.85;
    let result = {};
    
    if (OPENROUTER_API_KEY) {
      try {
        console.log('Calling OpenRouter DeepSeek API...');
        const response = await axios.post(OPENROUTER_API_URL, {
          model: 'deepseek/deepseek-chat',
          messages: [{
            role: 'user',
            content: `Classify this text as Spam, Scam, or Safe. Return a likelihood score from 0-100.

Text to analyze: "${text}"

Please provide your response in this exact format:
Classification: [Spam/Scam/Safe]
Score: [0-100]
Reasoning: [Brief explanation]`
          }],
          max_tokens: 300,
          temperature: 0.1
        }, {
          headers: {
            'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
            'Content-Type': 'application/json'
          },
          timeout: 15000
        });
        
        const analysis = response.data.choices[0].message.content;
        console.log('OpenRouter DeepSeek analysis completed');
        
        // Parse response
        let classification = 'Safe';
        let score = 0;
        
        const classificationMatch = analysis.match(/classification:\s*(spam|scam|safe)/i);
        const scoreMatch = analysis.match(/score:\s*(\d+)/i);
        
        if (classificationMatch) classification = classificationMatch[1];
        if (scoreMatch) score = parseInt(scoreMatch[1]);
        
        // Determine risk
        const lowerClassification = classification.toLowerCase();
        if (lowerClassification === 'scam' || score >= 71) {
          risk = 'high';
          confidence = 0.90;
        } else if (lowerClassification === 'spam' || score >= 31) {
          risk = 'medium';
          confidence = 0.80;
        } else {
          risk = 'low';
          confidence = 0.85;
        }
        
        result = {
          analysis: 'openrouter-deepseek',
          classification: classification,
          score: score,
          ai_analysis: analysis,
          reason: 'AI-powered analysis using OpenRouter DeepSeek'
        };
        
      } catch (apiError) {
        console.error('OpenRouter API error:', apiError.message);
        risk = 'medium';
        confidence = 0.70;
        result = {
          analysis: 'fallback',
          reason: 'AI analysis unavailable',
          error: apiError.message
        };
      }
    } else {
      risk = 'medium';
      confidence = 0.60;
      result = {
        analysis: 'no-api',
        reason: 'No text analysis API configured'
      };
    }
    
    const historyEntry = {
      id: Date.now(),
      type: 'text',
      text: text.substring(0, 500),
      risk,
      confidence,
      result,
      timestamp: new Date().toISOString()
    };
    
    history.unshift(historyEntry);
    if (history.length > 100) history = history.slice(0, 100);
    
    res.json({ risk, confidence, result, historyId: historyEntry.id });
    
  } catch (error) {
    console.error('Text analysis error:', error);
    res.status(500).json({
      error: 'Analysis failed',
      details: error.message,
      risk: 'unknown',
      confidence: 0.0
    });
  }
});

// --- URL Analysis Endpoint (basic heuristic) ---
app.post('/analyze/url', async (req, res) => {
  console.log('Received URL analysis request');
  try {
    const { url } = req.body;
    if (!url || !url.trim()) {
      return res.status(400).json({ error: 'No URL provided' });
    }
    
    // Basic heuristic analysis
    const urlLower = url.toLowerCase();
    const suspiciousPatterns = ['bit.ly', 'tinyurl', '.tk', '.ml', 'suspicious', 'phishing'];
    const suspiciousCount = suspiciousPatterns.filter(pattern => urlLower.includes(pattern)).length;
    
    let risk = 'low';
    let confidence = 0.75;
    
    if (suspiciousCount >= 2) {
      risk = 'high';
      confidence = 0.85;
    } else if (suspiciousCount >= 1) {
      risk = 'medium';
      confidence = 0.80;
    }
    
    const result = {
      analysis: 'heuristic',
      suspicious_patterns: suspiciousCount,
      reason: `URL analysis based on pattern matching`,
      url: url
    };
    
    const historyEntry = {
      id: Date.now(),
      type: 'url',
      url,
      risk,
      confidence,
      result,
      timestamp: new Date().toISOString()
    };
    
    history.unshift(historyEntry);
    if (history.length > 100) history = history.slice(0, 100);
    
    res.json({ risk, confidence, result, historyId: historyEntry.id });
    
  } catch (error) {
    console.error('URL analysis error:', error);
    res.status(500).json({
      error: 'Analysis failed',
      details: error.message,
      risk: 'unknown',
      confidence: 0.0
    });
  }
});

// --- History Endpoints ---
app.get('/history', (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  res.json(history.slice(0, limit));
});

app.delete('/history', (req, res) => {
  history.length = 0;
  res.json({ message: 'History cleared successfully', timestamp: new Date().toISOString() });
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
  console.log(`🚀 CB-FD-Backend running in ${NODE_ENV} mode`);
  console.log(`📡 Listening on http://0.0.0.0:${PORT}`);
  console.log(`🌍 CORS configured for: ${NETLIFY_SITE_URL}`);
  console.log(`🔒 JWT Secret: ${JWT_SECRET ? 'Configured' : 'Not configured'}`);
  console.log(`🤖 Reka Flash 3: ${REKA_API_KEY ? 'Configured' : 'Not configured'}`);
  console.log(`🤖 OpenRouter DeepSeek: ${OPENROUTER_API_KEY ? 'Configured' : 'Not configured'}`);
  console.log(`�️  Scanii Scanner: ${SCANII_API_KEY ? 'Configured' : 'Not configured'}`);
  console.log(`⏰ Started at: ${new Date().toISOString()}`);
  console.log(`🔗 API Endpoints: /analyze/file, /analyze/text, /analyze/url, /history`);
});

module.exports = app;
