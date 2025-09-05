// Entry point for Express backend
console.log('Starting CB-FD-Backend server...');

const express = require('express');
console.log('Express loaded successfully');

const cors = require('cors');
console.log('CORS loaded successfully');

const app = express();
console.log('Express app created');

const PORT = process.env.PORT || 5000;
console.log('Port configured:', PORT);

// Production-ready CORS configuration
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? [
        'https://your-netlify-site.netlify.app',
        'https://your-custom-domain.com'
      ] 
    : [
        'http://localhost:3000',
        'http://localhost:3001'
      ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' })); // Increased limit for larger texts
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error handler caught:', err);
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON in request body' });
  }
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

const axios = require('axios');
const multer = require('multer');
const upload = multer();

// In-memory history (replace with DB for production)
let history = [];

// Basic test endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'CB-Project backend running',
    timestamp: new Date().toISOString(),
    endpoints: ['/health', '/test']
  });
});

// Test endpoint to verify JSON parsing
app.post('/test', (req, res) => {
  console.log('Test endpoint - body:', req.body);
  res.json({ 
    received: req.body,
    message: 'JSON parsing working correctly'
  });
});

app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
  console.log('Server is ready to accept connections!');
});
