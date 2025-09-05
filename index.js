<<<<<<< HEAD
// Entry point for Express backend
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 5000;

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

// --- File Analysis (Reka Flash 3 Primary) ---
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
    
    if (isTextBased) {
      try {
        // Primary: Reka Flash 3 API for text-based file analysis
        console.log('Using Reka Flash 3 for text-based file analysis...');
        const rekaApiKey = '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';
        const rekaUrl = 'https://api.reka.ai/v1/chat/completions';
        
        // Extract text content from file
        const fileContent = file.buffer.toString('utf8');
        
        const rekaResponse = await axios.post(rekaUrl, {
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
${fileContent.substring(0, 30000)}` // Limit to 30K chars for efficiency
          }],
          max_tokens: 800,
          temperature: 0.1
        }, {
          headers: {
            'Authorization': `Bearer ${rekaApiKey}`,
            'Content-Type': 'application/json'
          },
          timeout: 20000 // 20 second timeout for large files
        });
        
        const analysis = rekaResponse.data.choices[0].message.content;
        console.log('Reka Flash 3 analysis completed:', analysis.substring(0, 200));
        
        // Parse Reka response to extract risk level and confidence
        let detectedRisk = 'low';
        let detectedConfidence = 0.75;
        
        // Enhanced parsing for better accuracy
        const lowerAnalysis = analysis.toLowerCase();
        if (lowerAnalysis.includes('high risk') || lowerAnalysis.includes('dangerous') || 
            lowerAnalysis.includes('malicious') || lowerAnalysis.includes('threat') ||
            lowerAnalysis.includes('malware') || lowerAnalysis.includes('phishing')) {
          detectedRisk = 'high';
          detectedConfidence = 0.90;
        } else if (lowerAnalysis.includes('medium risk') || lowerAnalysis.includes('suspicious') || 
                   lowerAnalysis.includes('caution') || lowerAnalysis.includes('warning') ||
                   lowerAnalysis.includes('potential risk')) {
          detectedRisk = 'medium';
          detectedConfidence = 0.80;
        } else if (lowerAnalysis.includes('low risk') || lowerAnalysis.includes('safe') ||
                   lowerAnalysis.includes('clean') || lowerAnalysis.includes('legitimate')) {
          detectedRisk = 'low';
          detectedConfidence = 0.85;
        }
        
        // Extract confidence score if mentioned in analysis
        const confidenceMatch = analysis.match(/confidence[:\s]+([0-9.]+)/i);
        if (confidenceMatch && parseFloat(confidenceMatch[1]) > 0) {
          detectedConfidence = Math.min(parseFloat(confidenceMatch[1]), 1.0);
        }
        
        risk = detectedRisk;
        confidence = detectedConfidence;
        result = {
          analysis: 'reka-flash-3',
          ai_analysis: analysis,
          reason: `AI-powered analysis using Reka Flash 3`,
          fileType: file.mimetype,
          size: file.size,
          processed_content_length: Math.min(fileContent.length, 30000)
        };
        
        console.log('Reka analysis result:', { risk, confidence, fileType: file.mimetype });
      } catch (rekaErr) {
        console.log('Reka Flash 3 API error, trying Scanii fallback:', rekaErr.message);
        
        // Fallback to Scanii for any files if Reka fails
        try {
          const scaniiKey = 'f6a27196b75409fd7358e154da9a6a8a';
          const scaniiSecret = ''; // Note: Empty secret for demo
          const scaniiUrl = 'https://api-us1.scanii.com/v2.2/files';
          
          if (scaniiSecret) {
            const response = await axios.post(scaniiUrl, file.buffer, {
              auth: { username: scaniiKey, password: scaniiSecret },
              headers: { 'Content-Type': file.mimetype },
              params: { filename: file.originalname },
            });
            result = response.data;
            risk = result.findings && result.findings.length > 0 ? 'high' : 'low';
            confidence = result.findings && result.findings.length > 0 ? 0.95 : 0.90;
          } else {
            throw new Error('Scanii API not configured - using basic fallback');
          }
        } catch (scaniiErr) {
          console.log('Scanii API also failed, using basic fallback analysis:', scaniiErr.message);
          
          // Final Fallback: Basic file analysis based on file properties
          const suspiciousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.jar'];
          const riskExtensions = ['.zip', '.rar', '.7z', '.gz', '.tar'];
          const fileExt = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
          
          if (suspiciousExtensions.includes(fileExt)) {
            risk = 'high';
            confidence = 0.85;
            result = {
              analysis: 'fallback',
              reason: `Potentially dangerous file type: ${fileExt}`,
              fileType: fileExt,
              size: file.size
            };
          } else if (riskExtensions.includes(fileExt)) {
            risk = 'medium';
            confidence = 0.70;
            result = {
              analysis: 'fallback',
              reason: `Archive file requiring caution: ${fileExt}`,
              fileType: fileExt,
              size: file.size
            };
          } else {
            risk = 'low';
            confidence = 0.80;
            result = {
              analysis: 'fallback',
              reason: 'File appears safe based on basic analysis',
              fileType: fileExt,
              size: file.size
            };
          }
        }
      }
    } else {
      // For binary files, try Scanii first, then basic fallback
      try {
        const scaniiKey = 'f6a27196b75409fd7358e154da9a6a8a';
        const scaniiSecret = ''; // Note: Empty secret for demo
        const scaniiUrl = 'https://api-us1.scanii.com/v2.2/files';
        
        if (scaniiSecret) {
          const response = await axios.post(scaniiUrl, file.buffer, {
            auth: { username: scaniiKey, password: scaniiSecret },
            headers: { 'Content-Type': file.mimetype },
            params: { filename: file.originalname },
          });
          result = response.data;
          risk = result.findings && result.findings.length > 0 ? 'high' : 'low';
          confidence = result.findings && result.findings.length > 0 ? 0.95 : 0.90;
        } else {
          throw new Error('Scanii API not configured - using basic fallback');
        }
      } catch (scaniiErr) {
        console.log('Scanii API failed for binary file, using basic fallback:', scaniiErr.message);
        
        // Basic fallback for binary files
        const suspiciousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.jar'];
        const riskExtensions = ['.zip', '.rar', '.7z', '.gz', '.tar'];
        const fileExt = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
        
        if (suspiciousExtensions.includes(fileExt)) {
          risk = 'high';
          confidence = 0.85;
          result = {
            analysis: 'fallback',
            reason: `Potentially dangerous file type: ${fileExt}`,
            fileType: fileExt,
            size: file.size
          };
        } else if (riskExtensions.includes(fileExt)) {
          risk = 'medium';
          confidence = 0.70;
          result = {
            analysis: 'fallback',
            reason: `Archive file requiring caution: ${fileExt}`,
            fileType: fileExt,
            size: file.size
          };
        } else {
          risk = 'low';
          confidence = 0.80;
          result = {
            analysis: 'fallback',
            reason: 'File appears safe based on basic analysis',
            fileType: fileExt,
            size: file.size
          };
        }
      }
    }
    
    const entry = { type: 'file', input: file.originalname, risk, confidence, result, date: new Date() };
    history.push(entry);
    console.log('File analysis result:', { risk, confidence, fileType: result.fileType });
    res.json({ risk, confidence, result });
  } catch (err) {
    console.error('File analysis error:', err);
    res.status(500).json({ error: 'File analysis failed', details: err.message });
  }
});

// --- Text Analysis (Tencent Hunyuan A13B) ---
app.post('/analyze/text', async (req, res) => {
  console.log('=== TEXT ANALYSIS REQUEST ===');
  console.log('Request headers:', req.headers);
  console.log('Request body:', req.body);
  console.log('Body type:', typeof req.body);
  console.log('Text value:', req.body?.text);
  
  try {
    // Validate request body exists
    if (!req.body) {
      console.error('ERROR: No request body found');
      return res.status(400).json({ 
        error: 'No request body provided',
        details: 'Request must include JSON body with text field'
      });
    }

    const { text } = req.body;
    
    // Validate text input
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      console.error('ERROR: Invalid text input:', { text, type: typeof text });
      return res.status(400).json({ 
        error: 'No valid text provided',
        details: 'Text field must be a non-empty string'
      });
    }
    
    console.log(`Processing text analysis for: "${text.substring(0, 50)}..."`);
    
    let risk = 'none', confidence = 0.99, result = { safe: true };
    
    try {
      // Primary: OpenRouter DeepSeek API
      console.log('Calling OpenRouter DeepSeek API...');
      const openrouterApiKey = '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';
      const openrouterUrl = 'https://openrouter.ai/api/v1/chat/completions';
      
      const response = await axios.post(openrouterUrl, {
        model: 'deepseek/deepseek-chat', // Using DeepSeek model
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
          'Authorization': `Bearer ${openrouterApiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: 15000 // 15 second timeout
      });
      
      console.log('OpenRouter DeepSeek API response:', response.data);
      const analysis = response.data.choices[0].message.content;
      console.log('AI Analysis text:', analysis);
      
      // Parse the AI response to extract classification and score
      let detectedRisk = 'none';
      let detectedConfidence = 0.90;
      let classification = 'Safe';
      let score = 0;
      
      // Enhanced parsing for structured response
      const classificationMatch = analysis.match(/classification:\s*(spam|scam|safe)/i);
      const scoreMatch = analysis.match(/score:\s*(\d+)/i) || analysis.match(/(\d+)(?:\s*\/\s*100|\s*%)/i);
      
      if (scoreMatch) {
        score = parseInt(scoreMatch[1]);
        console.log('Extracted score:', score);
      }
      
      if (classificationMatch) {
        classification = classificationMatch[1];
        console.log('Extracted classification:', classification);
      }
      
      // Determine risk level based on classification and score
      const lowerClassification = classification.toLowerCase();
      const lowerAnalysis = analysis.toLowerCase();
      
      if (lowerClassification === 'scam' || lowerAnalysis.includes('scam') || lowerAnalysis.includes('fraud') || score >= 71) {
        detectedRisk = 'high';
        classification = 'Scam';
        detectedConfidence = Math.max(0.85, Math.min(0.99, score / 100));
      } else if (lowerClassification === 'spam' || lowerAnalysis.includes('spam') || (score >= 31 && score <= 70)) {
        detectedRisk = 'low';
        classification = 'Spam';
        detectedConfidence = Math.max(0.70, Math.min(0.95, score / 100));
      } else if (lowerClassification === 'safe' || lowerAnalysis.includes('safe') || score <= 30) {
        detectedRisk = 'none';
        classification = 'Safe';
        detectedConfidence = Math.max(0.85, Math.min(0.99, 1 - (score / 100)));
      }
      
      risk = detectedRisk;
      confidence = detectedConfidence;
      result = {
        analysis: 'tencent-hunyuan-a13b',
        classification: classification,
        score: score,
        ai_analysis: analysis,
        reason: `AI-powered analysis using Tencent Hunyuan A13B`,
        likelihood_percentage: score
      };
      
      console.log('Tencent analysis result:', { risk, confidence, classification, score });
      
    } catch (apiErr) {
      console.error('Tencent Hunyuan API error:', apiErr.message);
      console.error('API Error details:', {
        message: apiErr.message,
        status: apiErr.response?.status,
        statusText: apiErr.response?.statusText,
        data: apiErr.response?.data
      });
      
      // Return error instead of fallback
      return res.status(503).json({
        error: 'Text analysis API unavailable',
        details: 'Tencent Hunyuan A13B API is currently unavailable. Please try again later.',
        apiError: apiErr.message,
        timestamp: new Date().toISOString()
      });
    }
    
    const entry = { type: 'text', input: text, risk, confidence, result, date: new Date() };
    history.push(entry);
    
    console.log('Final analysis result:', { risk, confidence, resultType: typeof result });
    console.log('=== TEXT ANALYSIS COMPLETE ===');
    
    res.json({ risk, confidence, result });
    
  } catch (err) {
    console.error('=== TEXT ANALYSIS FATAL ERROR ===');
    console.error('Error name:', err.name);
    console.error('Error message:', err.message);
    console.error('Error stack:', err.stack);
    console.error('Request details:', {
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: req.body
    });
    
    res.status(500).json({ 
      error: 'Text analysis failed', 
      details: err.message,
      timestamp: new Date().toISOString()
    });
  }
});// --- URL Analysis (Cloudmersive Virus Scan) ---
app.post('/analyze/url', async (req, res) => {
  console.log('Received URL analysis request:', req.body && req.body.url);
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'No URL provided' });
    
    let risk = 'none', confidence = 0.99, result = { safe: true };
    
    try {
      // Primary: Cloudmersive Virus Scan API
      console.log('Using Cloudmersive Virus Scan for URL analysis...');
      const cloudmersiveApiKey = '3a443ce0-8532-430f-b376-9a394d1615f4';
      const cloudmersiveUrl = 'https://api.cloudmersive.com/virus/scan/website';
      
      const response = await axios.post(cloudmersiveUrl, {
        Url: url
      }, {
        headers: {
          'Apikey': cloudmersiveApiKey,
          'Content-Type': 'application/json'
        },
        timeout: 15000 // 15 second timeout
      });
      
      result = response.data;
      console.log('Cloudmersive response:', result);
      
      // Parse Cloudmersive response
      if (result.CleanResult === false || result.FoundViruses?.length > 0) {
        risk = 'high';
        confidence = 0.95;
        result.analysis = 'cloudmersive-virus-scan';
        result.threat_detected = true;
        if (result.FoundViruses?.length > 0) {
          result.viruses = result.FoundViruses;
          result.reason = `Malware detected: ${result.FoundViruses.map(v => v.VirusName || v.FileName).join(', ')}`;
        } else {
          result.reason = 'Suspicious content or threat indicators found';
        }
      } else if (result.CleanResult === true) {
        risk = 'low';
        confidence = 0.90;
        result.analysis = 'cloudmersive-virus-scan';
        result.threat_detected = false;
        result.reason = 'URL appears safe - no malware or threats detected';
      } else {
        // Inconclusive result
        risk = 'medium';
        confidence = 0.70;
        result.analysis = 'cloudmersive-virus-scan';
        result.threat_detected = false;
        result.reason = 'Analysis inconclusive - proceed with caution';
      }
      
    } catch (apiErr) {
      console.log('Cloudmersive API error, using fallback analysis:', apiErr.message);
      
      // Fallback: Enhanced pattern-based risk assessment
      const suspiciousPatterns = [
        // URL shorteners (potential for hiding malicious links)
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link',
        // Malware-related keywords
        'malware', 'phishing', 'scam', 'hack', 'virus', 'trojan', 'ransomware',
        // Suspicious terms
        'free-money', 'click-here', 'suspicious', 'malicious', 'download-now',
        'urgent-action', 'verify-account', 'security-alert', 'limited-time',
        // Suspicious TLDs
        '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download'
      ];
      
      const suspiciousDomains = [
        'tempmail', 'guerrillamail', 'mailinator', '10minutemail',
        'discord.gg', 'telegram.me', 'drive.google.com/uc'
      ];
      
      const urlLower = url.toLowerCase();
      let suspiciousScore = 0;
      let detectedPatterns = [];
      
      // Check for suspicious patterns
      suspiciousPatterns.forEach(pattern => {
        if (urlLower.includes(pattern)) {
          suspiciousScore += 2;
          detectedPatterns.push(pattern);
        }
      });
      
      // Check for suspicious domains
      suspiciousDomains.forEach(domain => {
        if (urlLower.includes(domain)) {
          suspiciousScore += 3;
          detectedPatterns.push(domain);
        }
      });
      
      // Check for IP addresses instead of domains
      const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
      if (ipPattern.test(url)) {
        suspiciousScore += 4;
        detectedPatterns.push('direct-ip-access');
      }
      
      // Check for excessive redirects or suspicious structure
      const suspiciousStructure = url.split('/').length > 6 || url.includes('..') || url.includes('%');
      if (suspiciousStructure) {
        suspiciousScore += 2;
        detectedPatterns.push('suspicious-structure');
      }
      
      // Determine risk based on score
      if (suspiciousScore >= 5) {
        risk = 'high';
        confidence = 0.85;
        result = { 
          fallback: true, 
          analysis: 'pattern-based-fallback',
          reason: `High risk patterns detected: ${detectedPatterns.join(', ')}`,
          suspiciousScore,
          detectedPatterns
        };
      } else if (suspiciousScore >= 2) {
        risk = 'medium';
        confidence = 0.75;
        result = { 
          fallback: true, 
          analysis: 'pattern-based-fallback',
          reason: `Moderate risk patterns detected: ${detectedPatterns.join(', ')}`,
          suspiciousScore,
          detectedPatterns
        };
      } else {
        risk = 'low';
        confidence = 0.70;
        result = { 
          fallback: true, 
          analysis: 'pattern-based-fallback',
          reason: 'No suspicious patterns detected in URL structure',
          suspiciousScore: 0
        };
      }
    }
    
    const entry = { type: 'url', input: url, risk, confidence, result, date: new Date() };
    history.push(entry);
    console.log('URL analysis result:', { risk, confidence, analysis: result.analysis });
    res.json({ risk, confidence, result });
  } catch (err) {
    console.error('URL analysis error:', err);
    res.status(500).json({ error: 'URL analysis failed', details: err.message });
  }
});// --- History Endpoint ---
app.get('/history', (req, res) => {
  console.log('History requested');
  res.json(history.slice(-100).reverse()); // last 100 entries
});

// --- Delete History Endpoint ---
app.delete('/history', (req, res) => {
  console.log('History deletion requested');
  history.length = 0; // Clear the history array
  res.json({ message: 'History cleared successfully', timestamp: new Date().toISOString() });
});

// --- Analytics Endpoint ---
app.get('/analytics', (req, res) => {
  console.log('Analytics requested');
  const summary = { high: 0, low: 0, none: 0 };
  history.forEach(h => { summary[h.risk] = (summary[h.risk] || 0) + 1; });
  const total = history.length || 1;
  res.json({
    high: { count: summary.high, percent: (summary.high / total * 100).toFixed(1) },
    low: { count: summary.low, percent: (summary.low / total * 100).toFixed(1) },
    none: { count: summary.none, percent: (summary.none / total * 100).toFixed(1) },
    total,
  });
});

app.get('/', (req, res) => {
  res.json({ 
    message: 'CB-Project backend running',
    timestamp: new Date().toISOString(),
    endpoints: ['/analyze/text', '/analyze/url', '/analyze/file', '/history', '/analytics']
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
});
=======
// Entry point for Express backend
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '10mb' })); // Increased limit for larger texts
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

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

// --- File Analysis (Reka Flash 3 Primary) ---
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
    
    if (isTextBased) {
      try {
        // Primary: Reka Flash 3 API for text-based file analysis
        console.log('Using Reka Flash 3 for text-based file analysis...');
        const rekaApiKey = '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';
        const rekaUrl = 'https://api.reka.ai/v1/chat/completions';
        
        // Extract text content from file
        const fileContent = file.buffer.toString('utf8');
        
        const rekaResponse = await axios.post(rekaUrl, {
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
${fileContent.substring(0, 30000)}` // Limit to 30K chars for efficiency
          }],
          max_tokens: 800,
          temperature: 0.1
        }, {
          headers: {
            'Authorization': `Bearer ${rekaApiKey}`,
            'Content-Type': 'application/json'
          },
          timeout: 20000 // 20 second timeout for large files
        });
        
        const analysis = rekaResponse.data.choices[0].message.content;
        console.log('Reka Flash 3 analysis completed:', analysis.substring(0, 200));
        
        // Parse Reka response to extract risk level and confidence
        let detectedRisk = 'low';
        let detectedConfidence = 0.75;
        
        // Enhanced parsing for better accuracy
        const lowerAnalysis = analysis.toLowerCase();
        if (lowerAnalysis.includes('high risk') || lowerAnalysis.includes('dangerous') || 
            lowerAnalysis.includes('malicious') || lowerAnalysis.includes('threat') ||
            lowerAnalysis.includes('malware') || lowerAnalysis.includes('phishing')) {
          detectedRisk = 'high';
          detectedConfidence = 0.90;
        } else if (lowerAnalysis.includes('medium risk') || lowerAnalysis.includes('suspicious') || 
                   lowerAnalysis.includes('caution') || lowerAnalysis.includes('warning') ||
                   lowerAnalysis.includes('potential risk')) {
          detectedRisk = 'medium';
          detectedConfidence = 0.80;
        } else if (lowerAnalysis.includes('low risk') || lowerAnalysis.includes('safe') ||
                   lowerAnalysis.includes('clean') || lowerAnalysis.includes('legitimate')) {
          detectedRisk = 'low';
          detectedConfidence = 0.85;
        }
        
        // Extract confidence score if mentioned in analysis
        const confidenceMatch = analysis.match(/confidence[:\s]+([0-9.]+)/i);
        if (confidenceMatch && parseFloat(confidenceMatch[1]) > 0) {
          detectedConfidence = Math.min(parseFloat(confidenceMatch[1]), 1.0);
        }
        
        risk = detectedRisk;
        confidence = detectedConfidence;
        result = {
          analysis: 'reka-flash-3',
          ai_analysis: analysis,
          reason: `AI-powered analysis using Reka Flash 3`,
          fileType: file.mimetype,
          size: file.size,
          processed_content_length: Math.min(fileContent.length, 30000)
        };
        
        console.log('Reka analysis result:', { risk, confidence, fileType: file.mimetype });
      } catch (rekaErr) {
        console.log('Reka Flash 3 API error, trying Scanii fallback:', rekaErr.message);
        
        // Fallback to Scanii for any files if Reka fails
        try {
          const scaniiKey = 'f6a27196b75409fd7358e154da9a6a8a';
          const scaniiSecret = ''; // Note: Empty secret for demo
          const scaniiUrl = 'https://api-us1.scanii.com/v2.2/files';
          
          if (scaniiSecret) {
            const response = await axios.post(scaniiUrl, file.buffer, {
              auth: { username: scaniiKey, password: scaniiSecret },
              headers: { 'Content-Type': file.mimetype },
              params: { filename: file.originalname },
            });
            result = response.data;
            risk = result.findings && result.findings.length > 0 ? 'high' : 'low';
            confidence = result.findings && result.findings.length > 0 ? 0.95 : 0.90;
          } else {
            throw new Error('Scanii API not configured - using basic fallback');
          }
        } catch (scaniiErr) {
          console.log('Scanii API also failed, using basic fallback analysis:', scaniiErr.message);
          
          // Final Fallback: Basic file analysis based on file properties
          const suspiciousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.jar'];
          const riskExtensions = ['.zip', '.rar', '.7z', '.gz', '.tar'];
          const fileExt = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
          
          if (suspiciousExtensions.includes(fileExt)) {
            risk = 'high';
            confidence = 0.85;
            result = {
              analysis: 'fallback',
              reason: `Potentially dangerous file type: ${fileExt}`,
              fileType: fileExt,
              size: file.size
            };
          } else if (riskExtensions.includes(fileExt)) {
            risk = 'medium';
            confidence = 0.70;
            result = {
              analysis: 'fallback',
              reason: `Archive file requiring caution: ${fileExt}`,
              fileType: fileExt,
              size: file.size
            };
          } else {
            risk = 'low';
            confidence = 0.80;
            result = {
              analysis: 'fallback',
              reason: 'File appears safe based on basic analysis',
              fileType: fileExt,
              size: file.size
            };
          }
        }
      }
    } else {
      // For binary files, try Scanii first, then basic fallback
      try {
        const scaniiKey = 'f6a27196b75409fd7358e154da9a6a8a';
        const scaniiSecret = ''; // Note: Empty secret for demo
        const scaniiUrl = 'https://api-us1.scanii.com/v2.2/files';
        
        if (scaniiSecret) {
          const response = await axios.post(scaniiUrl, file.buffer, {
            auth: { username: scaniiKey, password: scaniiSecret },
            headers: { 'Content-Type': file.mimetype },
            params: { filename: file.originalname },
          });
          result = response.data;
          risk = result.findings && result.findings.length > 0 ? 'high' : 'low';
          confidence = result.findings && result.findings.length > 0 ? 0.95 : 0.90;
        } else {
          throw new Error('Scanii API not configured - using basic fallback');
        }
      } catch (scaniiErr) {
        console.log('Scanii API failed for binary file, using basic fallback:', scaniiErr.message);
        
        // Basic fallback for binary files
        const suspiciousExtensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.jar'];
        const riskExtensions = ['.zip', '.rar', '.7z', '.gz', '.tar'];
        const fileExt = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
        
        if (suspiciousExtensions.includes(fileExt)) {
          risk = 'high';
          confidence = 0.85;
          result = {
            analysis: 'fallback',
            reason: `Potentially dangerous file type: ${fileExt}`,
            fileType: fileExt,
            size: file.size
          };
        } else if (riskExtensions.includes(fileExt)) {
          risk = 'medium';
          confidence = 0.70;
          result = {
            analysis: 'fallback',
            reason: `Archive file requiring caution: ${fileExt}`,
            fileType: fileExt,
            size: file.size
          };
        } else {
          risk = 'low';
          confidence = 0.80;
          result = {
            analysis: 'fallback',
            reason: 'File appears safe based on basic analysis',
            fileType: fileExt,
            size: file.size
          };
        }
      }
    }
    
    const entry = { type: 'file', input: file.originalname, risk, confidence, result, date: new Date() };
    history.push(entry);
    console.log('File analysis result:', { risk, confidence, fileType: result.fileType });
    res.json({ risk, confidence, result });
  } catch (err) {
    console.error('File analysis error:', err);
    res.status(500).json({ error: 'File analysis failed', details: err.message });
  }
});

// --- Text Analysis (Tencent Hunyuan A13B) ---
app.post('/analyze/text', async (req, res) => {
  console.log('=== TEXT ANALYSIS REQUEST ===');
  console.log('Request headers:', req.headers);
  console.log('Request body:', req.body);
  console.log('Body type:', typeof req.body);
  console.log('Text value:', req.body?.text);
  
  try {
    // Validate request body exists
    if (!req.body) {
      console.error('ERROR: No request body found');
      return res.status(400).json({ 
        error: 'No request body provided',
        details: 'Request must include JSON body with text field'
      });
    }

    const { text } = req.body;
    
    // Validate text input
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      console.error('ERROR: Invalid text input:', { text, type: typeof text });
      return res.status(400).json({ 
        error: 'No valid text provided',
        details: 'Text field must be a non-empty string'
      });
    }
    
    console.log(`Processing text analysis for: "${text.substring(0, 50)}..."`);
    
    let risk = 'none', confidence = 0.99, result = { safe: true };
    
    try {
      // Primary: OpenRouter DeepSeek API
      console.log('Calling OpenRouter DeepSeek API...');
      const openrouterApiKey = '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';
      const openrouterUrl = 'https://openrouter.ai/api/v1/chat/completions';
      
      const response = await axios.post(openrouterUrl, {
        model: 'deepseek/deepseek-chat', // Using DeepSeek model
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
          'Authorization': `Bearer ${openrouterApiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: 15000 // 15 second timeout
      });
      
      console.log('OpenRouter DeepSeek API response:', response.data);
      const analysis = response.data.choices[0].message.content;
      console.log('AI Analysis text:', analysis);
      
      // Parse the AI response to extract classification and score
      let detectedRisk = 'none';
      let detectedConfidence = 0.90;
      let classification = 'Safe';
      let score = 0;
      
      // Enhanced parsing for structured response
      const classificationMatch = analysis.match(/classification:\s*(spam|scam|safe)/i);
      const scoreMatch = analysis.match(/score:\s*(\d+)/i) || analysis.match(/(\d+)(?:\s*\/\s*100|\s*%)/i);
      
      if (scoreMatch) {
        score = parseInt(scoreMatch[1]);
        console.log('Extracted score:', score);
      }
      
      if (classificationMatch) {
        classification = classificationMatch[1];
        console.log('Extracted classification:', classification);
      }
      
      // Determine risk level based on classification and score
      const lowerClassification = classification.toLowerCase();
      const lowerAnalysis = analysis.toLowerCase();
      
      if (lowerClassification === 'scam' || lowerAnalysis.includes('scam') || lowerAnalysis.includes('fraud') || score >= 71) {
        detectedRisk = 'high';
        classification = 'Scam';
        detectedConfidence = Math.max(0.85, Math.min(0.99, score / 100));
      } else if (lowerClassification === 'spam' || lowerAnalysis.includes('spam') || (score >= 31 && score <= 70)) {
        detectedRisk = 'low';
        classification = 'Spam';
        detectedConfidence = Math.max(0.70, Math.min(0.95, score / 100));
      } else if (lowerClassification === 'safe' || lowerAnalysis.includes('safe') || score <= 30) {
        detectedRisk = 'none';
        classification = 'Safe';
        detectedConfidence = Math.max(0.85, Math.min(0.99, 1 - (score / 100)));
      }
      
      risk = detectedRisk;
      confidence = detectedConfidence;
      result = {
        analysis: 'tencent-hunyuan-a13b',
        classification: classification,
        score: score,
        ai_analysis: analysis,
        reason: `AI-powered analysis using Tencent Hunyuan A13B`,
        likelihood_percentage: score
      };
      
      console.log('Tencent analysis result:', { risk, confidence, classification, score });
      
    } catch (apiErr) {
      console.error('Tencent Hunyuan API error:', apiErr.message);
      console.error('API Error details:', {
        message: apiErr.message,
        status: apiErr.response?.status,
        statusText: apiErr.response?.statusText,
        data: apiErr.response?.data
      });
      
      // Return error instead of fallback
      return res.status(503).json({
        error: 'Text analysis API unavailable',
        details: 'Tencent Hunyuan A13B API is currently unavailable. Please try again later.',
        apiError: apiErr.message,
        timestamp: new Date().toISOString()
      });
    }
    
    const entry = { type: 'text', input: text, risk, confidence, result, date: new Date() };
    history.push(entry);
    
    console.log('Final analysis result:', { risk, confidence, resultType: typeof result });
    console.log('=== TEXT ANALYSIS COMPLETE ===');
    
    res.json({ risk, confidence, result });
    
  } catch (err) {
    console.error('=== TEXT ANALYSIS FATAL ERROR ===');
    console.error('Error name:', err.name);
    console.error('Error message:', err.message);
    console.error('Error stack:', err.stack);
    console.error('Request details:', {
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: req.body
    });
    
    res.status(500).json({ 
      error: 'Text analysis failed', 
      details: err.message,
      timestamp: new Date().toISOString()
    });
  }
});// --- URL Analysis (Cloudmersive Virus Scan) ---
app.post('/analyze/url', async (req, res) => {
  console.log('Received URL analysis request:', req.body && req.body.url);
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'No URL provided' });
    
    let risk = 'none', confidence = 0.99, result = { safe: true };
    
    try {
      // Primary: Cloudmersive Virus Scan API
      console.log('Using Cloudmersive Virus Scan for URL analysis...');
      const cloudmersiveApiKey = '3a443ce0-8532-430f-b376-9a394d1615f4';
      const cloudmersiveUrl = 'https://api.cloudmersive.com/virus/scan/website';
      
      const response = await axios.post(cloudmersiveUrl, {
        Url: url
      }, {
        headers: {
          'Apikey': cloudmersiveApiKey,
          'Content-Type': 'application/json'
        },
        timeout: 15000 // 15 second timeout
      });
      
      result = response.data;
      console.log('Cloudmersive response:', result);
      
      // Parse Cloudmersive response
      if (result.CleanResult === false || result.FoundViruses?.length > 0) {
        risk = 'high';
        confidence = 0.95;
        result.analysis = 'cloudmersive-virus-scan';
        result.threat_detected = true;
        if (result.FoundViruses?.length > 0) {
          result.viruses = result.FoundViruses;
          result.reason = `Malware detected: ${result.FoundViruses.map(v => v.VirusName || v.FileName).join(', ')}`;
        } else {
          result.reason = 'Suspicious content or threat indicators found';
        }
      } else if (result.CleanResult === true) {
        risk = 'low';
        confidence = 0.90;
        result.analysis = 'cloudmersive-virus-scan';
        result.threat_detected = false;
        result.reason = 'URL appears safe - no malware or threats detected';
      } else {
        // Inconclusive result
        risk = 'medium';
        confidence = 0.70;
        result.analysis = 'cloudmersive-virus-scan';
        result.threat_detected = false;
        result.reason = 'Analysis inconclusive - proceed with caution';
      }
      
    } catch (apiErr) {
      console.log('Cloudmersive API error, using fallback analysis:', apiErr.message);
      
      // Fallback: Enhanced pattern-based risk assessment
      const suspiciousPatterns = [
        // URL shorteners (potential for hiding malicious links)
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link',
        // Malware-related keywords
        'malware', 'phishing', 'scam', 'hack', 'virus', 'trojan', 'ransomware',
        // Suspicious terms
        'free-money', 'click-here', 'suspicious', 'malicious', 'download-now',
        'urgent-action', 'verify-account', 'security-alert', 'limited-time',
        // Suspicious TLDs
        '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download'
      ];
      
      const suspiciousDomains = [
        'tempmail', 'guerrillamail', 'mailinator', '10minutemail',
        'discord.gg', 'telegram.me', 'drive.google.com/uc'
      ];
      
      const urlLower = url.toLowerCase();
      let suspiciousScore = 0;
      let detectedPatterns = [];
      
      // Check for suspicious patterns
      suspiciousPatterns.forEach(pattern => {
        if (urlLower.includes(pattern)) {
          suspiciousScore += 2;
          detectedPatterns.push(pattern);
        }
      });
      
      // Check for suspicious domains
      suspiciousDomains.forEach(domain => {
        if (urlLower.includes(domain)) {
          suspiciousScore += 3;
          detectedPatterns.push(domain);
        }
      });
      
      // Check for IP addresses instead of domains
      const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
      if (ipPattern.test(url)) {
        suspiciousScore += 4;
        detectedPatterns.push('direct-ip-access');
      }
      
      // Check for excessive redirects or suspicious structure
      const suspiciousStructure = url.split('/').length > 6 || url.includes('..') || url.includes('%');
      if (suspiciousStructure) {
        suspiciousScore += 2;
        detectedPatterns.push('suspicious-structure');
      }
      
      // Determine risk based on score
      if (suspiciousScore >= 5) {
        risk = 'high';
        confidence = 0.85;
        result = { 
          fallback: true, 
          analysis: 'pattern-based-fallback',
          reason: `High risk patterns detected: ${detectedPatterns.join(', ')}`,
          suspiciousScore,
          detectedPatterns
        };
      } else if (suspiciousScore >= 2) {
        risk = 'medium';
        confidence = 0.75;
        result = { 
          fallback: true, 
          analysis: 'pattern-based-fallback',
          reason: `Moderate risk patterns detected: ${detectedPatterns.join(', ')}`,
          suspiciousScore,
          detectedPatterns
        };
      } else {
        risk = 'low';
        confidence = 0.70;
        result = { 
          fallback: true, 
          analysis: 'pattern-based-fallback',
          reason: 'No suspicious patterns detected in URL structure',
          suspiciousScore: 0
        };
      }
    }
    
    const entry = { type: 'url', input: url, risk, confidence, result, date: new Date() };
    history.push(entry);
    console.log('URL analysis result:', { risk, confidence, analysis: result.analysis });
    res.json({ risk, confidence, result });
  } catch (err) {
    console.error('URL analysis error:', err);
    res.status(500).json({ error: 'URL analysis failed', details: err.message });
  }
});// --- History Endpoint ---
app.get('/history', (req, res) => {
  console.log('History requested');
  res.json(history.slice(-100).reverse()); // last 100 entries
});

// --- Delete History Endpoint ---
app.delete('/history', (req, res) => {
  console.log('History deletion requested');
  history.length = 0; // Clear the history array
  res.json({ message: 'History cleared successfully', timestamp: new Date().toISOString() });
});

// --- Analytics Endpoint ---
app.get('/analytics', (req, res) => {
  console.log('Analytics requested');
  const summary = { high: 0, low: 0, none: 0 };
  history.forEach(h => { summary[h.risk] = (summary[h.risk] || 0) + 1; });
  const total = history.length || 1;
  res.json({
    high: { count: summary.high, percent: (summary.high / total * 100).toFixed(1) },
    low: { count: summary.low, percent: (summary.low / total * 100).toFixed(1) },
    none: { count: summary.none, percent: (summary.none / total * 100).toFixed(1) },
    total,
  });
});

app.get('/', (req, res) => {
  res.json({ 
    message: 'CB-Project backend running',
    timestamp: new Date().toISOString(),
    endpoints: ['/analyze/text', '/analyze/url', '/analyze/file', '/history', '/analytics']
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
});
>>>>>>> b23f063d81246e59edde0b4c9973bef441470377
