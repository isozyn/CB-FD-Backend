# Railway Deployment Guide for CB-FD-Backend

## 🚀 Quick Deploy to Railway

### Step 1: Prepare Your Repository
Your project is now Railway-ready with:
- ✅ Production environment variables configured
- ✅ CORS set for your Netlify site: `https://starlit-croissant-5176b3.netlify.app`
- ✅ Three API integrations ready
- ✅ Health endpoint for Railway monitoring

### Step 2: Deploy to Railway

1. **Go to Railway.app and login**
   - Visit [Railway.app](https://railway.app)
   - Click "Deploy from GitHub repo"
   - Select your `CB-FD-Backend` repository

2. **Set Environment Variables in Railway Dashboard**
   After deployment, go to your project → Variables tab and add:

   ```bash
   # Required
   NODE_ENV=production
   NETLIFY_SITE_URL=https://starlit-croissant-5176b3.netlify.app
   
   # API Keys (use your actual keys)
   REKA_API_KEY=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
   OPENROUTER_API_KEY=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
   SCANII_API_KEY=f6a27196b75409fd7358e154da9a6a8a
   
   # Security (generate strong secrets)
   JWT_SECRET=your-super-secure-jwt-secret-make-it-long-and-random-123456789
   SESSION_SECRET=your-session-secret-key-for-production
   ```

3. **Railway will automatically:**
   - Install dependencies (`npm install`)
   - Start your server (`npm start`)
   - Provide a public URL like `https://your-app.railway.app`

### Step 3: Test Your Deployment

Once deployed, test these endpoints:

```bash
# Health check
GET https://your-app.railway.app/health

# File analysis
POST https://your-app.railway.app/analyze/file
Content-Type: multipart/form-data
Body: file upload

# Text analysis  
POST https://your-app.railway.app/analyze/text
Content-Type: application/json
Body: {"text": "Test message to analyze"}

# URL analysis
POST https://your-app.railway.app/analyze/url
Content-Type: application/json
Body: {"url": "https://example.com"}

# History
GET https://your-app.railway.app/history
```

### Step 4: Update Your Frontend

Update your Netlify frontend to use the Railway backend URL:
```javascript
const API_BASE_URL = 'https://your-app.railway.app';
```

## 🔧 API Configuration

Your backend now uses these three APIs:

1. **Reka Flash 3** - For text/file content analysis
2. **OpenRouter DeepSeek** - For text classification (spam/scam detection)
3. **Scanii** - For file security scanning

## 🛡️ Security Features

- **CORS**: Only accepts requests from your Netlify site
- **Environment Variables**: All sensitive data stored securely
- **Error Handling**: Production-safe error responses
- **Request Logging**: Comprehensive logging for debugging

## 📊 Monitoring

Railway will monitor your app via the `/health` endpoint. You can view:
- Real-time logs in Railway dashboard
- Performance metrics
- Deployment history

## 🚨 Troubleshooting

If deployment fails:
1. Check Railway logs for error messages
2. Verify all environment variables are set
3. Ensure your GitHub repo is up to date
4. Check that all dependencies install correctly

## 📞 Support

- Railway documentation: [docs.railway.app](https://docs.railway.app)
- Your app health: `https://your-app.railway.app/health`
- Railway dashboard for logs and metrics

---

**Your CB-FD-Backend is ready for production! 🎉**
