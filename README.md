# CB-FD-Backend - Railway Deployment Guide

Production-ready Express.js backend designed for Railway hosting with CORS configured for Netlify frontend.

## 🚀 Quick Deploy to Railway

1. **Connect Repository to Railway**
   - Go to [Railway.app](https://railway.app)
   - Click "Deploy from GitHub repo"
   - Select this repository

2. **Configure Environment Variables**
   In Railway dashboard, add these environment variables:
   
   ```bash
   # Required
   NETLIFY_SITE_URL=https://your-site-name.netlify.app
   JWT_SECRET=your-super-secret-jwt-key-here
   
   # Optional (if using database)
   DB_URL=${{Postgres.DATABASE_URL}}  # Railway auto-injects this if you add Postgres
   ```

3. **Deploy**
   - Railway will automatically build and deploy
   - Your API will be available at `https://your-app.railway.app`

## 🔧 Environment Variables Setup

### Required Variables
- `NETLIFY_SITE_URL`: Your Netlify site URL for CORS
- `JWT_SECRET`: Secret key for JWT token signing

### Optional Variables
- `DB_URL`: Database connection string
- `REDIS_URL`: Redis connection for caching
- `API_KEY_*`: Any third-party API keys

### Setting Variables in Railway
1. Go to your Railway project
2. Click on "Variables" tab
3. Add each variable with its value
4. Railway will automatically restart your service

## 📁 File Structure

```
CB-FD-Backend/
├── server.js           # Main server file
├── package.json        # Dependencies and scripts
├── railway.toml        # Railway configuration
├── .env.example        # Environment variables template
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

## 🛡️ Security Features

- **CORS Protection**: Only allows requests from your Netlify site
- **Security Headers**: XSS protection, content type sniffing prevention
- **Request Logging**: Production-ready logging
- **Error Handling**: Safe error responses (no sensitive data leaks)
- **Input Validation**: JSON parsing with error handling

## 🔗 API Endpoints

### Health Check
```
GET /health
```
Returns server status - required by Railway for health monitoring.

### Root
```
GET /
```
Returns API information and available endpoints.

### Example API Routes
```
GET /api/status       # API status check
POST /api/auth/verify # Example protected route
```

## 🏃‍♂️ Local Development

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Create Environment File**
   ```bash
   cp .env.example .env
   # Edit .env with your local values
   ```

3. **Run Development Server**
   ```bash
   npm run dev
   ```

4. **Test Production Mode Locally**
   ```bash
   npm run prod
   ```

## 🔍 Monitoring & Debugging

### Health Check
Your Railway app will be monitored via `/health` endpoint. This returns:
- Server status
- Environment info
- Uptime
- Memory usage
- Database connectivity (if configured)

### Logs
View logs in Railway dashboard:
1. Go to your project
2. Click on "Deployments"
3. Select latest deployment
4. View logs in real-time

## 🌐 CORS Configuration

The server is configured to:
- **Production**: Only allow requests from `NETLIFY_SITE_URL`
- **Development**: Allow localhost on ports 3000, 3001

To update allowed origins, modify the `corsOptions` in `server.js`.

## 🗄️ Database Integration

If you need a database:

1. **Add PostgreSQL to Railway**
   - In Railway dashboard, click "Add Service"
   - Select "PostgreSQL"
   - Railway will auto-inject `DATABASE_URL`

2. **Use in Your Code**
   ```javascript
   const DB_URL = process.env.DB_URL;
   // Use with your preferred ORM/client
   ```

## 🔐 JWT Authentication Example

```javascript
const jwt = require('jsonwebtoken');

// Generate token
const token = jwt.sign({ userId: 123 }, process.env.JWT_SECRET);

// Verify token
const decoded = jwt.verify(token, process.env.JWT_SECRET);
```

## 🚨 Production Checklist

- ✅ Environment variables configured in Railway
- ✅ CORS set to your Netlify URL
- ✅ JWT_SECRET is secure and random
- ✅ Database connection tested (if applicable)
- ✅ Health endpoint responding
- ✅ Error handling tested
- ✅ Logs monitored

## 🤝 Support

For Railway-specific issues, check:
- [Railway Documentation](https://docs.railway.app/)
- [Railway Discord](https://discord.gg/railway)

For code issues, check the application logs in Railway dashboard.

---

**Ready for production! 🎉**