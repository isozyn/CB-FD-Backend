# Railway Deployment Commands

# 1. Install Railway CLI (if not already installed)
npm install -g @railway/cli

# 2. Login to Railway
railway login

# 3. Initialize Railway project (run from project directory)
railway init

# 4. Set environment variables
railway variables set NETLIFY_SITE_URL=https://your-site-name.netlify.app
railway variables set JWT_SECRET=your-super-secret-jwt-key-make-it-long-and-random-123456789
railway variables set NODE_ENV=production

# 5. Deploy
railway up

# 6. Open your deployed app
railway open

# Optional: Add PostgreSQL database
railway add postgresql

# Optional: View logs
railway logs

# Optional: Connect to your app's environment
railway shell
