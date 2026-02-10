# Railway CLI Deployment Guide - AdminLoginPanel

## Prerequisites

Before deploying to Railway, ensure you have:

1. **Railway CLI installed**: `npm install -g @railway/cli`
2. **Git repository**: Project must be in a git repository
3. **GitHub account**: For connecting Railway to your repo
4. **Railway account**: Create at https://railway.app

## Step-by-Step Deployment

### 1. Initialize Railway Project

```bash
cd /path/to/AdminLoginPanel
railway init
```

When prompted:
- Choose "AdminLoginPanel" as project name
- Select "Other" for project type
- Press Enter to continue

### 2. Link GitHub Repository (Optional but Recommended)

```bash
# If not already connected
railway link
```

This allows Railway to auto-deploy on git pushes.

### 3. Add PostgreSQL Database

```bash
railway add
```

Select **PostgreSQL** from the list and press Enter.

Railway will automatically:
- Create a new PostgreSQL database
- Generate connection credentials
- Set `DATABASE_URL` environment variable

### 4. Configure Environment Variables

The following are automatically set by Railway:
- `DATABASE_URL` - PostgreSQL connection string (auto-generated)

Optional configurations you may want to add:

```bash
railway variables set FLASK_ENV=production
railway variables set LOG_LEVEL=INFO
```

To add Redis for rate limiting (optional):

```bash
railway add
# Select Redis from the list
```

Then set:
```bash
railway variables set REDIS_URL=${REDIS_URL}
```

### 5. Deploy the Application

**Option A: Deploy from Local Repository**

```bash
railway up
```

This will:
1. Read Procfile to determine how to start the app
2. Install Python dependencies from requirements.txt
3. Run the Flask application on port 5000

**Option B: Deploy from GitHub (Recommended)**

```bash
railway link --github
```

This enables continuous deployment: every push to main automatically deploys.

### 6. View Deployment Status

```bash
# Check deployment logs
railway logs

# View project status
railway status

# Open in browser
railway open
```

### 7. Database Initialization

The database will automatically initialize on first startup:

1. App starts and reads `DATABASE_URL`
2. `safe_init_db()` creates all tables
3. Initial data (user types, permissions) is seeded
4. App is ready to accept requests

**Verify database was created:**

```bash
railway shell
# Once in shell:
psql $DATABASE_URL -c "\dt"  # List all tables
```

## Post-Deployment Verification

### 1. Check Application Health

```bash
# Get app URL
railway open
# Should load the login page without errors
```

### 2. Verify Database Connection

```bash
# View logs for database initialization
railway logs | grep "OK\|ERROR"
```

Look for:
```
[OK] Database initialized successfully
[OK] Database migration completed!
```

### 3. Test Database Tables

```bash
railway shell
psql $DATABASE_URL << EOF
SELECT COUNT(*) FROM usertypes;
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM usertype_permissions;
EOF
```

Expected output:
```
 count
-------
     3    -- 3 user types (Administrator, Employee, Project-Coordinator)
(1 row)
```

## Troubleshooting

### Issue: "relation 'users' does not exist"

**Cause**: Database initialization failed

**Solution**:
```bash
# Check logs
railway logs

# Restart app to trigger re-initialization
railway redeploy
```

### Issue: "column 'granted' is of type boolean"

**Cause**: Boolean value type mismatch

**Solution**: This is already fixed in the code. If you see this error:
1. Pull latest code: `git pull origin sqlite-to-postgres-migration`
2. Deploy again: `railway up`

### Issue: In-memory rate limiting warning

**Cause**: Redis not configured (not critical for single instance)

**Solution** (optional):
```bash
railway add
# Select Redis
railway variables set REDIS_URL=${REDIS_URL}
railway redeploy
```

### Issue: Connection timeout

**Cause**: Database might be initializing or overloaded

**Solution**:
```bash
# Wait 30 seconds and retry
sleep 30
railway open
```

## Environment Variables Reference

| Variable | Auto-Set | Purpose |
|----------|----------|---------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Optional | Redis for rate limiting |
| `FLASK_ENV` | No | Set to `production` |
| `LOG_LEVEL` | No | `INFO`, `DEBUG`, `ERROR` |

## Database Schema

The following tables are automatically created:

1. **usertypes** - User roles (Administrator, Employee, Project-Coordinator)
2. **users** - User accounts
3. **usertype_permissions** - Role-based permissions
4. **user_permissions** - Per-user permissions
5. **projects** - Project management
6. **tasks** - Task management
7. **daily_task_reports** - Daily reports
8. **And 8+ more tables** - Comments, documents, milestones, etc.

## Monitoring

### View Real-time Logs

```bash
railway logs --follow
```

### View Metrics

```bash
railway open
# Click "Metrics" tab in dashboard
```

## Rollback to Previous Deploy

```bash
railway deployments
# Find the deployment ID you want to rollback to
railway redeploy <deployment-id>
```

## Scale or Stop Application

```bash
# Stop without deleting
railway pause

# Resume
railway resume

# Increase resources
railway redeploy --build
```

## Useful Commands

```bash
# View all environments
railway environments

# Switch environment (staging/production)
railway switch

# View raw connection details
railway variables

# SSH into the app
railway shell

# Remove database (CAREFUL!)
railway remove postgres
```

## Security Notes

1. **Never commit** `.env` files or database credentials
2. **Use** `railway variables` to set secrets, never hardcode them
3. **Enable** automatic HTTPS (Railway does this by default)
4. **Backup** your database regularly via Railway dashboard

## Additional Resources

- Railway Documentation: https://docs.railway.app
- Flask-SQLAlchemy Guide: https://flask-sqlalchemy.palletsprojects.com
- PostgreSQL Documentation: https://www.postgresql.org/docs

## Success Indicators

After deployment, you should see:

```
✓ Application started successfully
✓ Connected to PostgreSQL database
✓ Database tables created
✓ 3 user types seeded
✓ Ready to accept connections
```

Visit your Railway app URL and you should see the login page!
