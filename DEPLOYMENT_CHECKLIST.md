# Railway PostgreSQL Deployment - Verification Checklist

## Pre-Deployment Verification

### 1. Code Changes Completed
- [x] Fixed all `BOOLEAN DEFAULT 0` → `BOOLEAN DEFAULT FALSE`
- [x] Fixed all `granted = 1` → `granted = %s` with `True` parameter
- [x] Fixed all `INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL PRIMARY KEY`
- [x] Added `conn.commit()` after critical table creations
- [x] Updated Flask-Limiter configuration
- [x] Added PostgreSQL DictCursor wrapper

### 2. Boolean Type Fixes Verified
✅ **All Locations Fixed:**
- Line 281: `usertype_permissions.granted DEFAULT FALSE`
- Line 295: `users.granted DEFAULT FALSE`
- Line 315: `user_permissions.granted DEFAULT FALSE`
- Line 485: `report_comments.internal DEFAULT FALSE`
- Line 535: INSERT/UPDATE using `True` parameter
- Line 537: INSERT using `True` parameter
- Line 6855: SELECT using `True` parameter
- Line 6913: INSERT using `True` parameter
- Line 6960: INSERT using `True` parameter

### 3. Table Creation Order Verified
✅ **Proper Commit Sequence:**
- Line 253: `conn.commit()` after usertypes
- Line 270: `conn.commit()` after description column
- Line 306: `conn.commit()` after users
- Line 742: `conn.commit()` after daily_task_reports

### 4. Configuration Files Verified
- [x] `.env` has DATABASE_URL set for Railway PostgreSQL
- [x] `Procfile` configured for gunicorn
- [x] `requirements.txt` includes `psycopg2-binary`
- [x] `main.py` imports `psycopg2.extras` for DictCursor

## Deployment Steps

### Step 1: Push Code to Git
```bash
git add -A
git commit -m "PostgreSQL migration: fix boolean types, table creation order, and Flask-Limiter config"
git push origin sqlite-to-postgres-migration
```

### Step 2: Configure Railway Environment
1. Go to Railway Dashboard
2. Connect to GitHub repo (if not already)
3. Create new project from GitHub
4. Select repository and branch
5. Railway auto-creates PostgreSQL database
6. Set environment variables:
   - `DATABASE_URL` (auto-set by Railway)
   - `FLASK_ENV=production`
   - `SECRET_KEY` (use generated secret)

### Step 3: Deploy
1. Push branch to trigger deployment
2. Railway builds and deploys automatically
3. App starts with `gunicorn main:app` from Procfile

### Step 4: Verify Deployment
Monitor logs in Railway Dashboard:
```
[INFO] Flask app starting...
[OK] Database initialized successfully (verified schema)!
[OK] Init Daily Report Module success...
[INFO] Running on http://0.0.0.0:5000
```

## Post-Deployment Verification

### 1. Check Database Connection
```bash
# SSH into Railway container (optional)
# Or use Railway's database UI to verify
```

### 2. Verify Tables Created
```sql
-- Check all tables exist
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public';

-- Should show: usertypes, users, projects, tasks, daily_task_reports, etc.
```

### 3. Verify Boolean Columns
```sql
-- Check granted columns are boolean
SELECT column_name, data_type, column_default
FROM information_schema.columns
WHERE column_name = 'granted' AND table_schema = 'public';

-- Should show:
-- granted | boolean | false
```

### 4. Verify Initial Data
```sql
-- Check usertypes seeded
SELECT * FROM usertypes;
-- Should show: Administrator, Employee, Project-Cordinator

-- Check permissions seeded
SELECT COUNT(*) FROM usertype_permissions WHERE granted = true;
-- Should show: 19 (admin) + 3 (employee) + 6 (coordinator) = 28+
```

### 5. Test Application
1. Navigate to app URL
2. Login with default credentials
3. Test user management
4. Check daily reports functionality
5. Verify rate limiting works

## Rollback Plan

If deployment fails:

### Option 1: Quick Revert
```bash
# Switch back to main branch in Railway
git checkout main
git push origin main
# Railway auto-redeploys (if Railway is still working)
```

### Option 2: New Database
```bash
# If database is corrupted:
1. Delete PostgreSQL database in Railway
2. Create new PostgreSQL database
3. Deploy app again (will initialize fresh)
```

### Option 3: Return to SQLite (Local)
```bash
# For local development only
# Keep .env DATABASE_URL commented out
# App will use local project_management.db
```

## Monitoring

### Key Logs to Watch
```
[ERROR] Database initialization failed: → Fix database
[ERROR] Init Daily Report Module failed: → Check daily reports table
[WARNING] Flask-Limiter using in-memory storage → Expected (unless REDIS_URL set)
[ERROR] syntax error at or near "PRAGMA" → Boolean/SQL syntax error
[ERROR] relation "X" does not exist → Missing table (commit issue)
```

### Performance Monitoring
- Response times (should be <200ms for most endpoints)
- Database connection pooling (psycopg2 handles this)
- Memory usage (Flask is lightweight)
- Rate limiting (should prevent abuse)

## Common Issues & Solutions

### Issue: "relation 'users' does not exist"
**Cause:** Table creation transaction not committed
**Solution:** Already fixed - check line 306 has `conn.commit()`
**Verification:** Run Grep for `conn.commit()`

### Issue: "column 'granted' is of type boolean but expression is of type integer"
**Cause:** Using `1` instead of `True` in SQL
**Solution:** Already fixed - all instances changed to use `True`
**Verification:** Grep for `granted = 1` (should return 0 results)

### Issue: "Using the in-memory storage for tracking rate limits"
**Cause:** Flask-Limiter not configured with explicit backend
**Solution:** Already fixed - storage_uri explicitly set to "memory://"
**Verification:** Check lines 164-170 in main.py

### Issue: Login doesn't work after deployment
**Cause:** Database not initialized or users table empty
**Solution:** App calls `safe_init_db()` on startup (line 5826)
**Verification:** Check app logs for initialization messages

## Final Checklist

Before declaring deployment successful:

- [ ] App deploys without errors
- [ ] No "relation does not exist" errors in logs
- [ ] No "boolean type" errors in logs
- [ ] Database tables visible in Railway dashboard
- [ ] Can login with default credentials
- [ ] Can create/view projects
- [ ] Can create/view tasks
- [ ] Can submit daily reports
- [ ] Rate limiting doesn't trigger on normal use
- [ ] No performance degradation
- [ ] All endpoints respond normally

## Success Indicators

✅ Deployment is successful when:
1. App starts without database errors
2. All 16 tables created successfully
3. Boolean columns have correct default values
4. Initial user types and permissions seeded
5. Login functionality works
6. All core features accessible
7. No SQL type errors in logs

## Support

If issues persist:
1. Check Railway logs in real-time
2. Verify DATABASE_URL is correct
3. Check Procfile syntax
4. Ensure psycopg2-binary in requirements.txt
5. Review main.py for unintended changes

## Documentation Files

- `POSTGRESQL_FIXES_COMPLETE.md` - Detailed explanation of all fixes
- `SQL_FIXES_REFERENCE.md` - SQL examples and patterns
- `MIGRATION_SUMMARY.md` - Migration overview
- `QUICK_START_DEPLOYMENT.md` - Quick deployment guide
