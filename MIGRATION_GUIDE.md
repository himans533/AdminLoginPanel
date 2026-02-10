# SQLite to PostgreSQL Migration Guide

## Overview
This application has been successfully migrated from SQLite to PostgreSQL for Railway deployment. All database operations have been updated to support PostgreSQL while maintaining backward compatibility with local SQLite development.

## Changes Made

### 1. **Core Database Changes**
- **Removed SQLite-specific syntax:**
  - Removed all `PRAGMA foreign_keys = ON` statements
  - Removed `PRAGMA busy_timeout` statements
  - Replaced `AUTOINCREMENT` with PostgreSQL's `SERIAL` type
  - Replaced `sqlite_master` queries with `information_schema` queries

- **Fixed Connection Handling:**
  - Added `PostgreSQLConnection` wrapper class for consistent row access (dict-like behavior)
  - Imported `psycopg2.extras.DictCursor` for dictionary-based row access
  - Maintained SQLite compatibility for local development

### 2. **Files Modified**
- **main.py**: 
  - Updated `get_db_connection()` to return PostgreSQL wrapper
  - Fixed all `PRAGMA` statements
  - Fixed `init_db()` function with proper connection management
  - Fixed `migrate_db()` for PostgreSQL syntax
  - Fixed `check_db_initialized()` to use `information_schema` for PostgreSQL
  - Updated row access patterns for PostgreSQL compatibility

- **Removed verify_db.py**: SQLite-specific verification script no longer needed

### 3. **Database Tables Updated**
All tables have been created with proper PostgreSQL syntax:
- `usertypes`
- `usertype_permissions`
- `users`
- `user_permissions`
- `projects`
- `tasks`
- `comments`
- `documents`
- `milestones`
- `project_assignments`
- `progress_history`
- `activities`
- `user_skills`
- `daily_task_reports`
- `report_comments`
- `audit_logs`

## Deployment Steps

### For Railway Deployment:

1. **Environment Variables** (already configured):
   ```
   DATABASE_URL=postgresql://[user]:[password]@[host]:[port]/[database]
   ```
   The Railway environment will automatically provide this.

2. **Database Initialization** (automatic on startup):
   - The Flask app calls `safe_init_db()` on startup
   - This checks if the database is initialized using `check_db_initialized()`
   - If not initialized, it runs `init_db()` to create all tables
   - Then `migrate_db()` runs to ensure all columns exist

3. **No Manual Migration Needed**:
   - Simply deploy to Railway
   - The app will automatically create and initialize the PostgreSQL database on first run
   - All data will be properly structured

### For Local SQLite Development:

1. **Requirements**:
   - Ensure `psycopg2-binary` is in requirements.txt (it is)
   - SQLite3 is built-in with Python

2. **Local Database**:
   - If no `DATABASE_URL` is set, the app will use local SQLite (`project_management.db`)
   - Database will be automatically created on first run

3. **Database Location**:
   - Local: `./project_management.db`
   - Railway: PostgreSQL database via DATABASE_URL

## Testing the Migration

### Before Deployment:
1. Run the app locally to verify SQLite still works:
   ```bash
   python main.py
   ```

2. Check that `project_management.db` is created and accessible

### After Railway Deployment:
1. Check Railway logs for initialization messages:
   - Look for: "[OK] Database initialized successfully"
   - Look for: "[OK] Database migration completed!"

2. Verify database tables were created by checking the Railway PostgreSQL dashboard

3. Test API endpoints to ensure data persistence works

## Troubleshooting

### Error: "syntax error at or near 'PRAGMA'"
- ✅ **Fixed**: All PRAGMA statements have been removed or conditionally applied

### Error: "relation 'sqlite_master' does not exist"
- ✅ **Fixed**: Updated to use `information_schema` for PostgreSQL

### Error: "AUTOINCREMENT is not valid SQL"
- ✅ **Fixed**: Changed all `AUTOINCREMENT` to `SERIAL PRIMARY KEY`

### Error: "ModuleNotFoundError: No module named 'psycopg2'"
- ✅ **Fixed**: `psycopg2-binary` is in requirements.txt
- Railway will install it automatically during build

### Database Connection Issues:
1. Verify `DATABASE_URL` is set in Railway environment variables
2. Check Railway PostgreSQL service is running
3. Check credentials in DATABASE_URL are correct

## Data Migration from Existing SQLite Database

If you had production data in SQLite:

1. Export data from SQLite:
   ```bash
   sqlite3 project_management.db .dump > backup.sql
   ```

2. Transform SQLite dump to PostgreSQL compatible format (handle syntax differences)

3. Import into Railway PostgreSQL using Railway dashboard or psql CLI

**Note**: The app doesn't provide automated migration - you'll need to manually transfer data if needed.

## Rollback (if needed)

To revert to local SQLite development:
1. Remove `DATABASE_URL` from environment
2. The app will automatically fall back to `project_management.db`
3. Both databases can coexist without affecting each other

## Performance Notes

### PostgreSQL Benefits:
- Better concurrent connection handling (Railway requirement)
- More efficient query optimization for complex operations
- Built-in connection pooling support
- Superior transaction handling

### Verification:
- All database initialization happens automatically
- Connection pooling is handled by Railway/psycopg2
- Rate limiting works with in-memory storage as fallback

## Future Improvements

1. Add Redis for rate limiter storage (optional, set `REDIS_URL` env var)
2. Implement connection pooling with pgBouncer if needed
3. Add automated backups in Railway dashboard
4. Set up monitoring and alerting for database performance

---

**Status**: ✅ Ready for Railway deployment
