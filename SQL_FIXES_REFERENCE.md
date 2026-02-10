# SQL Fixes Reference Guide

## Issue 1: Boolean Type Mismatch in PostgreSQL

### The Problem
```sql
-- WRONG: PostgreSQL complains about type mismatch
ALTER TABLE usertype_permissions ADD COLUMN granted BOOLEAN DEFAULT 0;
-- Error: DEFAULT 0 type is integer, but column is boolean

-- WRONG: Inserting integer into boolean column
INSERT INTO usertype_permissions (usertype_id, module, action, granted) 
VALUES (1, 'ADMIN', 'VIEW', 1);
-- Error: column "granted" is of type boolean but expression is of type integer

-- WRONG: Comparing with integer literal
SELECT * FROM usertype_permissions WHERE granted = 1;
-- Works in SQLite, fails or behaves unexpectedly in PostgreSQL
```

### The Solution
```sql
-- CORRECT: Use FALSE for boolean default
ALTER TABLE usertype_permissions ADD COLUMN granted BOOLEAN DEFAULT FALSE;

-- CORRECT: Use boolean literals or NULL in Python, convert to bool
INSERT INTO usertype_permissions (usertype_id, module, action, granted) 
VALUES (1, 'ADMIN', 'VIEW', TRUE);

-- CORRECT: Compare with boolean values
SELECT * FROM usertype_permissions WHERE granted = TRUE;
SELECT * FROM usertype_permissions WHERE granted = FALSE;
```

### Python Implementation (Main App)

**BEFORE (Causes Type Errors):**
```python
# Line 537 - INSERT
cursor.execute(
    "INSERT INTO usertype_permissions (usertype_id, module, action, granted) VALUES (%s, %s, %s, 1)",
    (ut_id, module, action)
)
# Type Error: integer 1 cannot be cast to boolean

# Line 535 - UPDATE
cursor.execute(
    "UPDATE usertype_permissions SET granted = 1 WHERE id = %s",
    (exists['id'],)
)
# Type Error: cannot assign integer to boolean

# Line 6855 - SELECT
cursor.execute(
    "SELECT module, action FROM usertype_permissions WHERE granted = 1",
    (ut['id'],)
)
# PostgreSQL: 1 != true (different types)
```

**AFTER (Correct PostgreSQL Syntax):**
```python
# INSERT - Use Python True
cursor.execute(
    "INSERT INTO usertype_permissions (usertype_id, module, action, granted) VALUES (%s, %s, %s, %s)",
    (ut_id, module, action, True)
)
# Correctly casts Python True to PostgreSQL BOOLEAN

# UPDATE - Use parameterized True
cursor.execute(
    "UPDATE usertype_permissions SET granted = %s WHERE id = %s",
    (True, exists['id'])
)
# Parameterized True is type-safe

# SELECT - Use parameterized True
cursor.execute(
    "SELECT module, action FROM usertype_permissions WHERE granted = %s",
    (ut['id'], True)
)
# Parameterized comparison is type-safe and consistent
```

## Issue 2: Foreign Key Dependencies

### The Problem
```sql
-- WRONG: Creating users table before usertypes is committed
CREATE TABLE usertypes (id SERIAL PRIMARY KEY, ...);
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    user_type_id INTEGER NOT NULL,
    FOREIGN KEY (user_type_id) REFERENCES usertypes(id)
);
-- If usertypes transaction not committed, foreign key constraint fails

-- Error: relation "users" does not exist (during transaction)
-- Error: relation "usertypes" does not exist (during same transaction)
```

### The Solution
```python
# CORRECT: Commit after each critical table
conn, db_type = get_db_connection()
cursor = conn.cursor()

# 1. Create base table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS usertypes (
        id SERIAL PRIMARY KEY,
        user_role VARCHAR(100) UNIQUE NOT NULL
    )
""")
conn.commit()  # Ensure usertypes exists

# 2. Create dependent table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        user_type_id INTEGER NOT NULL,
        FOREIGN KEY (user_type_id) REFERENCES usertypes(id)
    )
""")
conn.commit()  # Ensure users exists

# 3. Create further dependents
cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_permissions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
""")
conn.commit()
```

### Dependency Chain
```
TABLE CREATION ORDER (with commits):

usertypes
    ↓ commit
users (FK → usertypes)
    ↓ commit
usertype_permissions (FK → usertypes)
user_permissions (FK → users)
projects (FK → users)
    ↓ commit
tasks (FK → projects, users)
daily_task_reports (FK → users, tasks, projects)
    ↓ commit
report_comments (FK → daily_task_reports, users)
```

## Issue 3: Schema Type Conversions

### All Boolean Columns Fixed

```sql
-- BEFORE (with errors in PostgreSQL)
CREATE TABLE usertype_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    granted BOOLEAN DEFAULT 0,  -- ERROR: type mismatch
    ...
);

-- AFTER (PostgreSQL compatible)
CREATE TABLE usertype_permissions (
    id SERIAL PRIMARY KEY,          -- SERIAL not AUTOINCREMENT
    granted BOOLEAN DEFAULT FALSE,  -- FALSE not 0
    ...
);
```

### All Table PKs Fixed

```sql
-- BEFORE (SQLite syntax)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ...
);

-- AFTER (PostgreSQL syntax)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,  -- SERIAL is PostgreSQL equivalent
    ...
);
```

## Parameterized Query Examples

### Safe Boolean Operations
```python
# ✅ SAFE - Parameterized and type-correct
cursor.execute(
    "SELECT * FROM table WHERE granted = %s",
    (True,)
)

# ✅ SAFE - Parameterized with variables
cursor.execute(
    "UPDATE table SET granted = %s WHERE id = %s",
    (is_granted, record_id)
)

# ❌ UNSAFE - String formatting (SQL injection risk)
cursor.execute(f"SELECT * FROM table WHERE granted = {1}")

# ❌ UNSAFE - Type mismatch
cursor.execute("SELECT * FROM table WHERE granted = 1")  # 1 is int, not boolean
```

### DictCursor Usage
```python
# PostgreSQL returns tuples by default
# DictCursor makes them dict-like (like SQLite's row_factory)

class PostgreSQLConnection:
    def cursor(self):
        return self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

# Now you can use dict access on both SQLite and PostgreSQL:
cursor.execute("SELECT id, user_role FROM usertypes")
for row in cursor.fetchall():
    print(row['id'], row['user_role'])  # Works on both databases!
```

## Rate Limiter Configuration

### BEFORE (In-Memory Warning)
```python
limiter = Limiter(key_func=get_client_ip, app=app)
# Warning: Using the in-memory storage for tracking rate limits as no storage was explicitly specified
```

### AFTER (Explicit Storage)
```python
if REDIS_URL:
    limiter = Limiter(
        key_func=get_client_ip,
        app=app,
        storage_uri=REDIS_URL,  # Explicit Redis backend
        default_limits=["1000 per hour"]
    )
else:
    limiter = Limiter(
        key_func=get_client_ip,
        app=app,
        storage_uri="memory://",  # Explicit in-memory backend (no warning)
        default_limits=["1000 per hour"]
    )
    logger.info("Using in-memory storage. For multi-dyno deployments, configure REDIS_URL.")
```

## Testing Queries

### Verify Boolean Defaults
```sql
-- Check that defaults are set correctly
SELECT column_name, column_default, data_type
FROM information_schema.columns
WHERE table_name = 'usertype_permissions'
AND column_name = 'granted';

-- Should show:
-- column_name | column_default | data_type
-- granted     | false          | boolean
```

### Verify Data Integrity
```sql
-- Check all permissions are properly set
SELECT id, usertype_id, module, action, granted
FROM usertype_permissions
WHERE granted = TRUE
ORDER BY usertype_id, module;

-- Should show all admin/coordinator permissions with granted = true
```

### Verify Foreign Keys
```sql
-- Check that foreign keys are created correctly
SELECT constraint_name, table_name, column_name
FROM information_schema.key_column_usage
WHERE table_name = 'users';

-- Should show user_type_id → usertypes.id
```

## Migration Path

If upgrading existing database:

```sql
-- 1. Add boolean column if it doesn't exist
ALTER TABLE usertype_permissions 
ADD COLUMN granted_new BOOLEAN DEFAULT FALSE;

-- 2. Copy data, converting 1/0 to TRUE/FALSE
UPDATE usertype_permissions 
SET granted_new = CASE WHEN granted = 1 THEN TRUE ELSE FALSE END;

-- 3. Drop old column and rename
ALTER TABLE usertype_permissions DROP COLUMN granted;
ALTER TABLE usertype_permissions RENAME COLUMN granted_new TO granted;
```

Or use Python script:
```python
cursor.execute("SELECT id, granted FROM usertype_permissions WHERE granted::text IN ('0', '1')")
for row in cursor.fetchall():
    bool_val = row['granted'] == '1'  # Convert to bool
    cursor.execute("UPDATE usertype_permissions SET granted = %s WHERE id = %s", (bool_val, row['id']))
conn.commit()
```
