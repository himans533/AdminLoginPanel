from flask import Flask, jsonify, request, render_template, session, g, send_from_directory
from flask_cors import CORS
import os

# Rate limiting
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except Exception:
    Limiter = None

# Optional Redis storage for limiter
REDIS_URL = os.environ.get('REDIS_URL')
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
import secrets
import json
import re
import os
import io
from datetime import datetime, timezone, timedelta
import logging
import time
from flask import redirect, url_for
import psycopg2
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
# Persistent secret key for Replit environment
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # TEMPORARY FIX
)

valid_tokens = {}

# In-memory store for failed login attempts (simple rate limiter)
failed_login_attempts = {}
LOGIN_BLOCK_THRESHOLD = 5  
LOGIN_BLOCK_WINDOW = 15 * 60  # 15 minutes


def get_client_ip():
    # Respect X-Forwarded-For if present
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'


def is_ip_blocked(ip):
    info = failed_login_attempts.get(ip)
    if not info:
        return False
    blocked_until = info.get('blocked_until')
    if blocked_until and blocked_until > time.time():
        return True
    # If window expired, clear
    if time.time() - info.get('first_failed', 0) > LOGIN_BLOCK_WINDOW:
        failed_login_attempts.pop(ip, None)
        return False
    return False


def register_failed_login(ip):
    now = time.time()
    info = failed_login_attempts.get(ip)
    if not info:
        failed_login_attempts[ip] = {'count': 1, 'first_failed': now}
    else:
        # Reset if outside window
        if now - info.get('first_failed', 0) > LOGIN_BLOCK_WINDOW:
            failed_login_attempts[ip] = {'count': 1, 'first_failed': now}
        else:
            info['count'] = info.get('count', 0) + 1
            if info['count'] >= LOGIN_BLOCK_THRESHOLD:
                info['blocked_until'] = now + LOGIN_BLOCK_WINDOW


def reset_failed_login(ip):
    failed_login_attempts.pop(ip, None)


# CSRF helpers
def generate_csrf_token():
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return token


@app.context_processor
def inject_csrf():
    # Make csrf_token available in templates
    return {'csrf_token': generate_csrf_token()}


@app.before_request
def csrf_protect():
    # Only protect requests when a session-authenticated user exists (cookie-based session)
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        # If session indicates authenticated (cookie-based), require X-CSRF-Token header
        if session.get('is_authenticated'):
            header = request.headers.get('X-CSRF-Token')
            if not header or header != session.get('csrf_token'):
                return jsonify({'error': 'Missing or invalid CSRF token.'}), 400

        # If Authorization Bearer token is used, enforce double-submit token check
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            if token not in valid_tokens:
                return jsonify({'error': 'Invalid bearer token.'}), 401
            expected = valid_tokens[token].get('csrf_token')
            header = request.headers.get('X-CSRF-Token')
            if not header or header != expected:
                return jsonify({'error': 'Missing or invalid CSRF token for bearer auth.'}), 400


@app.after_request
def set_security_headers(response):
    try:
        # Only set HSTS when running under https/production
        if request.scheme == 'https' or os.environ.get('FLASK_ENV') == 'production':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    except Exception:
        pass

    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Minimal Permissions-Policy header to opt-out of sensors
    response.headers['Permissions-Policy'] = 'geolocation=()'
    return response

# Make session cookies secure when appropriate
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get('FLASK_ENV') == 'production' else False

# Initialize rate limiter (use Redis if available)
limiter = None
if Limiter is not None:
    try:
        if REDIS_URL:
            # Using storage_uri lets flask-limiter auto-configure RedisStorage when possible
            limiter = Limiter(key_func=get_client_ip, app=app, storage_uri=REDIS_URL, default_limits=["1000 per hour"])
        else:
            limiter = Limiter(key_func=get_client_ip, app=app, default_limits=["1000 per hour"])
    except Exception as e:
        logger.warning(f"Flask-Limiter initialization failed: {e}")
        limiter = None
else:
    logger.info("flask-limiter not installed; skipping rate-limiter setup")

ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'anubha@gmail.com').lower()
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Anubha@#46')
ADMIN_OTP = os.environ.get('ADMIN_OTP', '123456')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB max
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads', 'profiles')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

DB_PATH = os.path.join(os.path.dirname(__file__), 'project_management.db')


def get_db_connection():
    # Force use of SQLite
    conn = psycopg2.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = psycopg2.Row
    try:
        conn.execute('PRAGMA foreign_keys = ON')
        conn.execute('PRAGMA journal_mode = WAL')
    except Exception:
        pass
    return conn



# REFACTORED init_db to be NON-DESTRUCTIVE and IDEMPOTENT
def init_db():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        
        cursor.execute("PRAGMA foreign_keys = ON")

        # 1. Create independent tables first
        
        # Usertypes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usertypes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_role TEXT NOT NULL UNIQUE,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Check if description column exists (for old DBS)
        try: 
            cursor.execute("ALTER TABLE usertypes ADD COLUMN description TEXT")
        except: pass

        # Usertype Permissions (dependent on usertypes)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usertype_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usertype_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                action TEXT NOT NULL,
                granted BOOLEAN DEFAULT 0,
                FOREIGN KEY (usertype_id) REFERENCES usertypes(id) ON DELETE CASCADE,
                UNIQUE(usertype_id, module, action)
            )
        ''')

        # Users (dependent on usertypes)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                user_type_id INTEGER NOT NULL,
                granted BOOLEAN DEFAULT 0,
                status TEXT DEFAULT 'Active',
                phone TEXT,
                department TEXT,
                bio TEXT,
                avatar_url TEXT,
                is_system INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_type_id) REFERENCES usertypes(id)
            )
        ''')
        
        # Ensure 'is_system' column
        try: cursor.execute("ALTER TABLE users ADD COLUMN is_system INTEGER DEFAULT 0")
        except: pass

        # User Permissions (dependent on users)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                action TEXT NOT NULL,
                granted BOOLEAN DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(user_id, module, action)
            )
        ''')

        # Projects (dependent on users)
        cursor.execute('''CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'In Progress',
            progress INTEGER DEFAULT 0,
            deadline DATE,
            reporting_time TIME DEFAULT '09:00',
            created_by_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (created_by_id) REFERENCES users(id)
        )''')

        # Tasks (dependent on projects, users)
        cursor.execute('''CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'Pending',
            priority TEXT DEFAULT 'Medium',
            deadline DATE,
            project_id INTEGER NOT NULL,
            created_by_id INTEGER NOT NULL,
            assigned_to_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            approval_status TEXT DEFAULT 'pending',
            weightage INTEGER DEFAULT 1,
            FOREIGN KEY (project_id) REFERENCES projects(id),
            FOREIGN KEY (created_by_id) REFERENCES users(id),
            FOREIGN KEY (assigned_to_id) REFERENCES users(id)
        )''')

        # Comments (dependent on users, projects, tasks)
        cursor.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            project_id INTEGER,
            task_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users(id),
            FOREIGN KEY (project_id) REFERENCES projects(id),
            FOREIGN KEY (task_id) REFERENCES tasks(id)
        )''')

        # Documents
        cursor.execute('''CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_size INTEGER,
            uploaded_by_id INTEGER NOT NULL,
            project_id INTEGER,
            task_id INTEGER,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by_id) REFERENCES users(id),
            FOREIGN KEY (project_id) REFERENCES projects(id),
            FOREIGN KEY (task_id) REFERENCES tasks(id)
        )''')

        # Milestones
        cursor.execute('''CREATE TABLE IF NOT EXISTS milestones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            due_date DATE,
            status TEXT DEFAULT 'Pending',
            project_id INTEGER NOT NULL,
            weightage INTEGER DEFAULT 1,
            created_by_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id),
            FOREIGN KEY (created_by_id) REFERENCES users(id)
        )''')

        # Project Assignments
        cursor.execute('''CREATE TABLE IF NOT EXISTS project_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            project_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (project_id) REFERENCES projects(id),
            UNIQUE(user_id, project_id)
        )''')

        # Progress History
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS progress_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            progress_percentage INTEGER,
            tasks_completed INTEGER,
            total_tasks INTEGER,
            milestones_completed INTEGER,
            total_milestones INTEGER,
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_progress_project_date 
            ON progress_history(project_id, recorded_at)
        ''')

        # Activities
        cursor.execute('''CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            activity_type TEXT NOT NULL,
            description TEXT NOT NULL,
            project_id INTEGER,
            task_id INTEGER,
            milestone_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (project_id) REFERENCES projects(id),
            FOREIGN KEY (task_id) REFERENCES tasks(id),
            FOREIGN KEY (milestone_id) REFERENCES milestones(id)
        )''')

        # User Skills
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_skills (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            skill_name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, skill_name)
        )''')

        # Daily Reports
        cursor.execute('''CREATE TABLE IF NOT EXISTS daily_task_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            project_id INTEGER NOT NULL,
            report_date DATE NOT NULL,
            work_description TEXT,
            time_spent REAL DEFAULT 0,
            status TEXT DEFAULT 'In Progress',
            blocker TEXT,
            approval_status TEXT DEFAULT 'pending',
            reviewed_by INTEGER,
            review_comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (task_id) REFERENCES tasks(id),
            FOREIGN KEY (project_id) REFERENCES projects(id),
            FOREIGN KEY (reviewed_by) REFERENCES users(id),
            UNIQUE(user_id, task_id, report_date)
        )''')

        # Report Comments
        cursor.execute('''CREATE TABLE IF NOT EXISTS report_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            commenter_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            internal BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (report_id) REFERENCES daily_task_reports(id),
            FOREIGN KEY (commenter_id) REFERENCES users(id)
        )''')
        
        # Audit Logs (Missing in original init_db properly but used in code)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id INTEGER,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Seed initial data if usertypes are empty or missing details
        cursor.execute("SELECT id, user_role FROM usertypes WHERE user_role IN ('Administrator', 'Employee', 'Project-Cordinator')")
        existing_types = {row['user_role']: row['id'] for row in cursor.fetchall()}
        
        defaults = {
            'Administrator': 'Full system access and management',
            'Employee': 'Standard employee access for reporting',
            'Project-Cordinator': 'Project management and team coordination'
        }
        
        ids = {}
        for role, desc in defaults.items():
            if role not in existing_types:
                cursor.execute("INSERT INTO usertypes (user_role, description) VALUES (?, ?)", (role, desc))
                ids[role] = cursor.lastrowid
            else:
                ids[role] = existing_types[role]
                cursor.execute("UPDATE usertypes SET description = ? WHERE id = ? AND (description IS NULL OR description = '' OR description = '-')",(desc, ids[role]))

        # Helper to seed permissions
        def seed_perms(ut_id, perms):
            if not ut_id: return
            for module, action in perms:
                # Check if exists
                cursor.execute("SELECT id FROM usertype_permissions WHERE usertype_id = ? AND module = ? AND action = ?", (ut_id, module, action))
                exists = cursor.fetchone()
                if exists:
                    cursor.execute("UPDATE usertype_permissions SET granted = 1 WHERE id = ?", (exists[0],))
                else:
                    cursor.execute("INSERT INTO usertype_permissions (usertype_id, module, action, granted) VALUES (?, ?, ?, 1)", (ut_id, module, action))

        # Get IDs for seeding permissions
        admin_id = ids.get('Administrator')
        employee_id = ids.get('Employee')
        coord_id = ids.get('Project-Cordinator')

        # Administrator permissions
        admin_perms = [
            ('ADMIN', 'VIEW_HIERARCHY'), ('ADMIN', 'CREATE_USERTYPE'), ('ADMIN', 'MANAGE_PERMISSIONS'),
            ('PROJ', 'VIEW_ALL'), ('PROJ', 'CREATE'), ('PROJ', 'EDIT'), ('PROJ', 'DELETE'), ('PROJ', 'ASSIGN_COORD'),
            ('TASK', 'VIEW'), ('TASK', 'CREATE'), ('TASK', 'ASSIGN'), ('TASK', 'EDIT'),
            ('TEAM', 'VIEW'), ('TEAM', 'ADD_MEMBER'), ('TEAM', 'REMOVE_MEMBER'), ('TEAM', 'MANAGE'),
            ('REP', 'VIEW'), ('REP', 'APPROVE'), ('REP', 'REJECT')
        ]
        seed_perms(admin_id, admin_perms)
            
        # Employee permissions
        employee_perms = [
            ('PROJ', 'VIEW_ALL'), ('TASK', 'VIEW'), ('REP', 'VIEW')
        ]
        seed_perms(employee_id, employee_perms)

        # Project Coordinator permissions
        coord_perms = [
            ('PROJ', 'VIEW_ALL'), ('PROJ', 'EDIT'), ('TASK', 'VIEW'), ('TASK', 'CREATE'), ('TASK', 'ASSIGN'), ('TASK', 'EDIT'),
            ('TEAM', 'VIEW'), ('TEAM', 'ADD_MEMBER'), ('REP', 'VIEW'), ('REP', 'APPROVE')
        ]
        seed_perms(coord_id, coord_perms)

        conn.commit()
        print("[OK] Database initialized successfully (verified schema)!")

    except Exception as e:
        print(f"[ERROR] Database initialization failed: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()


def migrate_db():
    """Add new columns without wiping existing data"""

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Enable foreign keys in SQLite
        cursor.execute("PRAGMA foreign_keys = ON")

        # List of columns to add (table, column, col_type)
        columns_to_add = [
            ("users", "phone", "TEXT"),
            ("users", "department", "TEXT"),
            ("users", "bio", "TEXT"),
            ("users", "avatar_url", "TEXT"),
            ("users", "status", "TEXT DEFAULT 'Active'"),
            ("projects", "completed_at", "TIMESTAMP"),
            ("projects", "reporting_time", "TIME"),
        ]

        for table, column, col_type in columns_to_add:
            try:
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
            except Exception as e:
                if "duplicate column name" in str(
                        e).lower() or "already exists" in str(e).lower():
                    pass  # Column already exists, skip
                else:
                    raise

        # Add usertypes description column
        try:
            cursor.execute("ALTER TABLE usertypes ADD COLUMN description TEXT")
        except Exception:
            pass

        # Create usertype_permissions table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usertype_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usertype_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                action TEXT NOT NULL,
                granted BOOLEAN DEFAULT 0,
                FOREIGN KEY (usertype_id) REFERENCES usertypes(id) ON DELETE CASCADE,
                UNIQUE(usertype_id, module, action)
            )
        ''')

        # Add daily_task_reports new columns if missing to support approvals and time tracking
        dtr_columns = [("daily_task_reports", "user_id", "INTEGER"),
                       ("daily_task_reports", "task_id", "INTEGER"),
                       ("daily_task_reports", "work_description", "TEXT"),
                       ("daily_task_reports", "time_spent", "REAL"),
                       ("daily_task_reports", "status", "TEXT"),
                       ("daily_task_reports", "blocker", "TEXT"),
                       ("daily_task_reports", "approval_status",
                        "TEXT DEFAULT 'pending'"),
                       ("daily_task_reports", "reviewed_by", "INTEGER"),
                       ("daily_task_reports", "review_comment", "TEXT")]

        for table, column, col_type in dtr_columns:
            try:
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
            except Exception as e:
                if "duplicate column name" in str(
                        e).lower() or "already exists" in str(e).lower():
                    pass
                else:
                    # If table doesn't exist yet, skip silently
                    if "no such table" in str(e).lower():
                        pass
                    else:
                        raise

        # If user_id is missing but employee_id exists, backfill user_id
        try:
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='daily_task_reports'"
            )
            if cursor.fetchone():
                # Add user_id if not present (safeguard)
                # Backfill where possible
                try:
                    cursor.execute('PRAGMA table_info(daily_task_reports)')
                    cols = [r[1] for r in cursor.fetchall()]
                    if 'user_id' in cols and 'employee_id' in cols:
                        cursor.execute(
                            'UPDATE daily_task_reports SET user_id = employee_id WHERE user_id IS NULL'
                        )
                except Exception:
                    pass
        except Exception:
            pass

        conn.commit()
        print("[OK] Database migration completed!")

    except Exception as e:
        print(f"[ERROR] Database migration failed: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()


def init_daily_report_module():
    """Ensure Daily Task Reporting tables exist with correct schema (non-destructive)"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")

        # 1. Daily Task Reports Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS daily_task_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                task_id INTEGER NOT NULL,
                project_id INTEGER NOT NULL,
                report_date DATE NOT NULL,
                work_description TEXT,
                result_of_effort TEXT,
                remarks TEXT,
                communication_email TEXT,
                communication_phone TEXT,
                task_assigned_by_id INTEGER,
                time_spent REAL DEFAULT 0,
                status TEXT DEFAULT 'In Progress',
                blocker TEXT,
                approval_status TEXT DEFAULT 'pending', -- pending, approved, rejected
                reviewed_by INTEGER,
                review_comment TEXT,
                is_locked INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (task_id) REFERENCES tasks(id),
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (reviewed_by) REFERENCES users(id)
            )
        ''')

        # 2. Report Comments Table (Optional/Advanced)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS report_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                commenter_id INTEGER NOT NULL,
                comment TEXT NOT NULL,
                internal BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (report_id) REFERENCES daily_task_reports(id) ON DELETE CASCADE,
                FOREIGN KEY (commenter_id) REFERENCES users(id)
            )
        ''')

        # Audit logs for Super Admin actions on reports
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id INTEGER,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (actor_id) REFERENCES users(id)
            )
        ''')

        # Ensure columns exist if table was already there (Migration check)
        try:
            cursor.execute(
                "ALTER TABLE daily_task_reports ADD COLUMN blocker TEXT")
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE daily_task_reports ADD COLUMN result_of_effort TEXT"
            )
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE daily_task_reports ADD COLUMN remarks TEXT")
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE daily_task_reports ADD COLUMN communication_email TEXT"
            )
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE daily_task_reports ADD COLUMN communication_phone TEXT"
            )
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE daily_task_reports ADD COLUMN task_assigned_by_id INTEGER"
            )
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE daily_task_reports ADD COLUMN is_locked INTEGER DEFAULT 0"
            )
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE daily_task_reports ADD COLUMN communication_details TEXT"
            )
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE daily_task_reports ADD COLUMN employee_id INTEGER"
            )
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE daily_task_reports ADD COLUMN task_title TEXT")
        except Exception:
            pass
        try:
            cursor.execute(
                "ALTER TABLE daily_task_reports ADD COLUMN status TEXT DEFAULT 'In Progress'"
            )
        except Exception:
            pass

        conn.commit()
        print("[OK] Daily Report Module Initialized")
    except Exception as e:
        print(f"[ERROR] Init Daily Report Module failed: {e}")
    finally:
        if conn:
            conn.close()


# Initialize module on startup
init_daily_report_module()


def validate_password_complexity(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter."

    if len(re.findall(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|]', password)) < 2:
        return False, "Password must contain at least two special characters."

    return True, "Password is valid."


def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("is_authenticated"):
            g.current_user_id = session.get("user_id")
            g.current_user_type = session.get("user_type", "employee")
            return f(*args, **kwargs)

        if request.is_json:
            return jsonify({"error": "Authentication required"}), 401

        return redirect("/login")

    return decorated_function


def admin_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("is_authenticated") and session.get(
                "user_type") == "admin":
            g.current_user_id = session.get("user_id")
            return f(*args, **kwargs)

        if request.is_json:
            return jsonify({"error": "Admin access required"}), 403

        return redirect("/login")

    return decorated_function


def employee_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("is_authenticated") and session.get(
                "user_type") == "employee":
            g.current_user_id = session.get("user_id")
            return f(*args, **kwargs)

        if request.is_json:
            return jsonify({"error": "Employee access required"}), 403

        return redirect("/login")

    return decorated_function


def get_current_user_id():
    return session.get("user_id")


@app.before_request
def debug_session():
    print("SESSION:", dict(session))


@app.route("/")
def index():
    return render_template("login.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/admin-dashboard")
def admin_dashboard():
    if not session.get("is_authenticated") or session.get(
            "user_type") != "admin":
        return redirect(url_for("login"))

    return render_template("admin-dashboard.html",
                           username=session.get("username"))


@app.route("/employee-dashboard")
@employee_required
def employee_dashboard():
    return render_template("employee-dashboard.html")


@app.route("/super-admin-dashboard")
@app.route("/admin/daily-reports")
@admin_required
def super_admin_dashboard():
    """Super Admin Daily Reports Dashboard"""
    return render_template("super-admin-dashboard.html")


@app.route('/admin/projects/<int:project_id>')
@login_required
def admin_project_detail(project_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Project basic info + creator
        cursor.execute(
            '''
            SELECT p.*, u.username as creator_name
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            WHERE p.id = ?
        ''', (project_id, ))
        project = cursor.fetchone()
        if not project:
            conn.close()
            return "Project not found", 404

        project_dict = dict(project)

        # Team members
        cursor.execute(
            '''
            SELECT u.id, u.username, u.email, ut.user_role
            FROM project_assignments pa
            JOIN users u ON pa.user_id = u.id
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            WHERE pa.project_id = ?
        ''', (project_id, ))
        members = [dict(r) for r in cursor.fetchall()]

        # Tasks for this project
        cursor.execute(
            '''
            SELECT t.id, t.title, t.status, t.assigned_to_id, u.username as assigned_to
            FROM tasks t
            LEFT JOIN users u ON t.assigned_to_id = u.id
            WHERE t.project_id = ?
            ORDER BY t.updated_at DESC
        ''', (project_id, ))
        tasks = [dict(r) for r in cursor.fetchall()]

        # Activities grouped by user for this project
        cursor.execute(
            '''
            SELECT a.user_id, u.username, COUNT(a.id) as activity_count
            FROM activities a
            LEFT JOIN users u ON a.user_id = u.id
            WHERE a.project_id = ?
            GROUP BY a.user_id, u.username
            ORDER BY activity_count DESC
        ''', (project_id, ))
        activities_by_user = {r['user_id']: dict(r) for r in cursor.fetchall()}

        # For each member, gather metrics (tasks assigned/completed and other projects)
        member_details = []
        for m in members:
            uid = m['id']
            cursor.execute(
                "SELECT COUNT(*) as total, SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completed FROM tasks WHERE project_id = ? AND assigned_to_id = ?",
                (project_id, uid))
            tcounts = cursor.fetchone()

            cursor.execute(
                '''
                SELECT COUNT(DISTINCT pa.project_id) as projects_count
                FROM project_assignments pa
                JOIN projects p ON pa.project_id = p.id
                WHERE pa.user_id = ? AND pa.project_id != ?
            ''', (uid, project_id))
            proj_cnt = cursor.fetchone()

            member_details.append({
                'id':
                uid,
                'username':
                m.get('username'),
                'email':
                m.get('email'),
                'role':
                m.get('user_role'),
                'tasks_total':
                tcounts['total'] or 0,
                'tasks_completed':
                tcounts['completed'] or 0,
                'other_projects':
                proj_cnt['projects_count'] or 0,
                'activities_count':
                activities_by_user.get(uid, {}).get('activity_count', 0)
            })

        conn.close()

        return render_template('project-detail.html',
                               project=project_dict,
                               members=member_details,
                               tasks=tasks)
    except Exception as e:
        logger.exception('Error loading project detail')
        return str(e), 500


@app.route('/admin/users/<int:user_id>')
@login_required
def admin_user_detail(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT u.id, u.username, u.email, u.phone, u.department, u.bio, u.user_type_id, ut.user_role
            FROM users u
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            WHERE u.id = ?
        ''', (user_id, ))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return "User not found", 404

        user_dict = dict(user)

        # 1. Direct Permissions
        cursor.execute('SELECT module, action, granted FROM user_permissions WHERE user_id = ?', (user_id,))
        direct_perms = cursor.fetchall()

        # 2. Role Permissions
        cursor.execute('SELECT module, action, granted FROM usertype_permissions WHERE usertype_id = ?', (user_dict['user_type_id'],))
        role_perms = cursor.fetchall()

        # Merge
        permissions = {}
        for p in role_perms:
            if p['module'] not in permissions: permissions[p['module']] = {}
            permissions[p['module']][p['action']] = bool(p['granted'])
        for p in direct_perms:
            if p['module'] not in permissions: permissions[p['module']] = {}
            permissions[p['module']][p['action']] = bool(p['granted'])
        
        user_dict['permissions'] = permissions

        # Projects the user is assigned to
        cursor.execute(
            '''
            SELECT p.id, p.title, p.status
            FROM project_assignments pa
            JOIN projects p ON pa.project_id = p.id
            WHERE pa.user_id = ?
        ''', (user_id, ))
        projects = [dict(r) for r in cursor.fetchall()]

        # Tasks assigned to the user
        cursor.execute(
            '''
            SELECT t.id, t.title, t.status, p.title as project_title
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            WHERE t.assigned_to_id = ?
            ORDER BY t.updated_at DESC
        ''', (user_id, ))
        tasks = [dict(r) for r in cursor.fetchall()]

        # Recent activities
        cursor.execute(
            '''
            SELECT a.id, a.activity_type, a.description, a.project_id, a.task_id, a.created_at
            FROM activities a
            WHERE a.user_id = ?
            ORDER BY a.created_at DESC
            LIMIT 200
        ''', (user_id, ))
        activities = [dict(r) for r in cursor.fetchall()]

        conn.close()

        return render_template('user-detail.html',
                               user=user_dict,
                               projects=projects,
                               tasks=tasks,
                               activities=activities)
    except Exception as e:
        logger.exception('Error loading user detail')
        return str(e), 500


@app.route("/api/admin/login/step1", methods=["POST"])
def login_step1():
    data = request.get_json() or {}
    identifier = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    client_ip = get_client_ip()
    if is_ip_blocked(client_ip):
        return jsonify({"error": "Too many failed login attempts. Try again later."}), 429

    if not identifier or not password:
        register_failed_login(client_ip)
        return jsonify({"error": "All fields are required."}), 400

    # Support login by either admin email or reserved "super admin" username
    admin_identifier_ok = False
    if "@" in identifier:
        # Validate basic email format
        if "." not in identifier.split("@")[-1]:
            return jsonify({"error": "Invalid email format."}), 400
        admin_identifier_ok = (identifier == ADMIN_EMAIL)
    else:
        # Allow reserved username variants (case-insensitive)
        normalized = identifier.replace("_", " ").strip()
        if normalized in ("super admin", "admin", "superadmin"):
            admin_identifier_ok = True
        else:
            admin_identifier_ok = False

    if not admin_identifier_ok:
        register_failed_login(client_ip)
        return jsonify({"error": "Email or username not found."}), 400

    if password != ADMIN_PASSWORD:
        register_failed_login(client_ip)
        return jsonify({"error": "Incorrect password."}), 400

    # Successful step1 -> reset attempts
    reset_failed_login(client_ip)

    return jsonify({
        "message": "OTP has been sent to your registered email (simulated).",
        "admin_id": 0,
        "success": True,
    }), 200

@app.route("/api/admin/login/step2", methods=["POST"])
def login_step2():
    data = request.get_json() or {}
    otp = data.get("otp") or ""

    client_ip = get_client_ip()
    if is_ip_blocked(client_ip):
        return jsonify({"error": "Too many failed login attempts. Try again later."}), 429

    if otp != ADMIN_OTP:
        register_failed_login(client_ip)
        return jsonify({"error": "Invalid OTP"}), 400

    # Successful admin login - reset failures
    reset_failed_login(client_ip)

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Try to find an existing user by admin email (case-insensitive)
        cur.execute("SELECT id FROM users WHERE lower(email) = ?", (ADMIN_EMAIL.lower(),))
        row = cur.fetchone()

        if row:
            admin_id = row['id']
        else:
            # Ensure there is an "Administrator" usertype
            cur.execute("SELECT id FROM usertypes WHERE lower(user_role) LIKE ?", ('%admin%',))
            ut = cur.fetchone()
            if ut:
                utid = ut['id']
            else:
                cur.execute("INSERT OR IGNORE INTO usertypes (user_role, created_at) VALUES (?, CURRENT_TIMESTAMP)", ('Administrator',))
                cur.execute("SELECT id FROM usertypes WHERE user_role = ?", ('Administrator',))
                utid = cur.fetchone()['id']

            # Create the admin user (username = Super Admin) with a safe hashed password
            from werkzeug.security import generate_password_hash
            hashed = generate_password_hash(ADMIN_PASSWORD)
            cur.execute(
                "INSERT OR IGNORE INTO users (username, email, password, user_type_id, granted, is_system, created_at) VALUES (?, ?, ?, ?, 1, 1, CURRENT_TIMESTAMP)",
                ('Super Admin', ADMIN_EMAIL, hashed, utid)
            )
            cur.execute("SELECT id FROM users WHERE username = ?", ('Super Admin',))
            admin_id = cur.fetchone()['id']

        # Establish session using the real DB user id
        session.clear()
        session.permanent = True
        session["is_authenticated"] = True
        session["user_id"] = admin_id
        session["username"] = "Super Admin"
        session["user_type"] = "admin"
        session["admin"] = True 

        return jsonify({"success": True}), 200

    except Exception as e:
        logger.exception("login_step2 failure")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        try:
            conn.close()
        except Exception:
            pass

@app.route("/api/admin/dashboard/overdue-items", methods=["GET"])
@admin_required
def get_overdue_items():
    """Get all overdue items for admin"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Overdue tasks
        cursor.execute('''
            SELECT t.id, t.title, t.description, t.status, t.priority, 
                   t.deadline, t.project_id, p.title as project_name,
                   t.assigned_to_id, u.username as assigned_to_name,
                   t.created_by_id, uc.username as created_by_name,
                   t.created_at, t.approval_status,
                   CURRENT_DATE - t.deadline as days_overdue
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            LEFT JOIN users u ON t.assigned_to_id = u.id
            LEFT JOIN users uc ON t.created_by_id = uc.id
            WHERE t.deadline < CURRENT_DATE 
            AND t.status != 'Completed'
            AND t.status != 'Overdue'
            ORDER BY t.deadline ASC
        ''')
        overdue_tasks = cursor.fetchall()

        # Overdue projects
        cursor.execute('''
            SELECT p.id, p.title, p.description, p.status, p.progress, 
                   p.deadline, p.created_by_id, u.username as creator_name,
                   p.created_at,
                   CURRENT_DATE - p.deadline as days_overdue
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            WHERE p.deadline < CURRENT_DATE 
            AND p.status != 'Completed'
            ORDER BY p.deadline ASC
        ''')
        overdue_projects = cursor.fetchall()

        conn.close()

        return jsonify({
            "overdue_tasks": [dict(row) for row in overdue_tasks],
            "overdue_projects": [dict(row) for row in overdue_projects],
            "total_overdue_tasks":
            len(overdue_tasks),
            "total_overdue_projects":
            len(overdue_projects)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/daily-report', methods=['POST'])
@login_required
def create_daily_report():
    """Submit a daily report.
    Rules:
    - One report per task per day.
    - Hours between 0 and 24.
    - Admins can submit on behalf of employees.
    """
    try:
        current_user_id = get_current_user_id()
        data = request.get_json() or {}

        # Check if admin is submitting on behalf of someone
        report_user_id = data.get(
            'user_id')  # Admin can specify who the report is for

        # Get current user's role
        conn = get_db_connection()
        cursor = conn.cursor()
        current_user_role_row = cursor.execute(
            '''
            SELECT ut.user_role FROM users u 
            JOIN usertypes ut ON u.user_type_id = ut.id 
            WHERE u.id = ?
        ''', (current_user_id, )).fetchone()
        current_role = (current_user_role_row['user_role']
                        if current_user_role_row else 'employee').lower()

        # If user_id is specified, only admins/super-admins can do this
        if report_user_id and report_user_id != current_user_id:
            if current_role not in ['admin', 'super admin']:
                conn.close()
                return jsonify({
                    'error':
                    'Only admins can submit reports for other users'
                }), 403
            user_id = report_user_id
        else:
            user_id = current_user_id

        task_id = data.get('task_id')
        project_id = data.get('project_id')
        report_date = data.get('report_date') or datetime.now().strftime(
            '%Y-%m-%d')
        work_description = data.get('work_description') or data.get(
            'result_of_effort')
        time_spent_str = data.get('time_spent', 0)
        status = data.get('status', 'In Progress')
        blocker = data.get('blocker', '')
        communication_email = data.get('communication_email') or data.get(
            'email') or ''
        communication_phone = data.get('communication_phone') or data.get(
            'phone') or ''
        result_of_effort = data.get(
            'result_of_effort') or work_description or ''
        remarks = data.get('remarks') or ''

        if not task_id or not work_description:
            conn.close()
            return jsonify({'error': 'Task and Description are required'}), 400

        try:
            time_spent = float(time_spent_str)
            if not (0 <= time_spent <= 24):
                raise ValueError
        except (ValueError, TypeError):
            conn.close()
            return jsonify({'error':
                            'Hours spent must be between 0 and 24'}), 400

        # Verify task existence
        cursor.execute(
            "SELECT id, project_id, assigned_to_id FROM tasks WHERE id = ?",
            (task_id, ))
        task = cursor.fetchone()
        if not task:
            conn.close()
            return jsonify({'error': 'Task not found'}), 404

        # Allow admins to report on any task, but employees only on their assigned tasks
        # OR if they created the task (only for non-admin users)
        if current_role == 'employee' and user_id == current_user_id:
            if task['assigned_to_id'] != user_id and task.get(
                    'created_by_id') != user_id:
                conn.close()
                return jsonify({
                    'error':
                    'You can only report on your assigned or created tasks'
                }), 403

        # Use project_id from task if not provided or mismatch
        real_project_id = project_id or task['project_id']

        # Check duplicate
        cursor.execute(
            "SELECT id FROM daily_task_reports WHERE user_id = ? AND task_id = ? AND report_date = ?",
            (user_id, task_id, report_date))
        if cursor.fetchone():
            conn.close()
            return jsonify({
                'error':
                'A report for this task already exists for this date.'
            }), 409

        communication_details = json.dumps({
            'email': communication_email,
            'phone': communication_phone
        })
        cursor.execute(
            '''
            INSERT INTO daily_task_reports 
            (user_id, task_id, project_id, report_date, work_description, result_of_effort, remarks, communication_email, communication_phone, communication_details, time_spent, status, blocker, task_assigned_by_id, approval_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        ''', (user_id, task_id, real_project_id, report_date, work_description,
              result_of_effort, remarks, communication_email,
              communication_phone, communication_details, time_spent, status,
              blocker, data.get('task_assigned_by_id')))

        report_id = cursor.lastrowid
        conn.commit()

        log_activity(user_id,
                     'daily_report_created',
                     f'Submitted daily report for task {task_id}',
                     real_project_id,
                     task_id=task_id)
        try:
            conn2 = get_db_connection()
            cur2 = conn2.cursor()
            cur2.execute(
                'INSERT INTO audit_logs (actor_id, action, target_type, target_id, details) VALUES (?,?,?,?,?)',
                (user_id, 'create_report', 'daily_report', report_id,
                 json.dumps({
                     'task_id': task_id,
                     'project_id': real_project_id
                 })))
            conn2.commit()
        except Exception:
            pass
        finally:
            try:
                conn2.close()
            except Exception:
                pass

        conn.close()
        return jsonify({'success': True, 'id': report_id}), 201

    except Exception as e:
        logger.exception('create_daily_report failed')
        return jsonify({'error': str(e)}), 500


@app.route('/api/daily-reports', methods=['GET'])
@login_required
def list_daily_reports():
    """List daily reports with filters and pagination. Role-based visibility."""
    try:
        user_id = get_current_user_id()
        user_type = getattr(g, 'current_user_type', session.get('user_type'))

        # filters
        start = request.args.get('start_date')
        end = request.args.get('end_date')
        employee = request.args.get('employee_id')
        project = request.args.get('project_id')
        task = request.args.get('task_id')
        status = request.args.get('status')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))

        params = []
        where = ['1=1']

        if start:
            where.append('report_date >= ?')
            params.append(start)
        if end:
            where.append('report_date <= ?')
            params.append(end)
        if employee:
            where.append('d.user_id = ?')
            params.append(employee)
        if project:
            where.append('d.project_id = ?')
            params.append(project)
        if task:
            where.append('d.task_id = ?')
            params.append(task)
        if status:
            where.append('d.status = ?')
            params.append(status)

        # Role-based access: employees see only their reports
        if user_type == 'employee' or user_type is None:
            where.append('d.user_id = ?')
            params.append(user_id)

        where_sql = ' AND '.join(where)
        offset = (page - 1) * per_page

        conn = get_db_connection()
        cursor = conn.cursor()
        query = f'''
            SELECT d.*, u.username AS employee_name, p.title AS project_title, t.title AS task_title, reviewer.username AS reviewer_name
            FROM daily_task_reports d
            LEFT JOIN users u ON d.user_id = u.id
            LEFT JOIN projects p ON d.project_id = p.id
            LEFT JOIN tasks t ON d.task_id = t.id
            LEFT JOIN users reviewer ON d.reviewed_by = reviewer.id
            WHERE {where_sql}
            ORDER BY d.report_date DESC, d.created_at DESC
            LIMIT ? OFFSET ?
        '''
        params.extend([per_page, offset])
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]

        # total count
        count_q = f'SELECT COUNT(*) as cnt FROM daily_task_reports d WHERE {where_sql}'
        cursor.execute(count_q, params[:-2])
        total = cursor.fetchone()['cnt']
        conn.close()

        return jsonify({
            'data': rows,
            'page': page,
            'per_page': per_page,
            'total': total
        }), 200
    except Exception as e:
        logger.exception('list_daily_reports failed')
        return jsonify({'error': str(e)}), 500


@app.route('/api/daily-report/<int:report_id>', methods=['PUT'])
@admin_required
def edit_daily_report(report_id):
    """Edit a report (admin/superadmin)."""
    try:
        data = request.get_json() or {}
        user_type = getattr(g, 'current_user_type', session.get('user_type'))
        is_admin = session.get('admin') or user_type == 'admin'

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM daily_task_reports WHERE id = ?',
                       (report_id, ))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Report not found'}), 404

        if row['approval_status'] == 'approved' and not is_admin:
            conn.close()
            return jsonify({'error': 'Approved reports are locked'}), 403

        updates = []
        params = []
        if 'work_description' in data:
            updates.append('work_description = ?')
            params.append(data['work_description'])
        if 'time_spent' in data:
            try:
                ts = float(data['time_spent'])
            except Exception:
                conn.close()
                return jsonify({'error': 'time_spent must be a number'}), 400
            if ts < 0 or ts > 24:
                conn.close()
                return jsonify(
                    {'error': 'time_spent must be between 0 and 24'}), 400
            updates.append('time_spent = ?')
            params.append(ts)
        if 'status' in data:
            if data['status'] not in ('In Progress', 'Completed', 'Blocked'):
                conn.close()
                return jsonify({'error': 'Invalid status'}), 400
            updates.append('status = ?')
            params.append(data['status'])

        if not updates:
            conn.close()
            return jsonify({'error': 'Nothing to update'}), 400

        params.append(report_id)
        sql = 'UPDATE daily_task_reports SET ' + ', '.join(
            updates) + ', updated_at = CURRENT_TIMESTAMP WHERE id = ?'
        cursor.execute(sql, params)
        conn.commit()
        log_activity(get_current_user_id(), 'daily_report_edited',
                     f'Edited report {report_id}', row['project_id'])
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        logger.exception('edit_daily_report failed')
        return jsonify({'error': str(e)}), 500


@app.route('/api/daily-report/<int:report_id>/action', methods=['POST'])
@login_required
def action_daily_report(report_id):
    """Approve or reject a report. Admins only."""
    try:
        data = request.get_json() or {}
        action = data.get('action')
        comment = data.get('comment', '')
        user_id = get_current_user_id()
        user_type = getattr(g, 'current_user_type', session.get('user_type'))
        is_admin = session.get('admin') or user_type == 'admin'

        if action not in ('approve', 'reject'):
            return jsonify({'error': 'Invalid action'}), 400

        if not is_admin:
            return jsonify({'error': 'Admin access required'}), 403

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM daily_task_reports WHERE id = ?',
                       (report_id, ))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Report not found'}), 404

        new_status = 'approved' if action == 'approve' else 'rejected'
        cursor.execute(
            'UPDATE daily_task_reports SET approval_status = ?, reviewed_by = ?, review_comment = ?, updated_at = CURRENT_TIMESTAMP, is_locked = CASE WHEN ? = \'approved\' THEN 1 ELSE is_locked END WHERE id = ?',
            (new_status, user_id, comment, new_status, report_id))
        conn.commit()
        log_activity(user_id, 'daily_report_reviewed',
                     f'{new_status} report {report_id}', row['project_id'])
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        logger.exception('action_daily_report failed')
        return jsonify({'error': str(e)}), 500


@app.route('/api/daily-report/<int:report_id>', methods=['DELETE'])
@admin_required
def delete_daily_report(report_id):
    """Delete report (super admin only)."""
    try:
        user_type = getattr(g, 'current_user_type', session.get('user_type'))
        if not (session.get('admin') or user_type == 'admin'):
            return jsonify({'error':
                            'Only admin can delete reports'}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT project_id FROM daily_task_reports WHERE id = ?',
            (report_id, ))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Report not found'}), 404
        cursor.execute('DELETE FROM report_comments WHERE report_id = ?',
                       (report_id, ))
        cursor.execute('DELETE FROM daily_task_reports WHERE id = ?',
                       (report_id, ))
        conn.commit()
        log_activity(get_current_user_id(), 'daily_report_deleted',
                     f'deleted report {report_id}', row['project_id'])
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        logger.exception('delete_daily_report failed')
        return jsonify({'error': str(e)}), 500


@app.route('/api/daily-report/<int:report_id>/comments', methods=['POST'])
@login_required
def add_report_comment(report_id):
    try:
        data = request.get_json() or {}
        comment = data.get('comment')
        internal = bool(data.get('internal', False))
        if not comment:
            return jsonify({'error': 'comment is required'}), 400
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM daily_task_reports WHERE id = ?',
                       (report_id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Report not found'}), 404
        cursor.execute(
            'INSERT INTO report_comments (report_id, commenter_id, comment, internal, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)',
            (report_id, user_id, comment, 1 if internal else 0))
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 201
    except Exception as e:
        logger.exception('add_report_comment failed')
        return jsonify({'error': str(e)}), 500


@app.route('/api/daily-reports/export', methods=['GET'])
@admin_required
def export_daily_reports():
    """Export filtered reports to CSV (admin/superadmin)."""
    try:
        import csv
        from io import StringIO

        params = []
        where = ['1=1']
        start = request.args.get('start_date')
        end = request.args.get('end_date')
        employee = request.args.get('employee_id')
        project = request.args.get('project_id')
        task = request.args.get('task_id')

        if start:
            where.append('report_date >= ?')
            params.append(start)
        if end:
            where.append('report_date <= ?')
            params.append(end)
        if employee:
            where.append('d.user_id = ?')
            params.append(employee)
        if project:
            where.append('d.project_id = ?')
            params.append(project)
        if task:
            where.append('d.task_id = ?')
            params.append(task)

        where_sql = ' AND '.join(where)
        conn = get_db_connection()
        cursor = conn.cursor()
        query = f"SELECT d.*, u.username as employee_name, p.title as project_title, t.title as task_title FROM daily_task_reports d LEFT JOIN users u ON d.user_id = u.id LEFT JOIN projects p ON d.project_id = p.id LEFT JOIN tasks t ON d.task_id = t.id WHERE {where_sql} ORDER BY d.report_date DESC"
        cursor.execute(query, params)
        rows = cursor.fetchall()

        si = StringIO()
        cw = csv.writer(si)
        cw.writerow([
            'id', 'report_date', 'employee', 'project', 'task',
            'work_description', 'time_spent', 'status', 'approval_status',
            'reviewed_by', 'review_comment', 'created_at'
        ])
        for r in rows:
            cw.writerow([
                r['id'], r['report_date'], r['employee_name'],
                r['project_title'], r['task_title'], r['work_description'],
                r['time_spent'], r['status'], r['approval_status'],
                r['reviewed_by'], r['review_comment'], r['created_at']
            ])
        output = si.getvalue()
        conn.close()
        return app.response_class(output,
                                  mimetype='text/csv',
                                  headers={
                                      "Content-Disposition":
                                      "attachment;filename=daily_reports.csv"
                                  })
    except Exception as e:
        logger.exception('export_daily_reports failed')
        return jsonify({'error': str(e)}), 500


@app.route("/api/admin/dashboard/completed-outcomes", methods=["GET"])
@admin_required
def get_completed_outcomes():
    """Get all completed projects (outcomes)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT p.id, p.title, p.description, p.status, p.progress, 
                   p.deadline, p.created_by_id, u.username as creator_name,
                   p.created_at, p.completed_at,
                   COUNT(DISTINCT t.id) as total_tasks,
                   COUNT(DISTINCT CASE WHEN t.status = 'Completed' THEN t.id END) as completed_tasks,
                   COUNT(DISTINCT m.id) as total_milestones,
                   COUNT(DISTINCT CASE WHEN m.status = 'Completed' THEN m.id END) as completed_milestones
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            LEFT JOIN tasks t ON p.id = t.project_id
            LEFT JOIN milestones m ON p.id = m.project_id
            WHERE p.status = 'Completed'
            GROUP BY p.id, u.username
            ORDER BY p.completed_at DESC
        ''')

        completed_projects = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in completed_projects]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/dashboard/recent-actions", methods=["GET"])
@admin_required
def get_recent_actions():
    """Get recent actions from all employees"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT a.id, a.activity_type, a.description, a.created_at,
                   u.username, u.email, u.user_type_id, ut.user_role,
                   p.title as project_title, t.title as task_title,
                   m.title as milestone_title,
                   CASE 
                     WHEN a.activity_type = 'project_created' THEN 'fas fa-folder-plus'
                     WHEN a.activity_type = 'task_created' THEN 'fas fa-tasks'
                     WHEN a.activity_type = 'task_completed' THEN 'fas fa-check-circle'
                     WHEN a.activity_type = 'milestone_created' THEN 'fas fa-flag'
                     WHEN a.activity_type = 'milestone_completed' THEN 'fas fa-flag-checkered'
                     WHEN a.activity_type = 'document_uploaded' THEN 'fas fa-file-upload'
                     WHEN a.activity_type = 'document_deleted' THEN 'fas fa-file-times'
                     ELSE 'fas fa-history'
                   END as icon_class
            FROM activities a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            LEFT JOIN projects p ON a.project_id = p.id
            LEFT JOIN tasks t ON a.task_id = t.id
            LEFT JOIN milestones m ON a.milestone_id = m.id
            ORDER BY a.created_at DESC
            LIMIT 50
        ''')

        activities = cursor.fetchall()
        conn.close()

        result = []
        for row in activities:
            result.append(dict(row))

        return jsonify(result), 200
    except Exception as e:
        print(f"[ERROR] /api/admin/dashboard/recent-actions failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/dashboard/activities", methods=["GET"])
@admin_required
def get_admin_activities():
    """Get all activities for admin dashboard"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT a.id, a.activity_type, a.description, a.created_at,
                   u.username, u.email, p.title as project_title,
                   t.title as task_title, m.title as milestone_title
            FROM activities a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN projects p ON a.project_id = p.id
            LEFT JOIN tasks t ON a.task_id = t.id
            LEFT JOIN milestones m ON a.milestone_id = m.id
            ORDER BY a.created_at DESC
            LIMIT 100
        ''')

        activities = cursor.fetchall()
        conn.close()

        result = []
        for row in activities:
            result.append(dict(row))

        return jsonify(result), 200
    except Exception as e:
        print(f"[ERROR] /api/admin/dashboard/activities failed: {str(e)}")
        return jsonify({"error": str(e)}), 500




@app.route('/api/admin/daily-reports', methods=['GET'])
@app.route('/api/admin/daily_reports', methods=['GET'])
@admin_required
def admin_get_daily_reports():
    """Admin: Fetch daily task reports.
    Supports both hyphen and underscore formats used by different parts of the frontend.
    """
    return list_daily_reports_api()


@app.route('/api/daily-report/submit', methods=['POST'])
@app.route('/api/admin/daily_reports', methods=['POST'])
@login_required
def create_daily_report_api():
    """Submit a daily report.
    Supports both Employee (task_id, project_id, etc.) 
    and Admin (date, employee_id, task, etc.) formats.
    """
    try:
        user_id = get_current_user_id()
        data = request.get_json() or {}

        # Determine format and map fields
        # Admin format uses 'date', 'employee_id', 'task', etc.
        report_date = data.get('report_date') or data.get(
            'date') or datetime.now().strftime('%Y-%m-%d')
        target_user_id = data.get('employee_id') or user_id
        project_id = data.get('project_id')

        # Task identification
        task_id = data.get('task_id')

        # Descriptions
        description = data.get('work_description') or data.get(
            'task') or data.get('result', '')
        if data.get('remarks'):
            description += f"\nRemarks: {data.get('remarks')}"

        hours = data.get(
            'time_spent'
        ) or 8  # Default to 8 if not provided (admin format doesn't have it)
        status = data.get('status',
                          'Completed' if data.get('result') else 'In Progress')
        blocker = data.get('blocker', '')

        if not (project_id and description):
            return jsonify({
                'error':
                'Missing required fields (project_id and description)'
            }), 400

        try:
            hours = float(hours)
        except (ValueError, TypeError):
            hours = 0

        conn = get_db_connection()
        cur = conn.cursor()

        # If task_id is missing (admin format), try to find/create a dummy task or just leave it null
        # Actually, the schema might require task_id. Let's check.
        # If task_id is NULL, we might need to allow it in the DB.

        communication_email = data.get('communication_email') or data.get(
            'email') or ''
        communication_phone = data.get('communication_phone') or data.get(
            'phone') or ''
        communication_details = json.dumps({
            'email': communication_email,
            'phone': communication_phone
        }) if (communication_email or communication_phone) else ''
        result_of_effort = data.get('result_of_effort') or data.get(
            'result') or ''
        remarks = data.get('remarks') or ''

        cur.execute(
            '''
            INSERT INTO daily_task_reports (
                user_id, task_id, project_id, report_date, 
                work_description, time_spent, status, blocker,
                communication_email, communication_phone, communication_details, result_of_effort, remarks,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (target_user_id, task_id, project_id, report_date, description,
              hours, status, blocker, communication_email, communication_phone,
              communication_details, result_of_effort, remarks))

        conn.commit()
        new_id = cur.lastrowid
        conn.close()

        return jsonify({'success': True, 'id': new_id}), 201
    except Exception as e:
        logger.exception('Failed to create daily report')
        return jsonify({'error': str(e)}), 500


@app.route('/api/daily-reports', methods=['GET'])
@login_required
def list_daily_reports_api():
    """Get daily reports with filters.
    - Employee: Own reports.
    - Admin: Team reports (or all if not filtered).
    - Super Admin: All reports.
    """
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()

        # Get user role
        user = conn.execute('SELECT user_type_id FROM users WHERE id = ?',
                            (user_id, )).fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        role_row = conn.execute('SELECT user_role FROM usertypes WHERE id = ?',
                                (user['user_type_id'], )).fetchone()
        role = role_row['user_role'].lower() if role_row else 'employee'

        # Parse filters
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        project_id = request.args.get('project_id')
        employee_id = request.args.get('employee_id')
        status = request.args.get('status')
        approval_status = request.args.get('approval_status')

        query = '''
            SELECT d.*, 
                   u.username as employee_name, 
                   p.title as project_title,
                   t.title as task_title,
                   rev.username as reviewer_name
            FROM daily_task_reports d
            LEFT JOIN users u ON d.user_id = u.id
            LEFT JOIN projects p ON d.project_id = p.id
            LEFT JOIN tasks t ON d.task_id = t.id
            LEFT JOIN users rev ON d.reviewed_by = rev.id
            WHERE 1=1
        '''
        params = []

        # Role-based restriction
        if role == 'employee':
            query += ' AND d.user_id = ?'
            params.append(user_id)
        elif role == 'admin' or role == 'manager':
            # Admin can see all, or maybe filter by their projects?
            # For now, let's assume Admin sees all but usually filters.
            # If Employee ID filter is passed, apply it.
            pass
        # Super admin sees all

        if employee_id and role in ['admin', 'super admin', 'manager']:
            query += ' AND d.user_id = ?'
            params.append(employee_id)

        if date_from:
            query += ' AND d.report_date >= ?'
            params.append(date_from)
        if date_to:
            query += ' AND d.report_date <= ?'
            params.append(date_to)
        if project_id:
            query += ' AND d.project_id = ?'
            params.append(project_id)
        if status:
            query += ' AND d.status = ?'
            params.append(status)
        if approval_status:
            query += ' AND d.approval_status = ?'
            params.append(approval_status)

        query += ' ORDER BY d.report_date DESC, d.created_at DESC'

        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return jsonify([dict(r) for r in rows]), 200

    except Exception as e:
        logger.exception("Error listing daily reports")
        return jsonify({'error': str(e)}), 500


@app.route('/api/daily-report/<int:report_id>', methods=['PUT'])
@login_required
def update_daily_report(report_id):
    """Edit report.
    - Employee: Only if pending and (today or same day).
    - Super Admin: Always.
    """
    try:
        user_id = get_current_user_id()
        data = request.get_json()
        conn = get_db_connection()
        cur = conn.cursor()

        report = cur.execute('SELECT * FROM daily_task_reports WHERE id = ?',
                             (report_id, )).fetchone()
        if not report:
            conn.close()
            return jsonify({'error': 'Report not found'}), 404

        # Check permissions
        is_owner = (report['user_id'] == user_id)

        # Check role
        user_role_row = cur.execute(
            '''
            SELECT ut.user_role FROM users u 
            JOIN usertypes ut ON u.user_type_id = ut.id 
            WHERE u.id = ?
        ''', (user_id, )).fetchone()
        role = user_role_row['user_role'].lower(
        ) if user_role_row else 'employee'

        is_super_admin = (role == 'super admin')

        # Evaluate lock and owner permissions
        is_locked = bool(report.get('is_locked', 0))
        can_edit = False
        if is_super_admin and not is_locked:
            can_edit = True
        elif is_owner:
            # Allow edit if report was rejected (any day) OR same-day and not locked and not approved
            try:
                report_date = datetime.strptime(report['report_date'],
                                                '%Y-%m-%d').date()
            except Exception:
                report_date = None
            if report['approval_status'] == 'rejected':
                can_edit = True
            elif report_date and report_date == datetime.now().date(
            ) and not is_locked and report['approval_status'] != 'approved':
                can_edit = True

        if not can_edit:
            conn.close()
            return jsonify({'error':
                            'Permission denied or report locked'}), 403

        # Update fields
        fields = []
        params = []
        if 'work_description' in data:
            fields.append("work_description = ?")
            params.append(data['work_description'])
        if 'result_of_effort' in data:
            fields.append("result_of_effort = ?")
            params.append(data['result_of_effort'])
        if 'remarks' in data:
            fields.append("remarks = ?")
            params.append(data['remarks'])
        if 'communication_email' in data:
            fields.append("communication_email = ?")
            params.append(data['communication_email'])
        if 'communication_phone' in data:
            fields.append("communication_phone = ?")
            params.append(data['communication_phone'])
        if 'task_assigned_by_id' in data:
            fields.append("task_assigned_by_id = ?")
            params.append(data['task_assigned_by_id'])
        if 'time_spent' in data:
            fields.append("time_spent = ?")
            params.append(data['time_spent'])
        if 'status' in data:
            fields.append("status = ?")
            params.append(data['status'])
        if 'blocker' in data:
            fields.append("blocker = ?")
            params.append(data['blocker'])

        if fields:
            fields.append("updated_at = CURRENT_TIMESTAMP")
            query = f"UPDATE daily_task_reports SET {', '.join(fields)} WHERE id = ?"
            params.append(report_id)
            cur.execute(query, params)
            conn.commit()
            # Audit for super admin edits
            try:
                if is_super_admin:
                    cur.execute(
                        'INSERT INTO audit_logs (actor_id, action, target_type, target_id, details) VALUES (?,?,?,?,?)',
                        (user_id, 'edit_report', 'daily_report', report_id,
                         json.dumps(data)))
                    conn.commit()
            except Exception:
                conn.rollback()

        conn.close()
        return jsonify({'success': True}), 200

    except Exception as e:
        logger.exception("Error updating report")
        return jsonify({'error': str(e)}), 500


@app.route('/api/daily-report/<int:report_id>/action', methods=['POST'])
@app.route('/api/daily-reports/<int:report_id>/approve', methods=['POST'])
@app.route('/api/daily-reports/<int:report_id>/reject', methods=['POST'])
@login_required
def action_daily_report_api(report_id):
    """Approve or Reject a report.
    Supports multiple URL patterns used by the frontend.
    """
    try:
        user_id = get_current_user_id()
        data = request.get_json() or {}

        # Determine action from URL if not in body
        action = data.get('action')
        if not action:
            if '/approve' in request.path:
                action = 'approve'
            elif '/reject' in request.path:
                action = 'reject'

        comment = data.get('comment', '')

        if action not in ['approve', 'reject']:
            return jsonify({'error': 'Invalid action'}), 400

        conn = get_db_connection()
        cur = conn.cursor()

        # Check role
        user_role_row = cur.execute(
            '''
            SELECT ut.user_role FROM users u 
            JOIN usertypes ut ON u.user_type_id = ut.id 
            WHERE u.id = ?
        ''', (user_id, )).fetchone()
        role = user_role_row['user_role'].lower(
        ) if user_role_row else 'employee'

        if role not in ['admin', 'super admin', 'manager']:
            conn.close()
            return jsonify({'error': 'Permission denied'}), 403

        new_status = 'approved' if action == 'approve' else 'rejected'

        cur.execute(
            '''
            UPDATE daily_task_reports 
            SET approval_status = ?, reviewed_by = ?, review_comment = ?, updated_at = CURRENT_TIMESTAMP, is_locked = CASE WHEN ? = 'approved' THEN 1 ELSE is_locked END
            WHERE id = ?
        ''', (new_status, user_id, comment, new_status, report_id))

        conn.commit()
        try:
            cur.execute(
                'INSERT INTO audit_logs (actor_id, action, target_type, target_id, details) VALUES (?,?,?,?,?)',
                (user_id, f'{action}_report', 'daily_report', report_id,
                 comment or ''))
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            conn.close()

        return jsonify({'success': True, 'status': new_status}), 200

    except Exception as e:
        logger.exception("Error in report action")
        return jsonify({'error': str(e)}), 500


@app.route('/api/daily-report/<int:report_id>', methods=['DELETE'])
@login_required
def delete_daily_report_api(report_id):
    """Delete report (Super Admin only)."""
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cur = conn.cursor()

        # Check role
        user_role_row = cur.execute(
            '''
            SELECT ut.user_role FROM users u 
            JOIN usertypes ut ON u.user_type_id = ut.id 
            WHERE u.id = ?
        ''', (user_id, )).fetchone()
        role = user_role_row['user_role'].lower(
        ) if user_role_row else 'employee'

        if role != 'super admin':
            conn.close()
            return jsonify({'error':
                            'Only Super Admin can delete reports'}), 403

        cur.execute('DELETE FROM daily_task_reports WHERE id = ?',
                    (report_id, ))
        conn.commit()
        try:
            cur.execute(
                'INSERT INTO audit_logs (actor_id, action, target_type, target_id, details) VALUES (?,?,?,?,?)',
                (user_id, 'delete_report', 'daily_report', report_id,
                 'deleted by super admin'))
            conn.commit()
        except Exception:
            conn.rollback()
        finally:
            conn.close()

        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route("/api/projects/<int:project_id>/calculate-progress",
           methods=["GET"])
@login_required
def calculate_project_progress(project_id):
    """
    Calculate project progress based on: 
    - 70% weight:  Task completion rate
    - 30% weight: Milestone completion rate
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get task progress data
        cursor.execute(
            '''
            SELECT 
                COUNT(*) as total_tasks,
                SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                COALESCE(SUM(weightage), 0) as total_weightage,
                COALESCE(SUM(CASE WHEN status = 'Completed' THEN weightage ELSE 0 END), 0) as completed_weightage
            FROM tasks 
            WHERE project_id = ?
        ''', (project_id, ))
        task_data = cursor.fetchone()

        # Get milestone progress data
        cursor.execute(
            '''
            SELECT 
                COUNT(*) as total_milestones,
                SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completed_milestones,
                COALESCE(SUM(weightage), 0) as total_m_weightage,
                COALESCE(SUM(CASE WHEN status = 'Completed' THEN weightage ELSE 0 END), 0) as completed_m_weightage
            FROM milestones 
            WHERE project_id = ?
        ''', (project_id, ))
        milestone_data = cursor.fetchone()

        # Calculate weighted progress
        task_progress = 0
        if task_data['total_weightage'] and task_data['total_weightage'] > 0:
            task_progress = (task_data['completed_weightage'] /
                             task_data['total_weightage']) * 100

        milestone_progress = 0
        if milestone_data['total_m_weightage'] and milestone_data[
                'total_m_weightage'] > 0:
            milestone_progress = (milestone_data['completed_m_weightage'] /
                                  milestone_data['total_m_weightage']) * 100

        # Overall progress:  70% tasks + 30% milestones
        overall_progress = int((task_progress * 0.7) +
                               (milestone_progress * 0.3))

        # Update project progress in database
        cursor.execute(
            '''
            UPDATE projects 
            SET progress = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (overall_progress, project_id))

        # Record progress history
        cursor.execute(
            '''
            INSERT INTO progress_history (
                project_id, progress_percentage, 
                tasks_completed, total_tasks,
                milestones_completed, total_milestones
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (project_id, overall_progress, task_data['completed_tasks']
              or 0, task_data['total_tasks']
              or 0, milestone_data['completed_milestones']
              or 0, milestone_data['total_milestones'] or 0))

        conn.commit()

        return jsonify({
            "project_id":
            project_id,
            "progress":
            overall_progress,
            "task_progress":
            round(task_progress, 2),
            "milestone_progress":
            round(milestone_progress, 2),
            "tasks_completed":
            task_data['completed_tasks'] or 0,
            "total_tasks":
            task_data['total_tasks'] or 0,
            "milestones_completed":
            milestone_data['completed_milestones'] or 0,
            "total_milestones":
            milestone_data['total_milestones'] or 0,
            "message":
            "Progress calculated successfully"
        }), 200

    except Exception as e:
        print(f"[ERROR] calculate_project_progress failed: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/projects/<int:project_id>/progress-history", methods=["GET"])
@login_required
def get_project_progress_history(project_id):
    """
    Retrieve historical progress data for charts/graphs
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT 
                progress_percentage,
                tasks_completed,
                total_tasks,
                milestones_completed,
                total_milestones,
                recorded_at
            FROM progress_history 
            WHERE project_id = ?
            ORDER BY recorded_at DESC
            LIMIT 30
        ''', (project_id, ))

        history = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in history]), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/dashboard/live-progress", methods=["GET"])
@login_required
def get_live_dashboard_progress():
    """
    Get real-time progress for all active projects
    Differentiates between admin and employee views
    """
    try:
        user_id = get_current_user_id()
        is_admin = session.get('admin') or session.get('user_type') == 'admin'

        conn = get_db_connection()
        cursor = conn.cursor()

        if is_admin:
            # Admin sees all active projects
            cursor.execute('''
                SELECT 
                    p.id,
                    p. title,
                    p.description,
                    p.status,
                    p.progress,
                    p.deadline,
                    p.reporting_time,
                    p.created_at,
                    p.updated_at,
                    u.username as creator_name,
                    COUNT(DISTINCT t.id) as total_tasks,
                    SUM(CASE WHEN t. status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                    COUNT(DISTINCT m.id) as total_milestones,
                    SUM(CASE WHEN m.status = 'Completed' THEN 1 ELSE 0 END) as completed_milestones,
                    COUNT(DISTINCT pa.user_id) as team_size
                FROM projects p
                LEFT JOIN users u ON p.created_by_id = u.id
                LEFT JOIN tasks t ON p.id = t.project_id
                LEFT JOIN milestones m ON p. id = m.project_id
                LEFT JOIN project_assignments pa ON p.id = pa.project_id
                WHERE p.status != 'Completed'
                GROUP BY p.id, u.username
                ORDER BY p.updated_at DESC
            ''')
        else:
            # Employees see only assigned projects
            cursor.execute(
                '''
                SELECT DISTINCT
                    p.id,
                    p.title,
                    p.description,
                    p.status,
                    p. progress,
                    p.deadline,
                    p.reporting_time,
                    p.created_at,
                    p. updated_at,
                    u.username as creator_name,
                    COUNT(DISTINCT t. id) as total_tasks,
                    SUM(CASE WHEN t.status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                    COUNT(DISTINCT m.id) as total_milestones,
                    SUM(CASE WHEN m.status = 'Completed' THEN 1 ELSE 0 END) as completed_milestones,
                    COUNT(DISTINCT pa.user_id) as team_size
                FROM projects p
                LEFT JOIN users u ON p.created_by_id = u.id
                LEFT JOIN tasks t ON p.id = t. project_id
                LEFT JOIN milestones m ON p.id = m.project_id
                LEFT JOIN project_assignments pa ON p. id = pa.project_id
                WHERE (p.created_by_id = ? OR p.id IN (
                    SELECT project_id FROM project_assignments WHERE user_id = ?
                ))
                AND p.status != 'Completed'
                GROUP BY p.id, u.username
                ORDER BY p.updated_at DESC
            ''', (user_id, user_id))

        projects = cursor.fetchall()
        conn.close()

        formatted_projects = []
        for project in projects:
            project_dict = dict(project)

            # Calculate additional metrics
            try:
                created_at = datetime.strptime(project_dict['created_at'],
                                               '%Y-%m-%d %H:%M:%S')
            except:
                created_at = datetime.now()

            now = datetime.now()
            days_active = max(1, (now - created_at).days)
            progress_per_day = project_dict[
                'progress'] / days_active if days_active > 0 else 0

            # Estimate completion date
            estimated_completion_str = None
            if project_dict['progress'] > 0 and progress_per_day > 0:
                days_remaining = (100 -
                                  project_dict['progress']) / progress_per_day
                estimated_completion = now + timedelta(days=days_remaining)
                estimated_completion_str = estimated_completion.strftime(
                    '%Y-%m-%d')

            # Calculate sub-progress metrics
            tasks_progress = int(
                (project_dict['completed_tasks'] /
                 project_dict['total_tasks'] *
                 100)) if project_dict['total_tasks'] > 0 else 0
            milestones_progress = int(
                (project_dict['completed_milestones'] /
                 project_dict['total_milestones'] *
                 100)) if project_dict['total_milestones'] > 0 else 0

            # Health status
            health_status = 'good' if project_dict[
                'progress'] >= 70 else 'warning' if project_dict[
                    'progress'] >= 40 else 'danger'

            project_dict.update({
                'days_active': days_active,
                'progress_per_day': round(progress_per_day, 2),
                'estimated_completion': estimated_completion_str,
                'tasks_progress': tasks_progress,
                'milestones_progress': milestones_progress,
                'health_status': health_status
            })

            formatted_projects.append(project_dict)

        # Calculate average progress
        avg_progress = 0
        if formatted_projects:
            avg_progress = round(
                sum(p['progress']
                    for p in formatted_projects) / len(formatted_projects), 2)

        return jsonify({
            "timestamp": datetime.now().isoformat(),
            "total_projects": len(formatted_projects),
            "average_progress": avg_progress,
            "projects": formatted_projects
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<int:user_id>/permissions", methods=["GET"])
@admin_required
def get_user_permissions(user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT module, action, granted FROM user_permissions 
            WHERE user_id = ? ORDER BY module, action
        ''', (user_id, ))
        permissions = cursor.fetchall()
        conn.close()

        result = {}
        for perm in permissions:
            module = perm['module']
            if module not in result:
                result[module] = {}
            result[module][perm['action']] = bool(perm['granted'])

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<int:user_id>/permissions", methods=["POST"])
@admin_required
def set_user_permissions(user_id):
    try:
        data = request.get_json()
        module = data.get("module")
        action = data.get("action")
        granted = data.get("granted")

        if not module or not action:
            return jsonify({'error': 'Module and action are required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if permission exists
        cursor.execute(
            '''
            SELECT id FROM user_permissions 
            WHERE user_id = ? AND module = ? AND action = ?
        ''', (user_id, module, action))

        if cursor.fetchone():
            cursor.execute(
                '''
                UPDATE user_permissions 
                SET granted = ? 
                WHERE user_id = ? AND module = ? AND action = ?
            ''', (granted, user_id, module, action))
        else:
            cursor.execute(
                '''
                INSERT INTO user_permissions (user_id, module, action, granted)
                VALUES (?, ?, ?, ?)
            ''', (user_id, module, action, granted))

        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        logger.exception('set_user_permissions failed')
        return jsonify({'error': str(e)}), 500


@app.route("/api/usertypes", methods=["GET"])
@login_required
def get_user_types():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM usertypes ORDER BY id ASC")
        types = cursor.fetchall()
        conn.close()
        return jsonify([dict(row) for row in types]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route("/api/usertypes", methods=["POST"])
@admin_required
def create_user_type():
    conn = None
    try:
        data = request.get_json()
        user_role = data.get("user_role")
        if not user_role:
            return jsonify({"error": "User role is required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("INSERT INTO usertypes (user_role) VALUES (?)",
                       (user_role, ))
        usertype_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            "id": usertype_id,
            "user_role": user_role,
            "message": "User type created successfully!"
        }), 201

    except sqlite3.IntegrityError:
        if conn:
            conn.close()
        return jsonify({"error": "User role already exists."}), 409

    except Exception as e:
        if conn:
            conn.close()
        return jsonify({"error": str(e)}), 500


@app.route("/api/usertypes/<int:id>", methods=["DELETE"])
@admin_required
def delete_user_type(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM usertypes WHERE id = ?', (id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "User type not found."}), 404

        cursor.execute(
            'SELECT COUNT(*) as count FROM users WHERE user_type_id = ?',
            (id, ))
        if cursor.fetchone()['count'] > 0:
            conn.close()
            return jsonify({
                "error":
                "Cannot delete user type that has associated users."
            }), 400

        cursor.execute('DELETE FROM usertypes WHERE id = ?', (id, ))
        conn.commit()
        conn.close()

        return jsonify({"message": "User type deleted successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users", methods=["GET"])
@login_required
def get_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.user_type_id, ut.user_role, u.created_at
            FROM users u 
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id 
            WHERE COALESCE(u.is_system, 0) != 1
            ORDER BY u.created_at DESC
        ''')
        users = cursor.fetchall()
        conn.close()

        result = []
        for row in users:
            created_at = row['created_at']
            if created_at and hasattr(created_at, 'isoformat'):
                created_at_str = created_at.isoformat()
            else:
                created_at_str = str(created_at) if created_at else None

            result.append({
                "id": row['id'],
                "username": row['username'],
                "email": row['email'],
                "user_type_id": row['user_type_id'],
                "user_role": row['user_role'],
                "created_at": created_at_str
            })

        return jsonify(result), 200
    except Exception as e:
        print(f"[ERROR] /api/users GET failed: {str(e)}")
        return jsonify({"error": str(e)}), 500



@app.route("/api/employees", methods=["GET"])
@login_required
def get_employees():
    """Get all employees (users with role 'employee')"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.user_type_id, ut.user_role, u.created_at, u.department
            FROM users u 
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id 
            WHERE LOWER(ut.user_role) = 'employee'
            ORDER BY u.username ASC
        ''')
        users = cursor.fetchall()
        conn.close()

        result = []
        for row in users:
            created_at = row['created_at']
            if created_at and hasattr(created_at, 'isoformat'):
                created_at_str = created_at.isoformat()
            else:
                created_at_str = str(created_at) if created_at else None

            result.append({
                "id": row['id'],
                "username": row['username'],
                "email": row['email'],
                "user_type_id": row['user_type_id'],
                "user_role": row['user_role'],
                "department": row['department'],
                "created_at": created_at_str
            })

        return jsonify(result), 200
    except Exception as e:
        print(f"[ERROR] /api/employees GET failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/users", methods=["POST"])
@admin_required
def create_user():
    try:
        data = request.get_json()
        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        confirm_password = data.get("confirm_password") or ""
        user_type_id = data.get("user_type_id")
        permissions_data = data.get("permissions")

        if isinstance(permissions_data, str):
            try:
                permissions = json.loads(permissions_data)
            except json.JSONDecodeError:
                permissions = {}
        else:
            permissions = permissions_data or {}

        if not all([username, email, password, confirm_password, user_type_id
                    ]):
            return jsonify({"error":
                            "All mandatory fields are required."}), 400

        if len(username) < 3:
            return jsonify(
                {"error": "Username must be at least 3 characters."}), 400

        # Prevent creating reserved system accounts like Super Admin
        if username.lower() == 'super admin':
            return jsonify({"error": "Username reserved."}), 400

        if "@" not in email or "." not in email.split("@")[-1]:
            return jsonify({"error": "Invalid email format."}), 400

        is_valid, validation_message = validate_password_complexity(password)
        if not is_valid:
            return jsonify({"error": validation_message}), 400

        if password != confirm_password:
            return jsonify({"error": "Passwords do not match."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM usertypes WHERE id = ?',
                       (user_type_id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Invalid user type selected."}), 400

        try:
            hashed_password = generate_password_hash(password,
                                                     method='pbkdf2:sha256')
            cursor.execute(
                '''
                INSERT INTO users (username, email, password, user_type_id, is_system) 
                VALUES (?,?,?,?,0)
            ''', (username, email, hashed_password, user_type_id))
            user_id = cursor.lastrowid
            conn.commit()

            for module, actions in permissions.items():
                if isinstance(actions, dict):
                    for action, granted in actions.items():
                        try:
                            cursor.execute(
                                '''
                                INSERT INTO user_permissions (user_id, module, action, granted)
                                VALUES (?,?,?,?)
                            ''', (user_id, module, action, bool(granted)))
                        except sqlite3.IntegrityError:
                            pass

            conn.commit()
            conn.close()

            return jsonify({
                "id": user_id,
                "username": username,
                "email": email,
                "user_type_id": user_type_id,
                "permissions": permissions,
                "created_at": datetime.now().isoformat(),
                "message": "User created successfully!"
            }), 201

        except sqlite3.IntegrityError as e:
            print(f"[ERROR] User creation conflict: {e}")
            conn.close()
            return jsonify({"error": "Username or email already exists."}), 409

    except Exception as e:
        print(f"[ERROR] /api/users POST failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<int:id>", methods=["GET"])
@admin_required
def get_user(id):
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get user basic info
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.user_type_id, ut.user_role, u.created_at, u.status
            FROM users u 
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id 
            WHERE u.id = ?
        ''', (id, ))
        user = cursor.fetchone()

        if not user:
            conn.close()
            return jsonify({"error": "User not found."}), 404

        # 1. Get Direct User Permissions
        cursor.execute('''
            SELECT module, action, granted FROM user_permissions 
            WHERE user_id = ? ORDER BY module, action
        ''', (id, ))
        direct_perms = cursor.fetchall()

        # 2. Get Role-based (UserType) Permissions
        cursor.execute('''
            SELECT module, action, granted FROM usertype_permissions 
            WHERE usertype_id = ? ORDER BY module, action
        ''', (user['user_type_id'], ))
        role_perms = cursor.fetchall()
        
        conn.close()

        # Merge permissions (Direct takes precedence if same module-action)
        permissions = {}
        
        # Add role permissions first
        for perm in role_perms:
            module = perm['module']
            if module not in permissions:
                permissions[module] = {}
            permissions[module][perm['action']] = bool(perm['granted'])
            
        # Add direct permissions (overwriting if necessary)
        for perm in direct_perms:
            module = perm['module']
            if module not in permissions:
                permissions[module] = {}
            permissions[module][perm['action']] = bool(perm['granted'])

        user_dict = dict(user)
        user_dict['permissions'] = permissions
        
        # Safe Date Serialization
        if user_dict.get('created_at'):
            created_at = user_dict['created_at']
            if hasattr(created_at, 'isoformat'):
                user_dict['created_at'] = created_at.isoformat()
            else:
                user_dict['created_at'] = str(created_at)

        return jsonify(user_dict), 200
    except Exception as e:
        logger.exception(f"Error fetching user {id}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<int:id>", methods=["PUT"])
@admin_required
def update_user(id):
    try:
        data = request.get_json() or {}
        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password")
        user_type_id = data.get("user_type_id")
        permissions_data = data.get("permissions")

        if isinstance(permissions_data, str):
            try:
                permissions = json.loads(permissions_data)
            except json.JSONDecodeError:
                permissions = {}
        else:
            permissions = permissions_data or {}

        if not username or not email or not user_type_id:
            return jsonify(
                {"error": "Username, email, and user type are required."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM users WHERE id = ?', (id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "User not found."}), 404

        try:
            if password:
                is_valid, validation_message = validate_password_complexity(
                    password)
                if not is_valid:
                    conn.close()
                    return jsonify({"error": validation_message}), 400
                hashed_password = generate_password_hash(
                    password, method='pbkdf2:sha256')
                cursor.execute(
                    '''
                    UPDATE users SET username = ?, email = ?, password = ?, user_type_id = ?
                    WHERE id = ?
                ''', (username, email, hashed_password, user_type_id, id))
            else:
                cursor.execute(
                    '''
                    UPDATE users SET username = ?, email = ?, user_type_id = ?
                    WHERE id = ?
                ''', (username, email, user_type_id, id))

            cursor.execute('DELETE FROM user_permissions WHERE user_id = ?',
                           (id, ))

            for module, actions in permissions.items():
                if isinstance(actions, dict):
                    for action, granted in actions.items():
                        try:
                            cursor.execute(
                                '''
                                INSERT INTO user_permissions (user_id, module, action, granted)
                                VALUES (?,?,?,?)
                            ''', (id, module, action, bool(granted)))
                        except sqlite3.IntegrityError as e:
                            print(f"[DEBUG] Permission insert conflict: {e}")
                            pass

            conn.commit()
            conn.close()

            return jsonify({
                "id": id,
                "username": username,
                "email": email,
                "user_type_id": user_type_id,
                "permissions": permissions,
                "message": "User updated successfully!"
            }), 200

        except sqlite3.IntegrityError as e:
            print(f"[ERROR] User update conflict: {e}")
            conn.close()
            return jsonify({"error": "Username or email already exists."}), 409

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<int:id>", methods=["DELETE"])
@admin_required
def delete_user(id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM users WHERE id = ?', (id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "User not found."}), 404

        cursor.execute('DELETE FROM user_permissions WHERE user_id = ?',
                       (id, ))
        cursor.execute('DELETE FROM users WHERE id = ?', (id, ))
        conn.commit()
        conn.close()

        return jsonify({"message": "User deleted successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/user/login", methods=["POST"])
def user_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            SELECT u.id, u.username, u.email, u.password, ut.user_role
            FROM users u
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            WHERE u.email = ?
        ''', (email, ))
        user = cursor.fetchone()

        if not user:
            conn.close()
            return jsonify({"error": "Invalid email or password."}), 401

        if not check_password_hash(user['password'], password):
            conn.close()
            return jsonify({"error": "Invalid email or password."}), 401

        cursor.execute(
            '''
            SELECT module, action, granted FROM user_permissions
            WHERE user_id = ? ORDER BY module, action
        ''', (user['id'], ))
        permissions_rows = cursor.fetchall()
        conn.close()

        permissions = {}
        for perm in permissions_rows:
            module = perm['module']
            if module not in permissions:
                permissions[module] = {}
            permissions[module][perm['action']] = bool(perm['granted'])

        # Store authentication info in session
        session.clear()
        session.permanent = True
        session['user_id'] = user['id']
        session['user_type'] = 'employee'
        session['username'] = user['username']
        session['permissions'] = permissions
        session['is_authenticated'] = True

        auth_token = secrets.token_urlsafe(32)
        csrf_for_token = secrets.token_urlsafe(16)
        # Store token in both session and global dict for API authentication
        session['auth_token'] = auth_token
        valid_tokens[auth_token] = {
            'user_id': user['id'],
            'username': user['username'],
            'user_type': 'employee',
            'csrf_token': csrf_for_token,
            'created_at': datetime.now(timezone.utc)
        }

        return jsonify({
            "user_id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "user_role": user['user_role'],
            "permissions": permissions,
            "token": auth_token,
            "csrf_token": csrf_for_token,
            "message": "Login successful!"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/user/logout", methods=["POST"])
def user_logout():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        if token in valid_tokens:
            del valid_tokens[token]
    # Clear session data
    session.clear()
    return jsonify({"message": "Logout successful!"}), 200


@app.route("/api/employee/projects", methods=["GET"])
@login_required
def get_employee_projects():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT DISTINCT p.id, p.title, p.description, p.status, p.progress, 
                   p.deadline, p.created_by_id, u.username as creator_name, p.created_at
            FROM projects p 
            LEFT JOIN users u ON p.created_by_id = u.id
                WHERE (p.created_by_id = ? OR p.id IN (
                    SELECT project_id FROM project_assignments WHERE user_id = ?
                ))
            ORDER BY p.created_at DESC
        ''', (user_id, user_id))

        projects = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in projects]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/employee/projects", methods=["POST"])
@login_required
def create_employee_project():
    """
    Create a new project.
    Ensures created_by_id references an existing users.id.
    If session user_id == 0 (super-admin placeholder), attempt to map to a real admin user or create a minimal system user.
    """
    try:
        data = request.get_json() or {}
        title = (data.get("title") or "").strip()
        description = data.get("description") or ""
        deadline = data.get("deadline") or None
        reporting_time = data.get("reporting_time") or "09:00"
        team_members = data.get("team_members") or []

        if not title:
            return jsonify({"error": "title is required"}), 400
        
        # Validate that at least one team member is assigned
        if not team_members or len(team_members) == 0:
            return jsonify({
                "error": "At least one team member must be assigned to the project. Please select team members before creating the project."
            }), 400

        conn = get_db_connection()
        cur = conn.cursor()

        # Resolve a valid created_by_id (don't use 0 as that doesn't exist in users)
        created_by_id = get_current_user_id()
        if created_by_id == 0 or created_by_id is None:
            # Try to find an Administrator user
            cur.execute("""
                SELECT u.id FROM users u
                JOIN usertypes ut ON u.user_type_id = ut.id
                WHERE lower(ut.user_role) LIKE '%admin%'
                LIMIT 1
            """)
            row = cur.fetchone()
            if row:
                created_by_id = row["id"]
            else:
                # Try any existing user
                cur.execute("SELECT id FROM users LIMIT 1")
                row2 = cur.fetchone()
                if row2:
                    created_by_id = row2["id"]
                else:
                    # No users exist — create a minimal system Administrator user
                    cur.execute("SELECT id FROM usertypes WHERE lower(user_role) LIKE '%admin%' LIMIT 1")
                    ut = cur.fetchone()
                    if ut:
                        usertype_id = ut["id"]
                    else:
                        cur.execute("INSERT INTO usertypes (user_role) VALUES (?)", ("Administrator",))
                        usertype_id = cur.lastrowid

                    # create a minimal system user (password hash not important for system account)
                    dummy_password = generate_password_hash(secrets.token_hex(8))
                    cur.execute("""
                        INSERT INTO users (username, email, password, user_type_id, granted, created_at)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """, ("system", "system@example.com", dummy_password, usertype_id, 1))
                    created_by_id = cur.lastrowid
                    conn.commit()

        # Insert project
        try:
            cur.execute("""
                INSERT INTO projects (title, description, deadline, reporting_time, created_by_id, status, progress, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (title, description, deadline, reporting_time, created_by_id, 'In Progress', 0))
            project_id = cur.lastrowid

            # Assign team members if provided (silently ignore duplicates)
            for uid in (team_members or []):
                try:
                    uid_int = int(uid)
                except Exception:
                    continue
                try:
                    cur.execute("""
                        INSERT OR IGNORE INTO project_assignments (user_id, project_id) VALUES (?, ?)
                    """, (uid_int, project_id))
                except Exception:
                    # continue on per-user errors
                    continue

            conn.commit()
        except sqlite3.IntegrityError as ie:
            conn.rollback()
            logger.exception("create_employee_project failed (IntegrityError)")
            return jsonify({"error": "Database integrity error when creating project: " + str(ie)}), 500
        except sqlite3.OperationalError as oe:
            conn.rollback()
            logger.exception("create_employee_project failed (OperationalError)")
            return jsonify({"error": "Database operational error (locked or similar). Please try again: " + str(oe)}), 500

        # Log activity if you have log_activity helper
        try:
            log_activity(created_by_id, 'project_created', f'Project {title} created', project_id)
        except Exception:
            pass

        conn.close()
        return jsonify({"success": True, "id": project_id}), 201

    except Exception as e:
        logger.exception("create_employee_project failed")
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass
        return jsonify({"error": str(e)}), 500

@app.route("/api/employee/tasks", methods=["GET"])
@login_required
def get_employee_tasks():
    """
    Get tasks for the logged-in employee.
    Returns tasks where the employee is assigned or is the creator.
    Optional filter: project_id query parameter to filter by project
    """
    conn = None
    try:
        user_id = get_current_user_id()
        if not user_id:
            return jsonify({"error": "User ID not found"}), 401

        project_id = request.args.get('project_id', None)

        conn = get_db_connection()
        cursor = conn.cursor()

        if project_id:
            # Filter by project
            try:
                project_id = int(project_id)
            except (ValueError, TypeError):
                conn.close()
                return jsonify({"error": "Invalid project_id"}), 400

            cursor.execute(
                '''
                SELECT t.id, t.title, t.description, t.status, t.priority, t.deadline,
                       t.project_id, p.title as project_name, t.assigned_to_id,
                       u.username as assigned_to_name, t.created_at, t.approval_status
                FROM tasks t
                LEFT JOIN projects p ON t.project_id = p.id
                LEFT JOIN users u ON t.assigned_to_id = u.id
                WHERE t.project_id = ? AND (t.assigned_to_id = ? OR t.created_by_id = ?)
                ORDER BY t.created_at DESC
            ''', (project_id, user_id, user_id))
        else:
            # Get all tasks for user
            cursor.execute(
                '''
                SELECT t.id, t.title, t.description, t.status, t.priority, t.deadline,
                       t.project_id, p.title as project_name, t.assigned_to_id,
                       u.username as assigned_to_name, t.created_at, t.approval_status
                FROM tasks t
                LEFT JOIN projects p ON t.project_id = p.id
                LEFT JOIN users u ON t.assigned_to_id = u.id
                WHERE t.assigned_to_id = ? OR t.created_by_id = ?
                ORDER BY t.created_at DESC
            ''', (user_id, user_id))

        tasks = cursor.fetchall()
        task_list = [dict(row) for row in tasks]

        return jsonify(task_list), 200

    except Exception as e:
        logger.exception("Error fetching employee tasks")
        return jsonify({
            "error": "Failed to fetch tasks",
            "details": str(e)
        }), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/employee/tasks", methods=["POST"])
@login_required
def create_employee_task():
    """
    Create a new task for a project.
    Requires 'task' module 'Add' permission.

    POST payload:
    {
        "title": "Task Title",           # Required
        "description": "...",             # Optional
        "project_id": 1,                  # Required (integer)
        "assigned_to_id": 2,              # Optional (integer or null)
        "priority": "High|Medium|Low",    # Optional, default "Medium"
        "deadline": "YYYY-MM-DD"          # Optional
    }
    """
    conn = None
    try:
        # Step 1: Parse and validate incoming payload
        data = request.get_json() or {}
        title = (data.get("title") or "").strip()
        description = data.get("description") or ""
        project_id = data.get("project_id")
        assigned_to_id = data.get("assigned_to_id")
        priority = data.get("priority") or "Medium"
        deadline = data.get("deadline")

        # Validate required fields
        if not title:
            return jsonify({"error": "Task title is required"}), 400
        if project_id is None:
            return jsonify({"error": "Project ID is required"}), 400

        # Normalize and validate project_id type
        try:
            project_id = int(project_id)
        except (ValueError, TypeError):
            return jsonify({"error":
                            "Project ID must be a valid integer"}), 400

        # Normalize and validate assigned_to_id type
        if assigned_to_id is not None and assigned_to_id != "":
            try:
                assigned_to_id = int(assigned_to_id)
            except (ValueError, TypeError):
                return jsonify({
                    "error":
                    "assigned_to_id must be a valid integer or null"
                }), 400
        else:
            assigned_to_id = None

        # Validate deadline format if provided
        if deadline:
            try:
                datetime.strptime(deadline, "%Y-%m-%d")
            except ValueError:
                return jsonify(
                    {"error": "Invalid deadline format. Use YYYY-MM-DD"}), 400

        # Get current user
        user_id = get_current_user_id()
        if user_id is None:
            logger.error("Could not determine current user ID")
            return jsonify(
                {"error": "Authentication error: User ID not found"}), 401

        # Step 2: Perform all read operations first (checks/validations)
        # This minimizes the time we hold write locks
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Check permission to create tasks (Super Admin bypass)
            if user_id != 0:
                cursor.execute(
                    'SELECT granted FROM user_permissions WHERE user_id = ? AND module = ? AND action = ?',
                    (user_id, 'task', 'Add'))
                perm = cursor.fetchone()

                # Allow creation if permission is explicitly granted OR if permission system not fully initialized
                # (This allows employees to create tasks even if permissions table is being set up)
                if perm and not perm['granted']:
                    logger.warning(
                        f"User {user_id} lacks permission to create tasks")
                    return jsonify({
                        "error":
                        "Permission denied: You don't have permission to create tasks"
                    }), 403
                elif not perm:
                    # Permission not found - this is OK for transitional state
                    logger.info(
                        f"Permission not found for user {user_id}, allowing task creation (permission system may not be initialized)"
                    )

            # Verify project exists
            cursor.execute('SELECT id FROM projects WHERE id = ?',
                           (project_id, ))
            if not cursor.fetchone():
                logger.warning(
                    f"Project {project_id} not found for task creation")
                return jsonify(
                    {"error": f"Project not found (ID: {project_id})"}), 404

            # Verify assigned_to user exists (if specified)
            if assigned_to_id:
                cursor.execute('SELECT id FROM users WHERE id = ?',
                               (assigned_to_id, ))
                if not cursor.fetchone():
                    logger.warning(
                        f"User {assigned_to_id} not found for task assignment")
                    return jsonify({
                        "error":
                        f"Assigned user not found (ID: {assigned_to_id})"
                    }), 404

        except sqlite3.DatabaseError as db_err:
            logger.exception(f"Database error during validation: {db_err}")
            return jsonify({
                "error": "Database error during validation",
                "details": str(db_err)
            }), 503

        # Decide status based on whether assigned at creation
        status_to_set = 'In Progress' if assigned_to_id else 'Pending'

        # Step 3: Insert the task (write operation with explicit transaction control)
        task_id = None
        try:
            # Use IMMEDIATE to acquire write lock immediately and prevent "database is locked" issues
            cursor.execute('BEGIN IMMEDIATE')

            cursor.execute(
                '''
                INSERT INTO tasks (title, description, project_id, created_by_id, assigned_to_id, priority, deadline, status)
                VALUES (?,?,?,?,?,?,?,?)
                ''', (title, description, project_id, user_id, assigned_to_id,
                      priority, deadline or None, status_to_set))

            task_id = cursor.lastrowid
            cursor.execute('COMMIT')
            logger.info(
                f"Task {task_id} created successfully by user {user_id}")

        except sqlite3.OperationalError as op_err:
            # "database is locked" typically means another process holds the lock
            cursor.execute('ROLLBACK')
            logger.exception(
                f"SQLite lock error while inserting task: {op_err}")
            return jsonify({
                "error": "Database is temporarily locked. Please try again.",
                "type": "DB_LOCKED"
            }), 503
        except sqlite3.IntegrityError as int_err:
            cursor.execute('ROLLBACK')
            logger.exception(f"Integrity constraint error: {int_err}")
            return jsonify(
                {"error": "Task creation failed: Constraint violation"}), 400
        except Exception as insert_err:
            cursor.execute('ROLLBACK')
            logger.exception(
                f"Unexpected error during task insert: {insert_err}")
            return jsonify({
                "error": "Failed to create task",
                "details": str(insert_err)
            }), 500

        # Close the connection early - don't hold locks for subsequent operations
        conn.close()
        conn = None

        # Step 4: Post-creation operations (these use their own connections)
        # These are non-critical and fail gracefully without affecting the response
        try:
            log_activity(user_id,
                         'task_created',
                         f'Created task: {title}',
                         project_id=project_id,
                         task_id=task_id)
        except Exception as log_err:
            logger.warning(
                f"Failed to log activity for task {task_id}: {log_err}")

        try:
            calculate_project_progress(project_id)
        except Exception as progress_err:
            logger.warning(
                f"Failed to update project progress for project {project_id}: {progress_err}"
            )

        # Step 5: Return success response
        return jsonify({
            "id": task_id,
            "title": title,
            "message": "Task created successfully!"
        }), 201

    except sqlite3.OperationalError as oe:
        logger.exception(f"Uncaught SQLite OperationalError: {oe}")
        return jsonify({
            "error": "Database operation failed",
            "type": "DB_ERROR",
            "details": str(oe)
        }), 503
    except Exception as e:
        logger.exception(f"Unexpected error in create_employee_task: {e}")
        return jsonify({
            "error": "An unexpected error occurred",
            "type": "INTERNAL_ERROR",
            "details": str(e) if app.debug else None
        }), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception as close_err:
                logger.warning(
                    f"Error closing database connection: {close_err}")


@app.route("/api/employee/tasks/<int:task_id>/complete", methods=["POST"])
@login_required
def complete_employee_task(task_id):
    """Complete a task (mark as Completed)"""
    conn = None
    try:
        user_id = get_current_user_id()
        if not user_id:
            return jsonify({"error": "User ID not found"}), 401

        conn = get_db_connection()
        cursor = conn.cursor()

        # Step 1: Fetch task details (validation)
        try:
            cursor.execute(
                '''
                SELECT status, project_id FROM tasks WHERE id = ? AND (assigned_to_id = ? OR created_by_id = ?)
            ''', (task_id, user_id, user_id))
            task = cursor.fetchone()

            if not task:
                logger.warning(
                    f"Task {task_id} not found or user {user_id} lacks permission"
                )
                return jsonify(
                    {"error": "Task not found or permission denied"}), 404

            if task['status'] == 'Completed':
                logger.info(f"Task {task_id} is already completed")
                return jsonify({"message": "Task is already completed"}), 200

            project_id = task['project_id']

        except sqlite3.DatabaseError as db_err:
            logger.exception(
                f"Database error while fetching task {task_id}: {db_err}")
            return jsonify({"error": "Database error during task fetch"}), 503

        # Step 2: Update task status with explicit transaction control
        try:
            cursor.execute('BEGIN IMMEDIATE')
            cursor.execute(
                '''
                UPDATE tasks SET status = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?
            ''', ('Completed', task_id))
            cursor.execute('COMMIT')
            logger.info(
                f"Task {task_id} marked as completed by user {user_id}")

        except sqlite3.OperationalError as op_err:
            cursor.execute('ROLLBACK')
            logger.exception(
                f"Lock error while updating task {task_id}: {op_err}")
            return jsonify({
                "error": "Database is temporarily locked. Please try again.",
                "type": "DB_LOCKED"
            }), 503
        except Exception as update_err:
            cursor.execute('ROLLBACK')
            logger.exception(f"Error updating task {task_id}: {update_err}")
            return jsonify({"error": "Failed to update task status"}), 500

        conn.close()
        conn = None

        # Step 3: Post-update operations (non-critical, use separate connections)
        try:
            log_activity(user_id,
                         'task_completed',
                         f'Completed task {task_id}',
                         task_id=task_id)
        except Exception as log_err:
            logger.warning(
                f"Failed to log activity for task completion: {log_err}")

        try:
            progress_response = calculate_project_progress(project_id)
            if isinstance(progress_response,
                          tuple) and progress_response[1] == 200:
                progress_data = progress_response[0].get_json() if hasattr(
                    progress_response[0], 'get_json') else {}
                return jsonify({
                    "message": "Task completed successfully!",
                    "project_progress": progress_data
                }), 200
        except Exception as progress_err:
            logger.warning(
                f"Failed to calculate project progress: {progress_err}")

        return jsonify({"message": "Task completed successfully!"}), 200

    except Exception as e:
        logger.exception(f"Unexpected error in complete_employee_task: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception as close_err:
                logger.warning(f"Error closing connection: {close_err}")


@app.route("/api/employee/milestones", methods=["GET"])
@login_required
def get_employee_milestones():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT m.id, m.title, m.description, m.status, m.due_date, m.project_id,
                   p.title as project_title, m.created_at
            FROM milestones m
            LEFT JOIN projects p ON m.project_id = p.id
            WHERE p.created_by_id = ? OR m.project_id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            )
            ORDER BY m.created_at DESC
        ''', (user_id, user_id))

        milestones = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in milestones]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Replace your existing /api/employee/milestones POST handler with this ---
@app.route('/api/employee/milestones', methods=['POST'])
@login_required
def create_milestone_employee():
    """
    Create milestone for a project. Ensures created_by is a valid user id
    and handles busy database / FK issues gracefully.
    """
    conn = None
    try:
        data = request.get_json() or {}
        title = (data.get('title') or '').strip()
        description = data.get('description') or ''
        due_date = data.get('due_date') or None
        project_id = data.get('project_id')

        if not title or not project_id:
            return jsonify({'error': 'title and project_id are required'}), 400

        conn = get_db_connection()
        conn.execute("PRAGMA busy_timeout = 5000")
        cur = conn.cursor()

        # Verify project exists
        cur.execute("SELECT id FROM projects WHERE id = ?", (int(project_id),))
        if not cur.fetchone():
            return jsonify({'error': 'Project not found'}), 404

        # Ensure created_by is valid (same logic as create_project_employee)
        session_user_id = get_current_user_id() or None
        created_by = None
        if session_user_id:
            cur.execute("SELECT id FROM users WHERE id = ?", (session_user_id,))
            row = cur.fetchone()
            if row:
                created_by = row['id']

        if not created_by:
            cur.execute("SELECT id FROM users ORDER BY id LIMIT 1")
            row = cur.fetchone()
            if row:
                created_by = row['id']
            else:
                # create fallback system user
                cur.execute("SELECT id FROM usertypes WHERE LOWER(user_role) LIKE 'admin%' LIMIT 1")
                ut = cur.fetchone()
                if ut:
                    user_type_id = ut['id']
                else:
                    cur.execute("INSERT INTO usertypes (user_role) VALUES (?)", ('Administrator',))
                    user_type_id = cur.lastrowid
                from werkzeug.security import generate_password_hash
                pw = generate_password_hash(secrets.token_urlsafe(12))
                cur.execute(
                    "INSERT INTO users (username, email, password, user_type_id, granted, created_at) VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP)",
                    ('system', 'system@example.local', pw, user_type_id)
                )
                created_by = cur.lastrowid

        # Insert milestone
        cur.execute(
            '''INSERT INTO milestones (title, description, due_date, project_id, created_by_id, created_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (title, description, due_date, int(project_id), int(created_by))
        )
        milestone_id = cur.lastrowid
        conn.commit()

        try:
            log_activity(created_by, 'milestone_created', f'Created milestone {title}', int(project_id), milestone_id)
        except Exception:
            pass

        return jsonify({'success': True, 'id': milestone_id}), 201

    except sqlite3.IntegrityError as e:
        if conn:
            conn.rollback()
        logger.exception('create_milestone_employee failed (integrity)')
        return jsonify({'error': 'Database integrity error', 'detail': str(e)}), 400
    except sqlite3.OperationalError as e:
        if conn:
            conn.rollback()
        logger.exception('create_milestone_employee failed (operational)')
        return jsonify({'error': 'Database is busy or locked. Try again.', 'detail': str(e)}), 500
    except Exception as e:
        if conn:
            conn.rollback()
        logger.exception('create_milestone_employee failed')
        return jsonify({'error': str(e)}), 500
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass


@app.route("/api/employee/milestones/<int:milestone_id>/complete",
           methods=["POST"])
@login_required
def complete_employee_milestone(milestone_id):
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT project_id FROM milestones WHERE id = ?',
                       (milestone_id, ))
        milestone = cursor.fetchone()

        if not milestone:
            conn.close()
            return jsonify({"error": "Milestone not found"}), 404

        cursor.execute(
            '''
            UPDATE milestones SET status = ?
            WHERE id = ?
        ''', ('Completed', milestone_id))

        conn.commit()
        conn.close()

        log_activity(user_id,
                     'milestone_completed',
                     f'Completed milestone ID: {milestone_id}',
                     milestone_id=milestone_id)

        # Update project progress
        try:
            calculate_project_progress(milestone['project_id'])
        except:
            pass

        return jsonify({"message": "Milestone completed successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/documents", methods=["GET"])
@login_required
def get_employee_documents():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT d.id, d.filename, d.original_filename, d.file_size,
                   d.uploaded_by_id, u.username as uploaded_by, d.project_id, d.task_id,
                   d.uploaded_at
            FROM documents d
            LEFT JOIN users u ON d.uploaded_by_id = u.id
            WHERE d.uploaded_by_id = ? OR d.project_id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            )
            ORDER BY d.uploaded_at DESC
        ''', (user_id, user_id))

        documents = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in documents]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/documents/upload", methods=["POST"])
@login_required
def upload_employee_document():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files['file']
        project_id = request.form.get('project_id')

        if not file.filename or not project_id:
            return jsonify({"error": "File and project ID are required"}), 400

        user_id = get_current_user_id()

        # Ensure upload folder exists
        upload_dir = os.path.join('uploads', 'documents')
        os.makedirs(upload_dir, exist_ok=True)

        # Use a secure and unique filename
        filename = f"{secrets.token_hex(8)}_{secure_filename(file.filename)}"
        file_path = os.path.join(upload_dir, filename)

        # Save the file
        file.save(file_path)

        file_size = os.path.getsize(file_path)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            INSERT INTO documents (filename, original_filename, file_size, uploaded_by_id, project_id)
            VALUES (?,?,?,?,?)
        ''', (filename, file.filename, file_size, user_id, project_id))

        doc_id = cursor.lastrowid
        conn.commit()
        conn.close()

        log_activity(user_id,
                     'document_uploaded',
                     f'Uploaded document: {file.filename}',
                     project_id=project_id)

        return jsonify({
            "id": doc_id,
            "filename": file.filename,
            "message": "Document uploaded successfully!"
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/documents/<int:doc_id>/delete", methods=["DELETE"])
@login_required
def delete_employee_document(doc_id):
    try:
        user_id = get_current_user_id()

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            'SELECT uploaded_by_id, project_id, filename FROM documents WHERE id = ?',
            (doc_id, ))
        doc_info = cursor.fetchone()

        if not doc_info:
            conn.close()
            return jsonify({"error": "Document not found."}), 404

        # Check ownership or project assignment
        if doc_info['uploaded_by_id'] != user_id:
            cursor.execute(
                '''
                SELECT 1 FROM project_assignments WHERE user_id = ? AND project_id = ?
            ''', (user_id, doc_info['project_id']))
            if not cursor.fetchone():
                conn.close()
                return jsonify({"error": "Permission denied"}), 403

        # Delete file from storage
        file_path = os.path.join('uploads', 'documents', doc_info['filename'])
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except OSError as e:
            print(f"[WARNING] Could not delete file {file_path}: {e}")
            # Continue with deletion from DB even if file deletion fails

        cursor.execute('DELETE FROM documents WHERE id = ?', (doc_id, ))
        conn.commit()
        conn.close()

        log_activity(user_id,
                     'document_deleted',
                     f'Deleted document ID: {doc_id}',
                     project_id=doc_info['project_id'])

        return jsonify({"message": "Document deleted successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/dashboard/stats", methods=["GET"])
@login_required
def get_employee_dashboard_stats():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT COUNT(DISTINCT id) as count FROM projects 
            WHERE created_by_id = ? OR id IN (SELECT project_id FROM project_assignments WHERE user_id = ?)
        ''', (user_id, user_id))
        total_projects = cursor.fetchone()['count']

        cursor.execute(
            'SELECT COUNT(*) as count FROM tasks WHERE assigned_to_id = ? OR created_by_id = ?',
            (user_id, user_id))
        total_tasks = cursor.fetchone()['count']

        cursor.execute(
            'SELECT COUNT(*) as count FROM tasks WHERE (assigned_to_id = ? OR created_by_id = ?) AND status = ?',
            (user_id, user_id, 'Completed'))
        completed_tasks = cursor.fetchone()['count']

        cursor.execute(
            '''
            SELECT COUNT(*) as count FROM milestones m 
            WHERE m.project_id IN (
                SELECT id FROM projects WHERE created_by_id = ? OR id IN (
                    SELECT project_id FROM project_assignments WHERE user_id = ?
                )
            )
        ''', (user_id, user_id))
        total_milestones = cursor.fetchone()['count']

        conn.close()

        return jsonify({
            "total_projects": total_projects,
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "total_milestones": total_milestones,
            "pending_tasks": total_tasks - completed_tasks
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/activities", methods=["GET"])
@login_required
def get_employee_activities():
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT a.id, a.activity_type, a.description, a.created_at,
                   u.username, p.title as project_title, p.description as project_description, p.deadline as project_deadline,
                   t.title as task_title, m.title as milestone_title
            FROM activities a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN projects p ON a.project_id = p.id
            LEFT JOIN tasks t ON a.task_id = t.id
            LEFT JOIN milestones m ON a.milestone_id = m.id
            WHERE a.user_id = ? OR a.project_id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            ) OR a.task_id IN (
                SELECT id FROM tasks WHERE assigned_to_id = ? OR created_by_id = ?
            ) OR a.milestone_id IN (
                SELECT id FROM milestones WHERE project_id IN (
                    SELECT project_id FROM project_assignments WHERE user_id = ?
                )
            )
            ORDER BY a.created_at DESC
            LIMIT 50
        ''', (user_id, user_id, user_id, user_id, user_id))

        activities = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in activities]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/search", methods=["GET"])
@login_required
def search():
    try:
        query = request.args.get('q', '').strip()
        if not query or len(query) < 2:
            return jsonify({"results": []}), 200

        # Check if admin or employee
        is_admin = session.get('admin') or session.get('user_type') == 'admin'
        user_id = get_current_user_id()

        conn = get_db_connection()
        cursor = conn.cursor()

        results = []

        # Search projects
        if is_admin:
            cursor.execute(
                '''
                SELECT 'project' as type, id, title as name, description,
                       created_at, NULL as project_name, NULL as status
                FROM projects
                WHERE title LIKE ? OR description LIKE ?
                ORDER BY created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%'))
        else:
            cursor.execute(
                '''
                SELECT 'project' as type, p.id, p.title as name, p.description,
                       p.created_at, NULL as project_name, NULL as status
                FROM projects p
                WHERE (p.title LIKE ? OR p.description LIKE ?) AND
                      (p.created_by_id = ? OR p.id IN (
                          SELECT project_id FROM project_assignments WHERE user_id = ?
                      ))
                ORDER BY p.created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%', user_id, user_id))

        projects = cursor.fetchall()
        for project in projects:
            results.append({
                "type":
                "project",
                "id":
                project['id'],
                "name":
                project['name'],
                "description":
                project['description'][:100] + "..."
                if project['description'] and len(project['description']) > 100
                else project['description'],
                "url":
                "/admin-dashboard" if is_admin else "/employee-dashboard",
                "tab":
                "projects-tab" if not is_admin else None
            })

        # Search tasks
        if is_admin:
            cursor.execute(
                '''
                SELECT 'task' as type, t.id, t.title as name, t.description,
                       t.created_at, p.title as project_name, t.status
                FROM tasks t
                LEFT JOIN projects p ON t.project_id = p.id
                WHERE t.title LIKE ? OR t.description LIKE ?
                ORDER BY t.created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%'))
        else:
            cursor.execute(
                '''
                SELECT 'task' as type, t.id, t.title as name, t.description,
                       t.created_at, p.title as project_name, t.status
                FROM tasks t
                LEFT JOIN projects p ON t.project_id = p.id
                    WHERE (t.title LIKE ? OR t.description LIKE ?) AND
                        (t.assigned_to_id = ? OR t.created_by_id = ?)
                ORDER BY t.created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%', user_id, user_id))

        tasks = cursor.fetchall()
        for task in tasks:
            results.append({
                "type":
                "task",
                "id":
                task['id'],
                "name":
                task['name'],
                "description":
                task['description'][:100] if task['description']
                and len(task['description']) > 100 else task['description'],
                "project_name":
                task['project_name'],
                "status":
                task['status'],
                "url":
                "/admin-dashboard" if is_admin else "/employee-dashboard",
                "tab":
                "tasks-tab" if not is_admin else None
            })

        # Search users (admin only)
        if is_admin:
            cursor.execute(
                '''
                SELECT 'user' as type, id, username as name, email as description,
                       created_at, NULL as project_name, NULL as status
                FROM users
                WHERE username LIKE ? OR email LIKE ?
                ORDER BY created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%'))

            users = cursor.fetchall()
            for user in users:
                results.append({
                    "type": "user",
                    "id": user['id'],
                    "name": user['name'],
                    "description": user['description'],
                    "url": "/admin-dashboard",
                    "tab": "users-tab"
                })

        # Search milestones
        if is_admin:
            cursor.execute(
                '''
                SELECT 'milestone' as type, m.id, m.title as name, m.description,
                       m.created_at, p.title as project_name, m.status
                FROM milestones m
                LEFT JOIN projects p ON m.project_id = p.id
                WHERE m.title LIKE ? OR m.description LIKE ?
                ORDER BY m.created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%'))
        else:
            cursor.execute(
                '''
                SELECT 'milestone' as type, m.id, m.title as name, m.description,
                       m.created_at, p.title as project_name, m.status
                FROM milestones m
                LEFT JOIN projects p ON m.project_id = p.id
                WHERE (m.title LIKE ? OR m.description LIKE ?) AND
                      (p.created_by_id = ? OR m.project_id IN (
                          SELECT project_id FROM project_assignments WHERE user_id = ?
                      ))
                ORDER BY m.created_at DESC
                LIMIT 10
            ''', (f'%{query}%', f'%{query}%', user_id, user_id))

        milestones = cursor.fetchall()
        for milestone in milestones:
            results.append({
                "type":
                "milestone",
                "id":
                milestone['id'],
                "name":
                milestone['name'],
                "description":
                milestone['description'][:100] if milestone['description']
                and len(milestone['description']) > 100 else
                milestone['description'],
                "project_name":
                milestone['project_name'],
                "status":
                milestone['status'],
                "url":
                "/admin-dashboard" if is_admin else "/employee-dashboard",
                "tab":
                "milestones-tab" if not is_admin else None
            })

        # Search documents
        if is_admin:
            cursor.execute(
                '''
                SELECT 'document' as type, d.id, d.original_filename as name,
                       d.file_size, d.uploaded_at, p.title as project_name, NULL as status
                FROM documents d
                LEFT JOIN projects p ON d.project_id = p.id
                WHERE d.original_filename LIKE ?
                ORDER BY d.uploaded_at DESC
                LIMIT 10
            ''', (f'%{query}%', ))
        else:
            cursor.execute(
                '''
                SELECT 'document' as type, d.id, d.original_filename as name,
                       d.file_size, d.uploaded_at, p.title as project_name, NULL as status
                FROM documents d
                LEFT JOIN projects p ON d.project_id = p.id
                WHERE d.original_filename LIKE ? AND
                      (d.uploaded_by_id = ? OR d.project_id IN (
                          SELECT project_id FROM project_assignments WHERE user_id = ?
                      ))
                ORDER BY d.uploaded_at DESC
                LIMIT 10
            ''', (f'%{query}%', user_id, user_id))

        documents = cursor.fetchall()
        for doc in documents:
            results.append({
                "type": "document",
                "id": doc['id'],
                "name": doc['name'],
                "description": f"Size: {doc['file_size']} bytes",
                "project_name": doc['project_name'],
                "url":
                "/admin-dashboard" if is_admin else "/employee-dashboard",
                "tab": "documents-tab" if not is_admin else None
            })

        conn.close()

        return jsonify({"results": results}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/projects", methods=["GET"])
@admin_required
def get_admin_projects():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT p.id, p.title, p.description, p.status, p.progress, 
                   p.deadline, p.created_by_id, u.username as creator_name, 
                   p.created_at, COUNT(DISTINCT pa.user_id) as team_count,
                   COUNT(DISTINCT t.id) as task_count
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            LEFT JOIN project_assignments pa ON p.id = pa.project_id
            LEFT JOIN tasks t ON p.id = t.project_id
            GROUP BY p.id, u.username
            ORDER BY p.created_at DESC
        ''')

        projects = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in projects]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/tasks", methods=["GET"])
@admin_required
def get_admin_tasks():
    """
    Get admin tasks. Supports optional query parameters:
    - status: filter by task.status (e.g., 'In Progress','Pending','Completed','Overdue')
    - assigned_to: user id
    - project_id: project id
    - limit, offset (pagination)
    """
    try:
        status = request.args.get('status')
        assigned_to = request.args.get('assigned_to')
        project_id = request.args.get('project_id')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))

        conn = get_db_connection()
        cursor = conn.cursor()

        base_query = '''
            SELECT t.id, t.title, t.description, t.status, t.priority, t.deadline,
                   t.project_id, p.title as project_name,
                   t.assigned_to_id, u.username as assigned_to_name,
                   t.created_by_id, uc.username as created_by_name,
                   t.created_at, t.approval_status, t.completed_at,
                   COALESCE(t.weightage,1) AS weightage
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            LEFT JOIN users u ON t.assigned_to_id = u.id
            LEFT JOIN users uc ON t.created_by_id = uc.id
            WHERE 1=1
        '''
        params = []

        if status:
            # special handling for 'Overdue'
            if status.lower() == 'overdue':
                base_query += " AND t.deadline < date('now') AND t.status != 'Completed'"
            else:
                base_query += " AND t.status = ?"
                params.append(status)
        if assigned_to:
            base_query += " AND t.assigned_to_id = ?"
            params.append(int(assigned_to))
        if project_id:
            base_query += " AND t.project_id = ?"
            params.append(int(project_id))

        base_query += ' ORDER BY t.created_at DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])

        cursor.execute(base_query, params)
        rows = cursor.fetchall()
        conn.close()

        results = []
        for r in rows:
            task = dict(r)
            # Calculate a simple progress percent if possible: using task weight and related completed sub-items is complex.
            # For now, attempt to compute percent of completed subtasks if any stored; fallback to 0.
            task['progress_percent'] = task.get(
                'progress_percent', 0) if 'progress_percent' in task else 0
            results.append(task)

        return jsonify(results), 200
    except Exception as e:
        logger.exception('get_admin_tasks failed')
        return jsonify({"error": str(e)}), 500


@app.route("/api/tasks/<int:task_id>/history", methods=["GET"])
@admin_required
def task_history(task_id):
    """
    Return task details and activity history related to the task.
    Useful for Task History view on admin dashboard.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Task details
        cursor.execute(
            '''
            SELECT t.*, p.title as project_name, u.username as assigned_to_name, uc.username as created_by_name
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            LEFT JOIN users u ON t.assigned_to_id = u.id
            LEFT JOIN users uc ON t.created_by_id = uc.id
            WHERE t.id = ?
        ''', (task_id, ))
        task_row = cursor.fetchone()
        if not task_row:
            conn.close()
            return jsonify({'error': 'Task not found'}), 404
        task = dict(task_row)

        # Activity history for this task
        cursor.execute(
            '''
            SELECT a.id, a.activity_type, a.description, a.user_id, u.username, a.project_id, a.task_id, a.created_at
            FROM activities a
            LEFT JOIN users u ON a.user_id = u.id
            WHERE a.task_id = ?
            ORDER BY a.created_at ASC
        ''', (task_id, ))
        history_rows = cursor.fetchall()
        history = [dict(r) for r in history_rows]

        conn.close()

        return jsonify({'task': task, 'history': history}), 200
    except Exception as e:
        logger.exception('task_history failed')
        return jsonify({'error': str(e)}), 500


@app.route("/api/admin/user-hierarchy", methods=["GET"])
@admin_required
def get_user_hierarchy():
    """
    Build a user hierarchy:
    Super Admin -> Coordinators/Managers -> Team Members -> Tasks
    Returns JSON tree for frontend rendering.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get coordinators/managers (heuristic: user_role contains 'coordinator' or 'manager' or 'admin')
        cursor.execute('''
            SELECT u.id, u.username, ut.user_role 
            FROM users u 
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            ORDER BY u.username
        ''')
        all_users = [dict(r) for r in cursor.fetchall()]

        # classify users
        coordinators = [
            u for u in all_users if u.get('user_role') and (
                'coordinator' in u['user_role'].lower() or 'manager' in
                u['user_role'].lower() or 'admin' in u['user_role'].lower())
        ]
        team_members = [u for u in all_users if u not in coordinators]

        # build nodes
        tree = []
        # Super Admin node (root)
        super_admin_node = {
            'name': 'Super Admin',
            'role': 'Full Access',
            'icon': 'fas fa-crown',
            'class': 'super-admin',
            'children': []
        }

        # coordinators
        coord_nodes = []
        for c in coordinators:
            coord_node = {
                'name': c['username'],
                'role': c.get('user_role') or 'Coordinator',
                'icon': 'fas fa-user-tie',
                'class': 'coordinator',
                'user_id': c['id'],
                'children': []
            }

            # assign team members that are assigned to any project where coordinator is creator or assigned - heuristic:
            cursor.execute(
                '''
                SELECT DISTINCT u.id, u.username, ut.user_role
                FROM users u
                LEFT JOIN usertypes ut ON u.user_type_id = ut.id
                LEFT JOIN project_assignments pa ON u.id = pa.user_id
                LEFT JOIN projects p ON pa.project_id = p.id
                WHERE p.created_by_id = ? 
                OR p.id IN (SELECT project_id FROM project_assignments WHERE user_id = ?)
            ''', (c['id'], c['id']))
            members = [dict(r) for r in cursor.fetchall()]
            # If no members found by that query, attach some team members heuristically
            if not members:
                members = [m for m in team_members[:3]]  # limit small sample

            for m in members:
                # fetch tasks for each member
                cursor.execute(
                    '''
                    SELECT id, title, status FROM tasks WHERE assigned_to_id = ? ORDER BY created_at DESC LIMIT 10
                ''', (m['id'], ))
                member_tasks = [dict(r) for r in cursor.fetchall()]
                coord_node['children'].append({
                    'name': m['username'],
                    'role': m.get('user_role') or 'Team Member',
                    'icon': 'fas fa-user',
                    'class': 'team-member',
                    'user_id': m['id'],
                    'children':
                    member_tasks  # tasks as children (task objects)
                })

            coord_nodes.append(coord_node)

        super_admin_node['children'] = coord_nodes
        tree.append(super_admin_node)

        conn.close()
        return jsonify(tree), 200
    except Exception as e:
        logger.exception('get_user_hierarchy failed')
        return jsonify({'error': str(e)}), 500


@app.route("/api/dashboard/live-progress", methods=["GET"])
@login_required
def get_live_dashboard_progress_enhanced():
    """
    Enhance live progress endpoint: include overdue_tasks, pending_tasks counts per project
    This wraps existing logic but makes per-project overdue/pending counts explicit.
    """
    try:
        user_id = get_current_user_id()
        is_admin = session.get('admin') or session.get('user_type') == 'admin'

        conn = get_db_connection()
        cursor = conn.cursor()

        if is_admin:
            cursor.execute('''
                SELECT 
                    p.id,
                    p.title,
                    p.description,
                    p.status,
                    p.progress,
                    p.deadline,
                    p.reporting_time,
                    p.created_at,
                    p.updated_at,
                    u.username as creator_name,
                    COUNT(DISTINCT t.id) as total_tasks,
                    SUM(CASE WHEN t.status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                    COUNT(DISTINCT m.id) as total_milestones,
                    SUM(CASE WHEN m.status = 'Completed' THEN 1 ELSE 0 END) as completed_milestones,
                    COUNT(DISTINCT pa.user_id) as team_size
                FROM projects p
                LEFT JOIN users u ON p.created_by_id = u.id
                LEFT JOIN tasks t ON p.id = t.project_id
                LEFT JOIN milestones m ON p.id = m.project_id
                LEFT JOIN project_assignments pa ON p.id = pa.project_id
                WHERE p.status != 'Completed'
                GROUP BY p.id, u.username
                ORDER BY p.updated_at DESC
            ''')
            raw_projects = cursor.fetchall()
        else:
            cursor.execute(
                '''
                SELECT DISTINCT
                    p.id,
                    p.title,
                    p.description,
                    p.status,
                    p.progress,
                    p.deadline,
                    p.reporting_time,
                    p.created_at,
                    p.updated_at,
                    u.username as creator_name,
                    COUNT(DISTINCT t.id) as total_tasks,
                    SUM(CASE WHEN t.status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                    COUNT(DISTINCT m.id) as total_milestones,
                    SUM(CASE WHEN m.status = 'Completed' THEN 1 ELSE 0 END) as completed_milestones,
                    COUNT(DISTINCT pa.user_id) as team_size
                FROM projects p
                LEFT JOIN users u ON p.created_by_id = u.id
                LEFT JOIN tasks t ON p.id = t.project_id
                LEFT JOIN milestones m ON p.id = m.project_id
                LEFT JOIN project_assignments pa ON p.id = pa.project_id
                WHERE (p.created_by_id = ? OR p.id IN (
                    SELECT project_id FROM project_assignments WHERE user_id = ?
                ))
                AND p.status != 'Completed'
                GROUP BY p.id, u.username
                ORDER BY p.updated_at DESC
            ''', (user_id, user_id))
            raw_projects = cursor.fetchall()

        formatted_projects = []
        for project in raw_projects:
            p = dict(project)
            # compute overdue and pending counts
            cursor2 = conn.cursor()
            cursor2.execute(
                "SELECT COUNT(*) as overdue_count FROM tasks WHERE project_id = ? AND deadline < date('now') AND status != 'Completed'",
                (p['id'], ))
            overdue_count = cursor2.fetchone()['overdue_count'] or 0
            cursor2.execute(
                "SELECT COUNT(*) as pending_count FROM tasks WHERE project_id = ? AND status != 'Completed' AND (deadline IS NULL OR deadline >= date('now'))",
                (p['id'], ))
            pending_count = cursor2.fetchone()['pending_count'] or 0

            total_tasks = p.get('total_tasks') or 0
            completed = p.get('completed_tasks') or 0
            milestones_total = p.get('total_milestones') or 0
            milestones_completed = p.get('completed_milestones') or 0

            # health_status
            health_status = 'good' if (
                p.get('progress') or 0) >= 70 else 'warning' if (
                    p.get('progress') or 0) >= 40 else 'danger'

            p.update({
                'overdue_tasks': overdue_count,
                'pending_tasks': pending_count,
                'total_tasks': total_tasks,
                'completed_tasks': completed,
                'total_milestones': milestones_total,
                'completed_milestones': milestones_completed,
                'health_status': health_status
            })
            formatted_projects.append(p)

        # average progress
        avg_progress = 0
        if formatted_projects:
            avg_progress = round(
                sum(p.get('progress', 0)
                    for p in formatted_projects) / len(formatted_projects), 2)

        conn.close()
        return jsonify({
            "timestamp": datetime.now().isoformat(),
            "total_projects": len(formatted_projects),
            "average_progress": avg_progress,
            "projects": formatted_projects
        }), 200
    except Exception as e:
        logger.exception('get_live_dashboard_progress_enhanced failed')
        return jsonify({"error": str(e)}), 500


@app.route('/api/projects/<int:project_id>/milestones', methods=['GET'])
@login_required
def api_get_project_milestones(project_id):
    """Return milestones for a project (used by admin dashboard project detail)."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            SELECT id, title, description, due_date, status, weightage, created_by_id, created_at
            FROM milestones
            WHERE project_id = ?
            ORDER BY created_at DESC
        ''', (project_id,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify(rows), 200
    except Exception as e:
        logger.exception('api_get_project_milestones failed')
        return jsonify({'error': str(e)}), 500


@app.route("/api/projects/<int:project_id>/tasks", methods=["GET"])
@login_required
def get_project_tasks(project_id):
    """Get all tasks for a specific project"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT t.id, t.title, t.description, t.status, t.priority, 
                   t.deadline, t.project_id, p.title as project_name,
                   t.assigned_to_id, u.username as assigned_to_name,
                   t.created_by_id, uc.username as created_by_name,
                   t.created_at, t.approval_status, t.completed_at
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            LEFT JOIN users u ON t.assigned_to_id = u.id
            LEFT JOIN users uc ON t.created_by_id = uc.id
            WHERE t.project_id = ?
            ORDER BY t.created_at DESC
        ''', (project_id, ))

        tasks = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in tasks]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/milestones", methods=["GET"])
@admin_required
def get_admin_milestones():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT m.id, m.title, m.description, m.status, m.due_date,
                   m.project_id, p.title as project_name,
                   m.created_by_id, u.username as created_by_name,
                   m.created_at
            FROM milestones m
            LEFT JOIN projects p ON m.project_id = p.id
            LEFT JOIN users u ON m.created_by_id = u.id
            ORDER BY m.due_date ASC
        ''')

        milestones = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in milestones]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


def log_activity(user_id,
                 activity_type,
                 description,
                 project_id=None,
                 task_id=None,
                 milestone_id=None):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO activities (user_id, activity_type, description, project_id, task_id, milestone_id)
            VALUES (?,?,?,?,?,?)
        ''', (user_id, activity_type, description, project_id, task_id,
              milestone_id))
        conn.commit()
    except Exception as e:
        print(f"[ERROR] Failed to log activity: {str(e)}")
    finally:
        if conn:
            conn.close()


@app.route("/api/employee/skills", methods=["GET"])
@login_required
def get_employee_skills():
    """Get all skills for the logged-in employee"""
    try:
        user_id = session.get('user_id')
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT id, skill_name, created_at 
            FROM user_skills 
            WHERE user_id = ?
            ORDER BY skill_name
        ''', (user_id, ))

        skills = cursor.fetchall()
        conn.close()

        return jsonify([dict(row) for row in skills]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/skills", methods=["POST"])
@login_required
def add_employee_skill():
    """Add a new skill for the logged-in employee"""
    try:
        data = request.get_json() or {}
        skill_name = (data.get("skill_name") or "").strip()

        if not skill_name:
            return jsonify({"error": "Skill name is required"}), 400

        user_id = session.get('user_id')
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                '''
                INSERT INTO user_skills (user_id, skill_name)
                VALUES (?, ?)
            ''', (user_id, skill_name))
            skill_id = cursor.lastrowid
            conn.commit()
            conn.close()

            return jsonify({
                "id": skill_id,
                "skill_name": skill_name,
                "message": "Skill added successfully!"
            }), 201
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({"error": "Skill already exists"}), 409

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/skills/<int:skill_id>", methods=["DELETE"])
@login_required
def delete_employee_skill(skill_id):
    """Delete a skill for the logged-in employee"""
    try:
        user_id = session.get('user_id')
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            'SELECT id FROM user_skills WHERE id = ? AND user_id = ?',
            (skill_id, user_id))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Skill not found"}), 404

        cursor.execute('DELETE FROM user_skills WHERE id = ? AND user_id = ?',
                       (skill_id, user_id))
        conn.commit()
        conn.close()

        return jsonify({"message": "Skill deleted successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/profile", methods=["GET"])
@login_required
def get_employee_profile():
    """Get profile for the logged-in employee"""
    try:
        user_id = get_current_user_id()
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT u.id, u.username, u.email, u.user_type_id, ut.user_role,
                   u.phone, u.department, u.bio, u.avatar_url, u.created_at
            FROM users u
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            WHERE u.id = ?
        ''', (user_id, ))

        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({"error": "User not found"}), 404

        cursor.execute(
            '''
            SELECT skill_name FROM user_skills WHERE user_id = ? ORDER BY skill_name
        ''', (user_id, ))
        skills = [row['skill_name'] for row in cursor.fetchall()]

        # 1. Get Direct User Permissions
        cursor.execute('''
            SELECT module, action, granted FROM user_permissions 
            WHERE user_id = ? ORDER BY module, action
        ''', (user_id, ))
        direct_perms = cursor.fetchall()

        # 2. Get Role-based (UserType) Permissions
        cursor.execute('''
            SELECT module, action, granted FROM usertype_permissions 
            WHERE usertype_id = ? ORDER BY module, action
        ''', (user['user_type_id'], ))
        role_perms = cursor.fetchall()

        conn.close()

        # Merge permissions (Direct takes precedence)
        permissions = {}
        
        # Add role permissions first
        for perm in role_perms:
            module = perm['module']
            if module not in permissions:
                permissions[module] = {}
            permissions[module][perm['action']] = bool(perm['granted'])
            
        # Add direct permissions (overwriting if necessary)
        for perm in direct_perms:
            module = perm['module']
            if module not in permissions:
                permissions[module] = {}
            permissions[module][perm['action']] = bool(perm['granted'])

        profile = dict(user)
        profile['skills'] = skills
        profile['permissions'] = permissions

        return jsonify(profile), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/profile", methods=["PUT"])
@login_required
def update_employee_profile():
    """Update profile for the logged-in employee with validation"""
    try:
        data = request.get_json() or {}
        user_id = get_current_user_id()
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401

        phone = data.get("phone", "").strip() if data.get("phone") else None
        department = data.get("department",
                              "").strip() if data.get("department") else None
        bio = data.get("bio", "").strip() if data.get("bio") else None

        if phone and len(phone) > 20:
            return jsonify({"error": "Phone number too long"}), 400
        if department and len(department) > 100:
            return jsonify({"error": "Department name too long"}), 400
        if bio and len(bio) > 500:
            return jsonify({"error": "Bio too long"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            UPDATE users 
            SET phone = ?, department = ?, bio = ?
            WHERE id = ?
        ''', (phone, department, bio, user_id))

        conn.commit()
        conn.close()

        return jsonify({"message": "Profile updated successfully!"}), 200
    except Exception as e:
        print(f"[ERROR] Profile update failed: {str(e)}")
        return jsonify({"error": f"Update failed: {str(e)}"}), 500


@app.route("/api/admin/profile", methods=["GET"])
@admin_required
def get_admin_profile():
    """Get admin profile"""
    return jsonify({
        "name": "Super Admin",
        "email": ADMIN_EMAIL,
        "role": "Administrator",
        "department": "Administration",
        "created_at": datetime.now().isoformat()
    }), 200


def allowed_file(filename):
    """Check if file has allowed extension"""
    return '.' in filename and filename.rsplit(
        '.', 1)[1].lower() in ALLOWED_EXTENSIONS


def optimize_image(image_file, max_width=500, max_height=500):
    """
    Optimize and validate uploaded image
    Resize to reasonable dimensions and compress for efficient storage
    Returns: BytesIO object with optimized image bytes
    """
    try:
        img = Image.open(image_file)

        # Convert RGBA to RGB if necessary
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            background.paste(
                img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
            img = background

        # Resize image maintaining aspect ratio
        img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)

        # Save optimized image to BytesIO
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=85, optimize=True)
        output.seek(0)

        return output
    except Exception as e:
        print(f"Error optimizing image: {str(e)}")
        raise


@app.route("/api/employee/profile/upload-avatar", methods=["POST"])
@login_required
def upload_avatar():
    """Upload and optimize profile avatar"""
    try:
        if 'avatar' not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files['avatar']
        if not file.filename:
            return jsonify({"error": "No file selected"}), 400

        if not allowed_file(file.filename):
            return jsonify({
                "error":
                "Invalid file type. Only PNG, JPG, JPEG, GIF, and WebP are allowed"
            }), 400

        user_id = get_current_user_id()

        # Ensure upload folder exists
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        # Optimize image
        try:
            optimized_image_bytes = optimize_image(file)
        except Exception as e:
            print(f"[ERROR] Failed to optimize image: {str(e)}")
            return jsonify(
                {"error":
                 "Failed to process image. Please try another file."}), 400

        # Generate secure filename
        filename = f"{user_id}_{secrets.token_hex(8)}.jpg"
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        try:
            # Save optimized image bytes to file
            with open(file_path, 'wb') as f:
                f.write(optimized_image_bytes.getvalue())
        except Exception as save_error:
            print(f"[ERROR] Error saving avatar: {str(save_error)}")
            return jsonify({
                "error":
                "Failed to save file to server. Check folder permissions."
            }), 500

        # Update database with new avatar URL
        conn = get_db_connection()
        cursor = conn.cursor()

        avatar_url = f"/uploads/profiles/{filename}"

        try:
            cursor.execute('UPDATE users SET avatar_url = ? WHERE id = ?',
                           (avatar_url, user_id))
            conn.commit()
        except sqlite3.OperationalError as db_error:
            # If column doesn't exist, add it
            if "no such column: avatar_url" in str(db_error):
                try:
                    cursor.execute(
                        'ALTER TABLE users ADD COLUMN avatar_url TEXT')
                    conn.commit()
                    cursor.execute(
                        'UPDATE users SET avatar_url = ? WHERE id = ?',
                        (avatar_url, user_id))
                    conn.commit()
                    print(f"[INFO] Added avatar_url column for user {user_id}")
                except Exception as alter_error:
                    conn.close()
                    print(
                        f"[ERROR] Failed to add avatar_url column: {str(alter_error)}"
                    )
                    return jsonify({
                        "error":
                        "Database configuration issue. Please contact administrator."
                    }), 500

        conn.close()

        return jsonify({
            "message": "Profile picture uploaded successfully!",
            "avatar_url": avatar_url
        }), 200

    except Exception as e:
        print(f"[ERROR] Error uploading avatar: {str(e)}")
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500


@app.route("/api/employee/profile/avatar", methods=["DELETE"])
@login_required
def delete_avatar():
    """
    Enhanced avatar deletion with proper file cleanup
    """
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT avatar_url FROM users WHERE id = ?',
                       (user_id, ))
        user = cursor.fetchone()

        if not user or not user['avatar_url']:
            conn.close()
            return jsonify({"error": "No profile picture found"}), 404

        # Delete file from storage
        filename = user['avatar_url'].split('/')[-1]
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except OSError:
            pass

        # Update database
        cursor.execute('UPDATE users SET avatar_url = NULL WHERE id = ?',
                       (user_id, ))
        conn.commit()
        conn.close()

        return jsonify({"message":
                        "Profile picture deleted successfully!"}), 200

    except Exception as e:
        print(f"[v0] Error deleting avatar: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/uploads/profiles/<path:filename>")
def serve_profile_picture(filename):
    """
    Serve profile pictures with proper security
    Validates filename before serving
    """
    try:
        # Security check: only allow alphanumeric and underscores
        if not re.match(r'^[\w\-]+\.jpg$', filename):
            return jsonify({"error": "Invalid file"}), 400

        return send_from_directory(UPLOAD_FOLDER,
                                   filename,
                                   as_attachment=False)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


@app.route("/api/projects/<int:project_id>/progress", methods=["GET"])
@login_required
def get_project_progress(project_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Count total tasks
        cursor.execute(
            "SELECT COUNT(*) as total FROM tasks WHERE project_id = ?",
            (project_id, ))
        total = cursor.fetchone()["total"]

        # Count completed tasks
        cursor.execute(
            "SELECT COUNT(*) as completed FROM tasks WHERE project_id = ? AND status = 'Completed'",
            (project_id, ))
        completed = cursor.fetchone()["completed"]

        # Avoid division by zero
        progress = 0
        if total > 0:
            progress = int((completed / total) * 100)

        # Save progress in DB
        cursor.execute(
            "UPDATE projects SET progress = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (progress, project_id))
        conn.commit()
        conn.close()

        return jsonify({"project_id": project_id, "progress": progress}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/employee/documents/<int:doc_id>/download", methods=["GET"])
@login_required
def download_document(doc_id):
    """Download a document file with proper error handling"""
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if user has access to this document
        cursor.execute(
            '''
            SELECT d.filename, d.original_filename, d.project_id
            FROM documents d
            WHERE d.id = ? AND (
                d.uploaded_by_id = ? OR 
                d.project_id IN (
                    SELECT project_id FROM project_assignments WHERE user_id = ?
                ) OR
                d.project_id IN (
                    SELECT id FROM projects WHERE created_by_id = ?
                )
            )
        ''', (doc_id, user_id, user_id, user_id))

        doc = cursor.fetchone()
        conn.close()

        if not doc:
            return jsonify({"error":
                            "Document not found or access denied"}), 404

        file_path = os.path.join('uploads', 'documents', doc['filename'])

        if not os.path.exists(file_path):
            print(f"[ERROR] File not found at path: {file_path}")
            return jsonify({"error": "File not found on server"}), 404

        # Log download activity
        log_activity(user_id,
                     'document_downloaded',
                     f'Downloaded document: {doc["original_filename"]}',
                     project_id=doc['project_id'])

        return send_from_directory('uploads/documents',
                                   doc['filename'],
                                   as_attachment=True,
                                   download_name=doc['original_filename'])

    except Exception as e:
        print(f"[ERROR] Document download failed: {str(e)}")
        return jsonify({"error": f"Download failed: {str(e)}"}), 500


@app.route("/api/admin/documents/<int:doc_id>/download", methods=["GET"])
@admin_required
def admin_download_document(doc_id):
    """Admin download a document file"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT filename, original_filename, project_id
            FROM documents
            WHERE id = ?
        ''', (doc_id, ))

        doc = cursor.fetchone()
        conn.close()

        if not doc:
            return jsonify({"error": "Document not found"}), 404

        file_path = os.path.join('uploads', 'documents', doc['filename'])

        if not os.path.exists(file_path):
            print(
                f"[ERROR] Admin document file not found at path: {file_path}")
            return jsonify({"error": "File not found on server"}), 404

        return send_from_directory('uploads/documents',
                                   doc['filename'],
                                   as_attachment=True,
                                   download_name=doc['original_filename'])

    except Exception as e:
        print(f"[ERROR] Admin document download failed: {str(e)}")
        return jsonify({"error": f"Download failed: {str(e)}"}), 500


# Enhanced profile stats endpoint
@app.route("/api/employee/profile/stats", methods=["GET"])
@login_required
def get_employee_profile_stats():
    """Get detailed profile statistics for employee"""
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        # Total projects
        cursor.execute(
            '''
            SELECT COUNT(DISTINCT id) as count FROM projects 
            WHERE created_by_id = ? OR id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            )
        ''', (user_id, user_id))
        total_projects = cursor.fetchone()['count']

        # Completed tasks
        cursor.execute(
            '''
            SELECT COUNT(*) as count FROM tasks 
            WHERE (assigned_to_id = ? OR created_by_id = ?) AND status = 'Completed'
        ''', (user_id, user_id))
        completed_tasks = cursor.fetchone()['count']

        # Pending tasks
        cursor.execute(
            '''
            SELECT COUNT(*) as count FROM tasks 
            WHERE (assigned_to_id = ? OR created_by_id = ?) 
            AND status != 'Completed'
        ''', (user_id, user_id))
        pending_tasks = cursor.fetchone()['count']

        # Total milestones
        cursor.execute(
            '''
            SELECT COUNT(*) as count FROM milestones m
            WHERE m.project_id IN (
                SELECT id FROM projects WHERE created_by_id = ?
                OR id IN (SELECT project_id FROM project_assignments WHERE user_id = ?)
            )
        ''', (user_id, user_id))
        total_milestones = cursor.fetchone()['count']

        # Completed milestones
        cursor.execute(
            '''
            SELECT COUNT(*) as count FROM milestones m
            WHERE m.status = 'Completed' AND m.project_id IN (
                SELECT id FROM projects WHERE created_by_id = ?
                OR id IN (SELECT project_id FROM project_assignments WHERE user_id = ?)
            )
        ''', (user_id, user_id))
        completed_milestones = cursor.fetchone()['count']

        # Documents uploaded
        cursor.execute(
            '''
            SELECT COUNT(*) as count FROM documents WHERE uploaded_by_id = ?
        ''', (user_id, ))
        documents_uploaded = cursor.fetchone()['count']

        conn.close()

        return jsonify({
            "total_projects":
            total_projects,
            "completed_tasks":
            completed_tasks,
            "pending_tasks":
            pending_tasks,
            "total_milestones":
            total_milestones,
            "completed_milestones":
            completed_milestones,
            "documents_uploaded":
            documents_uploaded,
            "completion_rate":
            round((completed_tasks /
                   (completed_tasks + pending_tasks) * 100), 2) if
            (completed_tasks + pending_tasks) > 0 else 0
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/projects/realtime", methods=["GET"])
@admin_required
def get_admin_realtime_projects():
    """Get real-time project updates for admin dashboard"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT p.id, p.title, p.description, p.status, p.progress,
                   p.deadline, p.reporting_time, p.created_at, p.updated_at,
                   u.username as creator_name,
                   COUNT(DISTINCT t.id) as total_tasks,
                   SUM(CASE WHEN t.status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                   COUNT(DISTINCT m.id) as total_milestones,
                   SUM(CASE WHEN m.status = 'Completed' THEN 1 ELSE 0 END) as completed_milestones,
                   COUNT(DISTINCT pa.user_id) as team_size
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            LEFT JOIN tasks t ON p.id = t.project_id
            LEFT JOIN milestones m ON p.id = m.project_id
            LEFT JOIN project_assignments pa ON p.id = pa.project_id
            WHERE p.status != 'Completed'
            GROUP BY p.id, u.username
            ORDER BY p.updated_at DESC
        ''')

        projects = cursor.fetchall()
        conn.close()

        result = []
        for row in projects:
            project_dict = dict(row)
            project_dict['completed_tasks'] = project_dict.get(
                'completed_tasks') or 0
            project_dict['total_tasks'] = project_dict.get('total_tasks') or 0
            project_dict['completed_milestones'] = project_dict.get(
                'completed_milestones') or 0
            project_dict['total_milestones'] = project_dict.get(
                'total_milestones') or 0
            project_dict['progress'] = project_dict.get('progress') or 0
            result.append(project_dict)

        return jsonify(result), 200
    except Exception as e:
        print(f"[ERROR] Admin realtime projects error: {str(e)}")
        return jsonify({"error": str(e)}), 500


# Get specific project details for admin
@app.route("/api/admin/projects/<int:project_id>", methods=["GET"])
@admin_required
def get_admin_project_detail(project_id):
    """Get detailed project information"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT p.*, u.username as creator_name,
                   COUNT(DISTINCT t.id) as total_tasks,
                   COUNT(DISTINCT m.id) as total_milestones
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            LEFT JOIN tasks t ON p.id = t.project_id
            LEFT JOIN milestones m ON p.id = m.project_id
            WHERE p.id = ?
            GROUP BY p.id, u.username
        ''', (project_id, ))

        project = cursor.fetchone()
        conn.close()

        if not project:
            return jsonify({"error": "Project not found"}), 404

        return jsonify(dict(project)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Update project (admin)
@app.route("/api/admin/projects/<int:project_id>", methods=["PUT"])
@admin_required
def admin_update_project(project_id):
    """Update project fields: title, description, status, deadline"""
    try:
        data = request.get_json() or {}
        title = data.get('title')
        description = data.get('description')
        status = data.get('status')
        deadline = data.get('deadline')  # expected YYYY-MM-DD or empty

        # Minimal validation
        if title is not None and len(title) > 255:
            return jsonify({"error": "Title too long"}), 400
        if description is not None and len(description) > 2000:
            return jsonify({"error": "Description too long"}), 400

        # Validate deadline format if provided
        if deadline:
            try:
                # accept date-only ISO
                datetime.strptime(deadline, '%Y-%m-%d')
            except Exception:
                return jsonify(
                    {"error": "Invalid deadline format. Use YYYY-MM-DD."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Ensure project exists
        cursor.execute('SELECT id FROM projects WHERE id = ?', (project_id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Project not found"}), 404

        # Build update statement dynamically
        updates = []
        params = []
        if title is not None:
            updates.append('title = ?')
            params.append(title)
        if description is not None:
            updates.append('description = ?')
            params.append(description)
        if status is not None:
            updates.append('status = ?')
            params.append(status)
        if deadline is not None:
            # allow clearing deadline by sending empty string
            updates.append('deadline = ?')
            params.append(deadline if deadline != '' else None)

        if updates:
            params.append(project_id)
            stmt = f"UPDATE projects SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
            cursor.execute(stmt, tuple(params))
            conn.commit()

        # Return updated project summary
        cursor.execute(
            '''
            SELECT p.id, p.title, p.description, p.status, p.progress, p.deadline, u.username as creator_name,
                   (SELECT COUNT(*) FROM project_assignments pa WHERE pa.project_id = p.id) as team_count,
                   (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id) as task_count
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            WHERE p.id = ?
        ''', (project_id, ))
        proj = cursor.fetchone()
        conn.close()

        if not proj:
            return jsonify({"error": "Project not found after update"}), 404

        result = dict(proj)
        return jsonify({
            "message": "Project updated successfully",
            "project": result
        }), 200

    except Exception as e:
        print(f"[ERROR] admin_update_project: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/projects/<int:project_id>/add-member", methods=["POST"])
@admin_required
def admin_add_project_member(project_id):
    """Add a member to a project by user id or email (payload: { member: "email or id" })"""
    try:
        data = request.get_json() or {}
        member = (data.get('member') or '').strip()
        if not member:
            return jsonify({"error": "Member id or email is required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # verify project exists
        cursor.execute('SELECT id FROM projects WHERE id = ?', (project_id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Project not found"}), 404

        user_id = None
        # if member looks like an integer id
        if re.fullmatch(r'\d+', member):
            cursor.execute('SELECT id FROM users WHERE id = ?',
                           (int(member), ))
            row = cursor.fetchone()
            if row:
                user_id = row['id']
        else:
            # try email lookup
            cursor.execute('SELECT id FROM users WHERE LOWER(email) = ?',
                           (member.lower(), ))
            row = cursor.fetchone()
            if row:
                user_id = row['id']

        if not user_id:
            conn.close()
            return jsonify({"error": "User not found"}), 404

        try:
            cursor.execute(
                'INSERT INTO project_assignments (user_id, project_id) VALUES (?, ?)',
                (user_id, project_id))
            conn.commit()
        except sqlite3.IntegrityError:
            # already assigned
            pass

        # count team size
        cursor.execute(
            'SELECT COUNT(*) as cnt FROM project_assignments WHERE project_id = ?',
            (project_id, ))
        team_count = cursor.fetchone()['cnt']

        # log activity
        try:
            log_activity(session.get('user_id') or 0,
                         'project_member_added',
                         f'Added user {user_id} to project {project_id}',
                         project_id=project_id)
        except Exception:
            pass

        conn.close()
        return jsonify({
            "message": "Member added to project",
            "team_count": team_count
        }), 200

    except Exception as e:
        print(f"[ERROR] admin_add_project_member: {e}")
        return jsonify({"error": str(e)}), 500


# Get specific task details for admin
@app.route("/api/admin/tasks/<int:task_id>", methods=["GET"])
@admin_required
def get_admin_task_detail(task_id):
    """Get detailed task information"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT t.*, p.title as project_name,
                   u.username as assigned_to_name,
                   uc.username as created_by_name
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            LEFT JOIN users u ON t.assigned_to_id = u.id
            LEFT JOIN users uc ON t.created_by_id = uc.id
            WHERE t.id = ?
        ''', (task_id, ))

        task = cursor.fetchone()
        conn.close()

        if not task:
            return jsonify({"error": "Task not found"}), 404

        return jsonify(dict(task)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Employee real-time projects endpoint with live progress calculation
@app.route("/api/employee/projects/realtime", methods=["GET"])
@login_required
def get_employee_realtime_projects():
    """Get real-time project updates with calculated progress percentage"""
    try:
        user_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT DISTINCT p.id, p.title, p.description, p.status,
                   p.deadline, p.reporting_time, p.created_at, p.updated_at,
                   u.username as creator_name,
                   COUNT(DISTINCT t.id) as total_tasks,
                   SUM(CASE WHEN t.status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                   COUNT(DISTINCT m.id) as total_milestones,
                   SUM(CASE WHEN m.status = 'Completed' THEN 1 ELSE 0 END) as completed_milestones,
                   COUNT(DISTINCT pa.user_id) as team_size
            FROM projects p
            LEFT JOIN users u ON p.created_by_id = u.id
            LEFT JOIN tasks t ON p.id = t.project_id
            LEFT JOIN milestones m ON p.id = m.project_id
            LEFT JOIN project_assignments pa ON p.id = pa.project_id
            WHERE (p.created_by_id = ? OR p.id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            )) AND p.status != 'Completed'
            GROUP BY p.id, u.username
            ORDER BY p.updated_at DESC
        ''', (user_id, user_id))

        projects = cursor.fetchall()

        # Calculate live progress percentage for each project
        result = []
        for row in projects:
            project_dict = dict(row)
            total_tasks = project_dict.get('total_tasks') or 0
            completed_tasks = project_dict.get('completed_tasks') or 0
            total_milestones = project_dict.get('total_milestones') or 0
            completed_milestones = project_dict.get(
                'completed_milestones') or 0

            # Calculate progress: if no tasks, progress is 0
            if total_tasks > 0:
                progress = int((completed_tasks / total_tasks) * 100)
            elif total_milestones > 0:
                progress = int((completed_milestones / total_milestones) * 100)
            else:
                progress = 0

            project_dict['progress'] = progress
            project_dict['completed_tasks'] = completed_tasks
            project_dict['total_tasks'] = total_tasks
            project_dict['completed_milestones'] = completed_milestones
            project_dict['total_milestones'] = total_milestones
            result.append(project_dict)

        conn.close()
        return jsonify(result), 200
    except Exception as e:
        print(f"[ERROR] Realtime projects error: {str(e)}")
        conn.close()
        return jsonify({"error": str(e)}), 500


def check_db_initialized():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='usertypes'
        """)
        exists = cursor.fetchone() is not None
        cursor.close()
        conn.close()
        return exists
    except Exception as e:
        print("DB check failed:", e)
        return False


def safe_init_db():
    try:
        if not check_db_initialized():
            init_db()
    except Exception as e:
        print("DB init skipped:", e)


safe_init_db()
# Always attempt a safe migration pass to add missing columns/tables without wiping data
migrate_db()


def update_project_status(project_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get total + completed tasks
    cursor.execute(
        """
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status='Completed' THEN 1 ELSE 0 END) as completed
        FROM tasks 
        WHERE project_id = ?
    """, (project_id, ))
    row = cursor.fetchone()

    total = row['total']
    completed = row['completed']

    # Decide project status
    new_status = None
    if total == 0:
        new_status = 'Pending'
    elif completed == total:
        new_status = 'Completed'
    else:
        new_status = 'In Progress'

        cursor.execute("UPDATE projects SET status = ? WHERE id = ?",
                       (new_status, project_id))

    conn.commit()
    conn.close()


@app.route("/api/admin/employees/<int:employee_id>/profile", methods=["GET"])
@admin_required
def get_employee_profile_admin(employee_id):
    """Admin endpoint to get an employee's profile details"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT u.id, u.username, u.email, u.user_type_id, ut.user_role,
                   u.phone, u.department, u.bio, u.avatar_url, u.created_at
            FROM users u
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            WHERE u.id = ?
        ''', (employee_id, ))

        user = cursor.fetchone()
        if not user:
            conn.close()
            return jsonify({"error": "Employee not found"}), 404

        # Get skills
        cursor.execute(
            '''
            SELECT skill_name FROM user_skills WHERE user_id = ? ORDER BY skill_name
        ''', (employee_id, ))
        skills = [row['skill_name'] for row in cursor.fetchall()]

        # Get stats
        cursor.execute(
            '''
            SELECT COUNT(DISTINCT id) as count FROM projects 
            WHERE created_by_id = ? OR id IN (
                SELECT project_id FROM project_assignments WHERE user_id = ?
            )
        ''', (employee_id, employee_id))
        projects_count = cursor.fetchone()['count']

        cursor.execute(
            '''
            SELECT COUNT(*) as count FROM tasks 
            WHERE assigned_to_id = ? AND status = 'Completed'
        ''', (employee_id, ))
        tasks_completed = cursor.fetchone()['count']

        cursor.execute(
            '''
            SELECT COUNT(*) as count FROM documents WHERE uploaded_by_id = ?
        ''', (employee_id, ))
        documents_count = cursor.fetchone()['count']

        conn.close()

        profile = dict(user)
        profile['skills'] = skills
        profile['stats'] = {
            'projects': projects_count,
            'tasks_completed': tasks_completed,
            'documents': documents_count
        }

        return jsonify(profile), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Daily Task Reports Endpoints - IMPROVED
@app.route("/api/admin/daily-reports", methods=["GET"])
@admin_required
def get_daily_reports():
    """Get all daily task reports for admin viewing with filtering"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Get query parameters for filtering
        employee_id = request.args.get('employee_id')
        project_id = request.args.get('project_id')
        report_date = request.args.get('date')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        approval_status = request.args.get('approval_status')
        search = request.args.get('search', '')

        query = '''
            SELECT 
                dtr.id, 
                dtr.report_date,
                u.username as employee_name,
                u.email as employee_email,
                p.title as project_name,
                t.title as task_title,
                dtr.task_id,
                assigned_by.username as assigned_by_name,
                dtr.communication_details,
                dtr.result_of_effort,
                dtr.remarks,
                dtr.work_description,
                dtr.time_spent,
                dtr.status,
                dtr.blocker,
                dtr.approval_status,
                dtr.review_comment,
                dtr.reviewed_by,
                reviewer.username as reviewer_name,
                dtr.created_at,
                dtr.updated_at
            FROM daily_task_reports dtr
            JOIN users u ON dtr.user_id = u.id
            LEFT JOIN projects p ON dtr.project_id = p.id
            LEFT JOIN tasks t ON dtr.task_id = t.id
            LEFT JOIN users assigned_by ON dtr.task_assigned_by_id = assigned_by.id
            LEFT JOIN users reviewer ON dtr.reviewed_by = reviewer.id
            WHERE 1=1
        '''
        params = []

        if employee_id:
            query += ' AND dtr.user_id = ?'
            params.append(employee_id)
        if project_id:
            query += ' AND dtr.project_id = ?'
            params.append(project_id)
        if report_date:
            query += ' AND dtr.report_date = ?'
            params.append(report_date)
        if start_date:
            query += ' AND dtr.report_date >= ?'
            params.append(start_date)
        if end_date:
            query += ' AND dtr.report_date <= ?'
            params.append(end_date)
        if approval_status:
            query += ' AND dtr.approval_status = ?'
            params.append(approval_status)
        if search:
            query += ' AND (dtr.work_description LIKE ? OR dtr.result_of_effort LIKE ? OR t.title LIKE ?)'
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

        query += ' ORDER BY dtr.report_date DESC, dtr.created_at DESC'

        cursor.execute(query, params)
        reports = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return jsonify(reports), 200
    except Exception as e:
        logger.exception("Error getting daily reports")
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/daily-reports/<int:report_id>/review', methods=['POST'])
@admin_required
def review_daily_report(report_id):
    """Admin reviews (approve/reject) a daily report"""
    try:
        data = request.get_json() or {}
        approval = data.get('approval_status')
        comment = data.get('review_comment', '')
        if approval not in ('approved', 'rejected', 'pending'):
            return jsonify({'error': 'Invalid approval_status'}), 400

        reviewer_id = get_current_user_id()
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if report exists
        cursor.execute('SELECT id FROM daily_task_reports WHERE id = ?',
                       (report_id, ))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Report not found'}), 404

        cursor.execute(
            '''UPDATE daily_task_reports SET approval_status = ?, reviewed_by = ?, review_comment = ?, updated_at = CURRENT_TIMESTAMP
                          WHERE id = ?''',
            (approval, reviewer_id, comment, report_id))
        conn.commit()

        # Log the review action
        log_activity(reviewer_id,
                     'report_reviewed',
                     f'Reviewed report {report_id} as {approval}',
                     target_type='daily_report',
                     target_id=report_id)

        conn.close()
        return jsonify({'success': True, 'approval_status': approval}), 200
    except Exception as e:
        logger.exception('Failed to review report')
        return jsonify({'error': str(e)}), 500


@app.route('/admin/daily-reports')
@admin_required
def admin_daily_reports_page():
    return render_template('admin-daily-reports.html')


@app.route("/api/employee/daily-report", methods=["POST"])
@login_required
def submit_daily_report():
    """Employee submits daily task report"""
    conn = None
    try:
        data = request.get_json() or {}
        employee_id = session.get('user_id')

        # Validate required fields
        required_fields = ['report_date', 'project_id', 'work_description']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"error":
                                f"Missing required field: {field}"}), 400

        project_id = data.get('project_id')
        task_id = data.get('task_id')

        # Ensure the employee is assigned to the project or the specific task
        conn = get_db_connection()
        cursor = conn.cursor()
        assigned = False

        try:
            # Check project assignment
            cursor.execute(
                'SELECT 1 FROM project_assignments WHERE user_id = ? AND project_id = ? LIMIT 1',
                (employee_id, project_id))
            if cursor.fetchone():
                assigned = True
            elif task_id:
                # Check task assignment
                cursor.execute(
                    'SELECT 1 FROM tasks WHERE id = ? AND assigned_to_id = ? LIMIT 1',
                    (task_id, employee_id))
                if cursor.fetchone():
                    assigned = True
        except Exception:
            assigned = False

        if not assigned:
            conn.close()
            return jsonify(
                {"error": "You are not assigned to this project or task"}), 403

        # Check for duplicate report for same date and task
        if task_id:
            cursor.execute(
                'SELECT id FROM daily_task_reports WHERE user_id = ? AND task_id = ? AND report_date = ?',
                (employee_id, task_id, data['report_date']))
            if cursor.fetchone():
                conn.close()
                return jsonify({
                    "error":
                    "A report for this task already exists for this date"
                }), 409

        # Prepare data for insertion
        work_description = data.get('work_description', '')
        time_spent = data.get('time_spent', 0)
        status = data.get('status', 'In Progress')
        blocker = data.get('blocker', '')
        report_date = data.get('report_date')
        result_of_effort = data.get('result_of_effort', '')
        remarks = data.get('remarks', '')
        communication_email = data.get('communication_email', '')
        communication_phone = data.get('communication_phone', '')
        task_assigned_by_id = data.get('task_assigned_by_id')

        try:
            cursor.execute(
                '''
                INSERT INTO daily_task_reports (
                    user_id, report_date, project_id, task_id,
                    work_description, time_spent, status, blocker, 
                    task_assigned_by_id, result_of_effort, remarks, 
                    communication_email, communication_phone, 
                    approval_status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''', (employee_id, report_date, project_id, task_id,
                  work_description, time_spent, status, blocker,
                  task_assigned_by_id, result_of_effort, remarks,
                  communication_email, communication_phone))

            conn.commit()
            report_id = cursor.lastrowid
            conn.close()

            # Log activity
            log_activity(employee_id,
                         'daily_report_submitted',
                         f'Submitted daily report for project {project_id}',
                         project_id=project_id,
                         target_type='daily_report',
                         target_id=report_id)

            return jsonify({
                "success": True,
                "report_id": report_id,
                "message": "Report submitted successfully"
            }), 201
        except sqlite3.IntegrityError as e:
            conn.close()
            logger.error(f"Integrity error submitting report: {e}")
            return jsonify({"error": "Database error occurred"}), 500
    except Exception as e:
        logger.exception("Error submitting daily report")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/daily-reports/stats", methods=["GET"])
@admin_required
def get_daily_reports_stats():
    """Get statistics for daily reports"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Total reports
        cursor.execute('SELECT COUNT(*) as count FROM daily_task_reports')
        total_reports = cursor.fetchone()['count']

        # Pending approvals
        cursor.execute(
            'SELECT COUNT(*) as count FROM daily_task_reports WHERE approval_status = "pending"'
        )
        pending_reports = cursor.fetchone()['count']

        # Approved reports
        cursor.execute(
            'SELECT COUNT(*) as count FROM daily_task_reports WHERE approval_status = "approved"'
        )
        approved_reports = cursor.fetchone()['count']

        # Rejected reports
        cursor.execute(
            'SELECT COUNT(*) as count FROM daily_task_reports WHERE approval_status = "rejected"'
        )
        rejected_reports = cursor.fetchone()['count']

        # Total hours logged
        cursor.execute(
            'SELECT COALESCE(SUM(time_spent), 0) as total_hours FROM daily_task_reports WHERE approval_status = "approved"'
        )
        total_hours = cursor.fetchone()['total_hours']

        # Reports today
        cursor.execute('''
            SELECT COUNT(*) as count FROM daily_task_reports
            WHERE report_date = DATE('now')
        ''')
        reports_today = cursor.fetchone()['count']

        # Reports this week
        cursor.execute('''
            SELECT COUNT(*) as count FROM daily_task_reports
            WHERE report_date >= DATE('now', '-7 days')
        ''')
        reports_week = cursor.fetchone()['count']

        # Unique employees with reports
        cursor.execute('''
            SELECT COUNT(DISTINCT user_id) as count FROM daily_task_reports
        ''')
        unique_employees = cursor.fetchone()['count']

        # Average hours per report
        avg_hours = 0
        if approved_reports > 0:
            avg_hours = total_hours / approved_reports

        conn.close()

        return jsonify({
            "total_reports": total_reports,
            "pending_reports": pending_reports,
            "approved_reports": approved_reports,
            "rejected_reports": rejected_reports,
            "total_hours_logged": float(total_hours),
            "avg_hours_per_report": round(float(avg_hours), 2),
            "reports_today": reports_today,
            "reports_week": reports_week,
            "unique_employees": unique_employees
        }), 200
    except Exception as e:
        logger.exception("Error getting daily reports stats")
        return jsonify({"error": str(e)}), 500


@app.route("/api/daily-reports/dashboard/stats", methods=["GET"])
@admin_required
def get_daily_reports_dashboard_stats():
    """Comprehensive daily reports statistics for Super Admin Dashboard"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Total metrics
        cursor.execute('SELECT COUNT(*) as count FROM daily_task_reports')
        total_reports = cursor.fetchone()['count']

        cursor.execute(
            'SELECT COUNT(*) as count FROM daily_task_reports WHERE approval_status = ?',
            ('approved', ))
        approved_reports = cursor.fetchone()['count']

        cursor.execute(
            'SELECT COUNT(*) as count FROM daily_task_reports WHERE approval_status = ?',
            ('pending', ))
        pending_reports = cursor.fetchone()['count']

        cursor.execute(
            'SELECT COUNT(*) as count FROM daily_task_reports WHERE approval_status = ?',
            ('rejected', ))
        rejected_reports = cursor.fetchone()['count']

        # Total hours
        cursor.execute(
            'SELECT COALESCE(SUM(time_spent), 0) as total FROM daily_task_reports WHERE approval_status = ?',
            ('approved', ))
        total_hours = cursor.fetchone()['total'] or 0

        # Average hours per report
        if approved_reports > 0:
            avg_hours = total_hours / approved_reports
        else:
            avg_hours = 0

        # Reports by status
        cursor.execute('''
            SELECT status, COUNT(*) as count FROM daily_task_reports GROUP BY status
        ''')
        status_breakdown = {
            row['status']: row['count']
            for row in cursor.fetchall()
        }

        # Reports by project (top 10)
        cursor.execute('''
            SELECT p.title, COUNT(d.id) as count
            FROM daily_task_reports d
            LEFT JOIN projects p ON d.project_id = p.id
            GROUP BY d.project_id
            ORDER BY count DESC
            LIMIT 10
        ''')
        top_projects = [{
            'project': row['title'],
            'count': row['count']
        } for row in cursor.fetchall()]

        # Reports by employee (top 10)
        cursor.execute('''
            SELECT u.username, COUNT(d.id) as count
            FROM daily_task_reports d
            LEFT JOIN users u ON d.user_id = u.id
            GROUP BY d.user_id
            ORDER BY count DESC
            LIMIT 10
        ''')
        top_employees = [{
            'employee': row['username'],
            'count': row['count']
        } for row in cursor.fetchall()]

        # Date range analytics
        cursor.execute('''
            SELECT 
                report_date,
                COUNT(*) as count,
                SUM(CASE WHEN approval_status = 'approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN approval_status = 'pending' THEN 1 ELSE 0 END) as pending,
                COALESCE(SUM(time_spent), 0) as hours
            FROM daily_task_reports
            GROUP BY report_date
            ORDER BY report_date DESC
            LIMIT 30
        ''')
        date_analytics = []
        for row in cursor.fetchall():
            date_analytics.append({
                'date': row['report_date'],
                'reports': row['count'],
                'approved': row['approved'],
                'pending': row['pending'],
                'hours': float(row['hours'])
            })

        # Date range analytics - for trend chart (last 7 days)
        cursor.execute('''
            SELECT report_date, COUNT(*) as count
            FROM daily_task_reports
            WHERE report_date >= DATE('now', '-7 days')
            GROUP BY report_date
            ORDER BY report_date ASC
        ''')
        daily_trend_data = {}
        for row in cursor.fetchall():
            daily_trend_data[row['report_date']] = row['count']

        # Create trend array for last 7 days
        daily_trend = []
        for i in range(7):
            d = (datetime.now() - timedelta(days=6 - i)).strftime('%Y-%m-%d')
            daily_trend.append(daily_trend_data.get(d, 0))

        conn.close()

        return jsonify({
            'summary': {
                'total_reports': total_reports,
                'approved': approved_reports,
                'pending': pending_reports,
                'rejected': rejected_reports,
                'total_hours': float(total_hours),
                'avg_hours_per_report': round(avg_hours, 2)
            },
            'by_status': status_breakdown,
            'top_projects': top_projects,
            'top_employees': top_employees,
            'date_analytics': date_analytics,
            'daily_trend': daily_trend
        }), 200
    except Exception as e:
        logger.exception('Error getting daily reports dashboard stats')
        return jsonify({'error': str(e)}), 500


@app.route("/api/admin/activity", methods=["POST"])
@admin_required
def admin_activity():
    """Record an arbitrary admin activity from the dashboard UI.
    This endpoint lets the frontend record admin actions as activities
    so they appear in the global activity feed.
    """
    data = request.get_json() or {}
    description = data.get('description', '')
    activity_type = data.get('activity_type', 'admin_action')
    project_id = data.get('project_id')
    task_id = data.get('task_id')
    milestone_id = data.get('milestone_id')
    target_type = data.get('target_type')
    target_id = data.get('target_id')

    try:
        # Use admin user id 0 for system/admin actions
        user_id = get_current_user_id()
        log_activity(user_id, activity_type, description, project_id, task_id,
                     milestone_id)

        # Also log to audit logs if it's a significant action
        if activity_type in [
                'report_reviewed', 'report_deleted', 'report_edited'
        ]:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO audit_logs (actor_id, action, target_type, target_id, details, created_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (user_id, activity_type, target_type, target_id, description))
            conn.commit()
            conn.close()

        return jsonify({'success': True}), 200
    except Exception as e:
        logger.exception('Failed to log admin activity')
        return jsonify({'success': False, 'error': str(e)}), 500


# NEW: Batch approval endpoint
@app.route("/api/admin/daily-reports/batch-approve", methods=["POST"])
@admin_required
def batch_approve_reports():
    """Approve multiple reports at once"""
    try:
        data = request.get_json() or {}
        report_ids = data.get('report_ids', [])
        action = data.get('action', 'approve')  # 'approve' or 'reject'
        comment = data.get('comment', '')

        if not report_ids:
            return jsonify({'error': 'No report IDs provided'}), 400

        if action not in ['approve', 'reject']:
            return jsonify({'error': 'Invalid action'}), 400

        reviewer_id = get_current_user_id()
        new_status = 'approved' if action == 'approve' else 'rejected'

        conn = get_db_connection()
        cursor = conn.cursor()

        # Update all reports
        placeholders = ','.join(['?'] * len(report_ids))
        cursor.execute(
            f'''
            UPDATE daily_task_reports 
            SET approval_status = ?, reviewed_by = ?, review_comment = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id IN ({placeholders})
        ''', [new_status, reviewer_id, comment] + report_ids)

        updated_count = cursor.rowcount
        conn.commit()

        # Log batch action
        log_activity(reviewer_id,
                     'batch_report_review',
                     f'{action.capitalize()}d {updated_count} reports',
                     target_type='daily_report_batch')

        conn.close()

        return jsonify({
            'success': True,
            'updated_count': updated_count,
            'action': action,
            'status': new_status
        }), 200

    except Exception as e:
        logger.exception("Error in batch approve")
        return jsonify({'error': str(e)}), 500


# NEW: Get report summary by employee
@app.route("/api/admin/daily-reports/employee-summary", methods=["GET"])
@admin_required
def get_employee_report_summary():
    """Get summary of reports by employee"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT 
                u.id as employee_id,
                u.username as employee_name,
                u.email as employee_email,
                COUNT(dtr.id) as total_reports,
                SUM(CASE WHEN dtr.approval_status = 'approved' THEN 1 ELSE 0 END) as approved_reports,
                SUM(CASE WHEN dtr.approval_status = 'pending' THEN 1 ELSE 0 END) as pending_reports,
                SUM(CASE WHEN dtr.approval_status = 'rejected' THEN 1 ELSE 0 END) as rejected_reports,
                COALESCE(SUM(dtr.time_spent), 0) as total_hours,
                MAX(dtr.report_date) as last_report_date
            FROM users u
            LEFT JOIN daily_task_reports dtr ON u.id = dtr.user_id
            WHERE u.user_type_id = (SELECT id FROM usertypes WHERE user_role = 'Employee')
            GROUP BY u.id, u.username, u.email
            ORDER BY u.username
        ''')

        employees = []
        for row in cursor.fetchall():
            employees.append({
                'employee_id': row['employee_id'],
                'employee_name': row['employee_name'],
                'employee_email': row['employee_email'],
                'total_reports': row['total_reports'] or 0,
                'approved_reports': row['approved_reports'] or 0,
                'pending_reports': row['pending_reports'] or 0,
                'rejected_reports': row['rejected_reports'] or 0,
                'total_hours': float(row['total_hours'] or 0),
                'last_report_date': row['last_report_date']
            })

        conn.close()
        return jsonify(employees), 200

    except Exception as e:
        logger.exception("Error getting employee report summary")
        return jsonify({'error': str(e)}), 500


# NEW: Get reports for a specific employee (admin view)
@app.route("/api/admin/employees/<int:employee_id>/daily-reports",
           methods=["GET"])
@admin_required
def get_employee_daily_reports(employee_id):
    """Get all daily reports for a specific employee"""
    try:
        # Get query parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        approval_status = request.args.get('approval_status')

        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify employee exists
        cursor.execute('SELECT id, username FROM users WHERE id = ?',
                       (employee_id, ))
        employee = cursor.fetchone()
        if not employee:
            conn.close()
            return jsonify({'error': 'Employee not found'}), 404

        query = '''
            SELECT 
                dtr.*,
                p.title as project_title,
                t.title as task_title,
                reviewer.username as reviewer_name
            FROM daily_task_reports dtr
            LEFT JOIN projects p ON dtr.project_id = p.id
            LEFT JOIN tasks t ON dtr.task_id = t.id
            LEFT JOIN users reviewer ON dtr.reviewed_by = reviewer.id
            WHERE dtr.user_id = ?
        '''
        params = [employee_id]

        if start_date:
            query += ' AND dtr.report_date >= ?'
            params.append(start_date)
        if end_date:
            query += ' AND dtr.report_date <= ?'
            params.append(end_date)
        if approval_status:
            query += ' AND dtr.approval_status = ?'
            params.append(approval_status)

        query += ' ORDER BY dtr.report_date DESC, dtr.created_at DESC'

        cursor.execute(query, params)
        reports = [dict(row) for row in cursor.fetchall()]

        conn.close()

        return jsonify({
            'employee': {
                'id': employee['id'],
                'username': employee['username']
            },
            'reports': reports,
            'count': len(reports)
        }), 200

    except Exception as e:
        logger.exception("Error getting employee daily reports")
        return jsonify({'error': str(e)}), 500


# Enhanced log_activity function with target_type support
def log_activity(user_id,
                 activity_type,
                 description,
                 project_id=None,
                 task_id=None,
                 milestone_id=None,
                 target_type=None,
                 target_id=None):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO activities (user_id, activity_type, description, project_id, task_id, milestone_id)
            VALUES (?,?,?,?,?,?)
        ''', (user_id, activity_type, description, project_id, task_id,
              milestone_id))
        conn.commit()

        # Also log to audit logs for important actions
        if activity_type in [
                'report_reviewed', 'report_deleted', 'report_edited',
                'batch_report_review', 'daily_report_submitted'
        ]:
            cursor.execute(
                '''
                INSERT INTO audit_logs (actor_id, action, target_type, target_id, details, created_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (user_id, activity_type, target_type, target_id, description))
            conn.commit()

    except Exception as e:
        print(f"[ERROR] Failed to log activity: {str(e)}")
    finally:
        if conn:
            conn.close()


# Replace the previous get_all_users() function with this fixed version

@app.route("/api/admin/users", methods=["GET"])
@admin_required
def get_all_users():
    """
    Admin endpoint: return list of all users in a sqlite-friendly way.
    Returns a JSON array with fields: id, username, email, user_role, user_type_id, created_at
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.id, u.username, u.email, u.user_type_id, ut.user_role, u.created_at
            FROM users u
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            WHERE COALESCE(u.is_system, 0) != 1
            ORDER BY u.created_at DESC
        """)
        rows = cursor.fetchall()
        conn.close()

        users = []
        for r in rows:
            created_at = r['created_at'] if r['created_at'] is not None else None
            # Ensure created_at is serialized as a string (ISO if possible)
            try:
                # If stored as text, leave as-is
                if isinstance(created_at, str):
                    created_at_str = created_at
                else:
                    # sqlite3 can return strings; if it's a datetime-like object, attempt isoformat
                    created_at_str = created_at.isoformat() if hasattr(created_at, 'isoformat') else str(created_at)
            except Exception:
                created_at_str = str(created_at) if created_at is not None else None

            users.append({
                "id": r["id"],
                "username": r["username"],
                "email": r["email"],
                "user_type_id": r["user_type_id"],
                "user_role": r["user_role"],
                "created_at": created_at_str
            })

        return jsonify(users), 200
    except Exception as e:
        logger.exception("Error in /api/admin/users")
        return jsonify({"error": str(e)}), 500

# Get project team members
@app.route("/api/projects/<int:project_id>/team-members", methods=["GET"])
@login_required
def get_project_team_members(project_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get team members for the project
        cursor.execute('''
            SELECT u.id, u.username, u.email, ut.user_role, pa.user_id
            FROM project_assignments pa
            JOIN users u ON pa.user_id = u.id
            LEFT JOIN usertypes ut ON u.user_type_id = ut.id
            WHERE pa.project_id = ?
        ''', (project_id,))
        
        team_members = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        result = []
        for member in team_members:
            result.append({
                'id': member['id'],
                'user_id': member['user_id'],
                'username': member['username'],
                'email': member['email'],
                'user_role': member['user_role']
            })
        
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error getting project team members: {e}")
        return jsonify({"error": str(e)}), 500


# Add team member to project
@app.route("/api/projects/<int:project_id>/add-team-member", methods=["POST"])
@login_required
def add_team_member_to_project(project_id):
    try:
        data = request.get_json()
        user_id = data.get("user_id")
        user_type_id = data.get("user_type_id")
        permissions = data.get("permissions", [])
        
        if not user_id or not user_type_id:
            return jsonify({"error": "user_id and user_type_id are required"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user already assigned to project
        cursor.execute('''
            SELECT id FROM project_assignments 
            WHERE user_id = ? AND project_id = ?
        ''', (user_id, project_id))
        
        if cursor.fetchone():
            conn.close()
            return jsonify({"error": "User is already assigned to this project"}), 400
        
        # Add user to project_assignments
        cursor.execute('''
            INSERT INTO project_assignments (user_id, project_id)
            VALUES (?, ?)
        ''', (user_id, project_id))
        
        # Update user type if needed
        if user_type_id:
            cursor.execute('''
                UPDATE users SET user_type_id = ? WHERE id = ?
            ''', (user_type_id, user_id))
        
        # Store permissions if needed (you may need to create a user_permissions table)
        if permissions:
            for perm in permissions:
                cursor.execute('''
                    INSERT OR IGNORE INTO user_permissions (user_id, module, action, granted)
                    VALUES (?, ?, ?, 1)
                ''', (user_id, 'project', perm))
        
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Team member added successfully"}), 201
    except Exception as e:
        logger.error(f"Error adding team member to project: {e}")
        return jsonify({"error": str(e)}), 500


# Remove team member from project
@app.route("/api/projects/<int:project_id>/remove-team-member", methods=["DELETE"])
@login_required
def remove_team_member_from_project(project_id):
    try:
        data = request.get_json()
        user_id = data.get("user_id")
        
        if not user_id:
            return jsonify({"error": "user_id is required"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Remove user from project_assignments
        cursor.execute('''
            DELETE FROM project_assignments 
            WHERE user_id = ? AND project_id = ?
        ''', (user_id, project_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "User is not assigned to this project"}), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Team member removed successfully"}), 200
    except Exception as e:
        logger.error(f"Error removing team member from project: {e}")
        return jsonify({"error": str(e)}), 500

# -------------------------------------------------------------------------
# USER TYPE MANAGEMENT ENDPOINTS
# -------------------------------------------------------------------------

# Ensure usertype_permissions table exists (Safety check)
def ensure_usertype_permissions_table():
    pass # No longer needed as init_db is now robust and idempotent

@app.route("/api/usertypes", methods=["GET"])
@login_required
def get_usertypes():
    """Get all user types with their permissions"""
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM usertypes ORDER BY id")
        usertypes = [dict(row) for row in cursor.fetchall()]
        
        for ut in usertypes:
            # Safely get permissions
            try:
                # IMPORTANT: Only fetch granted = 1 for "Assigned Permissions"
                cursor.execute("SELECT module, action FROM usertype_permissions WHERE usertype_id = ? AND granted = 1", (ut['id'],))
                perms = cursor.fetchall()
                perm_list = []
                for p in perms:
                    mod = p['module']
                    act = p['action']
                    if mod == 'SYSTEM':
                        perm_list.append(act)
                    else:
                        perm_list.append(f"{mod}_{act}")
                ut['permissions'] = perm_list
            except Exception as e:
                print(f"Error fetching permissions for usertype {ut['id']}: {e}")
                ut['permissions'] = []
            
            # Count users
            try:
                cursor.execute("SELECT COUNT(*) as count FROM users WHERE user_type_id = ?", (ut['id'],))
                ut['user_count'] = cursor.fetchone()['count']
            except:
                ut['user_count'] = 0

        conn.close()
        return jsonify(usertypes), 200
    except Exception as e:
        logger.exception("Error fetching user types")
        return jsonify({"error": str(e)}), 500

@app.route("/api/usertypes", methods=["POST"])
@admin_required
def create_usertype():
    """Create a new user type with permissions"""
    try:
        data = request.get_json()
        user_role = data.get('user_role')
        description = data.get('description', '')
        permissions = data.get('permissions', []) # List of strings "MODULE_ACTION"
        
        logger.info(f"Creating user type: {user_role}, Perms count: {len(permissions)}")

        if not user_role:
            return jsonify({"error": "User role name is required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO usertypes (user_role, description) VALUES (?, ?)", (user_role, description))
            usertype_id = cursor.lastrowid
            
            for perm in permissions:
                parts = perm.split('_', 1)
                if len(parts) == 2:
                     module, action = parts
                else:
                     module = 'SYSTEM'
                     action = perm
                
                cursor.execute("INSERT INTO usertype_permissions (usertype_id, module, action, granted) VALUES (?, ?, ?, 1)",
                               (usertype_id, module, action))
            
            conn.commit()
            return jsonify({"success": True, "message": "User type created", "id": usertype_id}), 201
            
        except sqlite3.IntegrityError:
            return jsonify({"error": "User type already exists"}), 409
        finally:
            conn.close()

    except Exception as e:
        logger.exception("Error creating user type")
        return jsonify({"error": str(e)}), 500

@app.route("/api/usertypes/<int:ut_id>", methods=["PUT"])
@admin_required
def update_usertype(ut_id):
    """Update user type and permissions"""
    try:
        data = request.get_json()
        user_role = data.get('user_role') # Optional update
        description = data.get('description')
        permissions = data.get('permissions') # Optional update list

        conn = get_db_connection()
        cursor = conn.cursor()

        if user_role:
            try:
                cursor.execute("UPDATE usertypes SET user_role = ? WHERE id = ?", (user_role, ut_id))
            except sqlite3.IntegrityError:
                return jsonify({"error": "User role name already taken"}), 409
        
        if description is not None:
             cursor.execute("UPDATE usertypes SET description = ? WHERE id = ?", (description, ut_id))

        if permissions is not None:
            # Replace permissions
            cursor.execute("DELETE FROM usertype_permissions WHERE usertype_id = ?", (ut_id,))
            for perm in permissions:
                parts = perm.split('_', 1)
                if len(parts) == 2:
                     module, action = parts
                else:
                     module = 'SYSTEM'
                     action = perm
                cursor.execute("INSERT INTO usertype_permissions (usertype_id, module, action, granted) VALUES (?, ?, ?, 1)",
                               (ut_id, module, action))
            
            # Optional: Update existing users of this type?
            # For now, let's NOT automatically update existing users' personal permissions to avoid overwriting custom overrides.
            # But in a strict RBAC, we would.
        
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "User type updated"}), 200

    except Exception as e:
        logger.exception("Error updating user type")
        return jsonify({"error": str(e)}), 500

@app.route("/api/usertypes/<int:ut_id>", methods=["DELETE"])
@admin_required
def delete_usertype(ut_id):
    """Delete a user type"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if users exist
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE user_type_id = ?", (ut_id,))
        if cursor.fetchone()['count'] > 0:
            conn.close()
            return jsonify({"error": "Cannot delete user type that has assigned users"}), 400

        cursor.execute("DELETE FROM usertypes WHERE id = ?", (ut_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "User type deleted"}), 200
    except Exception as e:
        logger.exception("Error deleting user type")
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/dashboard/stats", methods=["GET"])
@admin_required
def get_admin_dashboard_stats():
    """Get general admin dashboard statistics"""
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Active Projects (status != Completed)
        cursor.execute("SELECT COUNT(*) as count FROM projects WHERE status != 'Completed'")
        active_projects = cursor.fetchone()['count']

        # Active Tasks (status != Completed)
        cursor.execute("SELECT COUNT(*) as count FROM tasks WHERE status != 'Completed' AND status != 'Pending'")
        active_tasks = cursor.fetchone()['count']

        # Pending Tasks (status = Pending)
        cursor.execute("SELECT COUNT(*) as count FROM tasks WHERE status = 'Pending'")
        pending_tasks = cursor.fetchone()['count']

        # Overdue Tasks
        cursor.execute("SELECT COUNT(*) as count FROM tasks WHERE status != 'Completed' AND deadline < date('now')")
        overdue_tasks = cursor.fetchone()['count']

        # Completed Tasks
        cursor.execute("SELECT COUNT(*) as count FROM tasks WHERE status = 'Completed'")
        completed_tasks = cursor.fetchone()['count']

        # Total Users
        cursor.execute("SELECT COUNT(*) as count FROM users")
        total_users = cursor.fetchone()['count']
        
        # Total User Types
        cursor.execute("SELECT COUNT(*) as count FROM usertypes")
        total_usertypes = cursor.fetchone()['count']

        conn.close()

        return jsonify({
            "active_projects": active_projects,
            "active_tasks": active_tasks,
            "pending_approvals": pending_tasks, 
            "overdue_tasks": overdue_tasks,
            "completed_tasks": completed_tasks,
            "total_users": total_users,
            "total_usertypes": total_usertypes
        }), 200

    except Exception as e:
        logger.exception("Error getting admin dashboard stats")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
