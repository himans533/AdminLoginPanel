#!/usr/bin/env python3
"""
PostgreSQL Database Initialization Script for Railway Deployment
This script initializes the PostgreSQL database with all required tables and seed data.
Run this script before starting the Flask application.
"""

import os
import sys
import psycopg2
import psycopg2.extras
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash
import secrets

def get_postgres_connection():
    """Establish PostgreSQL connection from DATABASE_URL"""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise Exception("DATABASE_URL environment variable not set!")
    
    if not database_url.startswith("postgres"):
        raise Exception(f"Expected PostgreSQL URL, got: {database_url[:20]}...")
    
    url = urlparse(database_url)
    conn = psycopg2.connect(
        host=url.hostname,
        port=url.port,
        user=url.username,
        password=url.password,
        dbname=url.path[1:]
    )
    return conn

def init_database():
    """Initialize all tables in PostgreSQL database"""
    conn = None
    try:
        conn = get_postgres_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        print("✅ Connected to PostgreSQL database")
        
        # 1. Create usertypes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usertypes (
                id SERIAL PRIMARY KEY,
                user_role VARCHAR(100) UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        print("✅ Created usertypes table")
        
        # 2. Create usertype_permissions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS usertype_permissions (
                id SERIAL PRIMARY KEY,
                usertype_id INTEGER NOT NULL,
                module VARCHAR NOT NULL,
                action VARCHAR NOT NULL,
                granted BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (usertype_id) REFERENCES usertypes(id) ON DELETE CASCADE,
                UNIQUE(usertype_id, module, action)
            );
        """)
        print("✅ Created usertype_permissions table")
        
        # 3. Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR NOT NULL UNIQUE,
                email VARCHAR NOT NULL UNIQUE,
                password VARCHAR NOT NULL,
                user_type_id INTEGER NOT NULL,
                granted BOOLEAN DEFAULT FALSE,
                status VARCHAR DEFAULT 'Active',
                phone VARCHAR,
                department VARCHAR,
                bio VARCHAR,
                avatar_url VARCHAR,
                is_system INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_type_id) REFERENCES usertypes(id)
            );
        """)
        print("✅ Created users table")
        
        # 4. Create user_permissions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_permissions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                module VARCHAR NOT NULL,
                action VARCHAR NOT NULL,
                granted BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(user_id, module, action)
            );
        """)
        print("✅ Created user_permissions table")
        
        # 5. Create projects table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id SERIAL PRIMARY KEY,
                title VARCHAR NOT NULL,
                description VARCHAR,
                status VARCHAR DEFAULT 'In Progress',
                progress INTEGER DEFAULT 0,
                deadline DATE,
                reporting_time TIME DEFAULT '09:00',
                created_by_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (created_by_id) REFERENCES users(id)
            );
        """)
        print("✅ Created projects table")
        
        # 6. Create tasks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id SERIAL PRIMARY KEY,
                title VARCHAR NOT NULL,
                description VARCHAR,
                status VARCHAR DEFAULT 'Pending',
                priority VARCHAR DEFAULT 'Medium',
                deadline DATE,
                project_id INTEGER NOT NULL,
                created_by_id INTEGER NOT NULL,
                assigned_to_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                approval_status VARCHAR DEFAULT 'pending',
                weightage INTEGER DEFAULT 1,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (created_by_id) REFERENCES users(id),
                FOREIGN KEY (assigned_to_id) REFERENCES users(id)
            );
        """)
        print("✅ Created tasks table")
        
        # 7. Create comments table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS comments (
                id SERIAL PRIMARY KEY,
                content VARCHAR NOT NULL,
                author_id INTEGER NOT NULL,
                project_id INTEGER,
                task_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (author_id) REFERENCES users(id),
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (task_id) REFERENCES tasks(id)
            );
        """)
        print("✅ Created comments table")
        
        # 8. Create documents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                filename VARCHAR NOT NULL,
                original_filename TEXT NOT NULL,
                file_size INTEGER,
                uploaded_by_id INTEGER NOT NULL,
                project_id INTEGER,
                task_id INTEGER,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploaded_by_id) REFERENCES users(id),
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (task_id) REFERENCES tasks(id)
            );
        """)
        print("✅ Created documents table")
        
        # 9. Create milestones table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS milestones (
                id SERIAL PRIMARY KEY,
                title VARCHAR NOT NULL,
                description VARCHAR,
                due_date DATE,
                status VARCHAR DEFAULT 'Pending',
                project_id INTEGER NOT NULL,
                weightage INTEGER DEFAULT 1,
                created_by_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (created_by_id) REFERENCES users(id)
            );
        """)
        print("✅ Created milestones table")
        
        # 10. Create project_assignments table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS project_assignments (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                project_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (project_id) REFERENCES projects(id),
                UNIQUE(user_id, project_id)
            );
        """)
        print("✅ Created project_assignments table")
        
        # 11. Create progress_history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS progress_history (
                id SERIAL PRIMARY KEY,
                project_id INTEGER NOT NULL,
                progress_percentage INTEGER,
                tasks_completed INTEGER,
                total_tasks INTEGER,
                milestones_completed INTEGER,
                total_milestones INTEGER,
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            );
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_progress_project_date 
            ON progress_history(project_id, recorded_at);
        """)
        print("✅ Created progress_history table and index")
        
        # 12. Create activities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activities (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                activity_type VARCHAR NOT NULL,
                description VARCHAR NOT NULL,
                project_id INTEGER,
                task_id INTEGER,
                milestone_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (task_id) REFERENCES tasks(id),
                FOREIGN KEY (milestone_id) REFERENCES milestones(id)
            );
        """)
        print("✅ Created activities table")
        
        # 13. Create user_skills table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_skills (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                skill_name VARCHAR NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(user_id, skill_name)
            );
        """)
        print("✅ Created user_skills table")
        
        # 14. Create daily_task_reports table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS daily_task_reports (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                task_id INTEGER NOT NULL,
                project_id INTEGER NOT NULL,
                report_date DATE NOT NULL,
                work_description VARCHAR,
                result_of_effort VARCHAR,
                remarks VARCHAR,
                communication_email VARCHAR,
                communication_phone VARCHAR,
                task_assigned_by_id INTEGER,
                time_spent REAL DEFAULT 0,
                status VARCHAR DEFAULT 'In Progress',
                blocker VARCHAR,
                approval_status VARCHAR DEFAULT 'pending',
                reviewed_by INTEGER,
                review_comment VARCHAR,
                is_locked INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (task_id) REFERENCES tasks(id),
                FOREIGN KEY (project_id) REFERENCES projects(id),
                FOREIGN KEY (reviewed_by) REFERENCES users(id),
                UNIQUE(user_id, task_id, report_date)
            );
        """)
        print("✅ Created daily_task_reports table")
        
        # 15. Create report_comments table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report_comments (
                id SERIAL PRIMARY KEY,
                report_id INTEGER NOT NULL,
                commenter_id INTEGER NOT NULL,
                comment VARCHAR NOT NULL,
                internal BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (report_id) REFERENCES daily_task_reports(id) ON DELETE CASCADE,
                FOREIGN KEY (commenter_id) REFERENCES users(id)
            );
        """)
        print("✅ Created report_comments table")
        
        # 16. Create audit_logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                actor_id INTEGER,
                action VARCHAR NOT NULL,
                target_type VARCHAR,
                target_id INTEGER,
                details VARCHAR,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        print("✅ Created audit_logs table")
        
        # Seed initial user types
        user_types_data = [
            ('Administrator', 'Full system access and management'),
            ('Employee', 'Standard employee access for reporting'),
            ('Project-Cordinator', 'Project management and team coordination')
        ]
        
        cursor.execute("SELECT COUNT(*) as count FROM usertypes")
        count = cursor.fetchone()['count']
        
        if count == 0:
            for role, desc in user_types_data:
                cursor.execute(
                    "INSERT INTO usertypes (user_role, description) VALUES (%s, %s)",
                    (role, desc)
                )
            print("✅ Seeded user types")
        
        conn.commit()
        print("\n✅ Database initialization completed successfully!")
        
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        if conn:
            conn.rollback()
        sys.exit(1)
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    init_database()
