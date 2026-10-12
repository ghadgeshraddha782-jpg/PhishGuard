
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "data"
DATABASE_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH = DATABASE_DIR / "phishing_dashboard.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def create_tables():
    connection = get_connection()

    try:
        cursor = connection.cursor()

        # USERS: passwords will be stored as salted hashes.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'USER'
                    CHECK (role IN ('USER', 'ADMIN')),
                created_at TEXT NOT NULL
            )
        """)

        # ANALYSES: preserve existing records and add ownership.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_domain TEXT,
                subject TEXT,
                risk_score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                created_at TEXT NOT NULL,
                user_id INTEGER,
                FOREIGN KEY (user_id)
                    REFERENCES users (user_id)
                    ON DELETE SET NULL
            )
        """)

        # Safe migration for an existing analyses table.
        columns = {
            row["name"]
            for row in cursor.execute(
                "PRAGMA table_info(analyses)"
            ).fetchall()
        }

        if "user_id" not in columns:
            cursor.execute("""
                ALTER TABLE analyses
                ADD COLUMN user_id INTEGER
                REFERENCES users(user_id)
                ON DELETE SET NULL
            """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS review_cases (
                review_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                reported_by TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                admin_notes TEXT DEFAULT '',
                reviewed_by TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                reviewed_at TEXT DEFAULT NULL,
                FOREIGN KEY (analysis_id)
                    REFERENCES analyses (analysis_id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                indicator_type TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                FOREIGN KEY (analysis_id)
                    REFERENCES analyses (analysis_id)
                    ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS url_analyses (
                url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                url_safe_representation TEXT,
                risk_score INTEGER,
                findings TEXT,
                FOREIGN KEY (analysis_id)
                    REFERENCES analyses (analysis_id)
                    ON DELETE CASCADE
            )
        """)

        # Server-side login sessions; only token hashes are stored.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id)
                    REFERENCES users (user_id)
                    ON DELETE CASCADE
            )
        """)

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    create_tables()
    print("Database tables created successfully.")
    print(f"Database location: {DATABASE_PATH}")
