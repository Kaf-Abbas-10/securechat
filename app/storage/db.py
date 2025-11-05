#!/usr/bin/env python3
"""
MySQL users table + salted hashing (no chat storage).

Handles:
    - Connection setup
    - Table creation (users)
    - Registration with random salt
    - Login verification
"""

import os
import mysql.connector
import hashlib
import secrets
from mysql.connector import Error


class UserDatabase:
    """
    MySQL user storage helper.
    Table schema:
        users(
            email VARCHAR(255),
            username VARCHAR(64) UNIQUE,
            salt VARBINARY(16),
            pwd_hash CHAR(64)
        )
    """

    def __init__(self, host="localhost", user="root", password="", database="securechat"):
        """Initialize DB connection."""
        try:
            self.conn = mysql.connector.connect(
                host=host, user=user, password=password
            )
            self.cursor = self.conn.cursor()
            self._ensure_database(database)
            self.conn.database = database
            self._ensure_table()
        except Error as e:
            raise RuntimeError(f"MySQL connection failed: {e}")

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------
    def _ensure_database(self, database: str):
        """Create database if missing."""
        self.cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database}")
        self.conn.commit()

    def _ensure_table(self):
        """Create users table if missing."""
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                email VARCHAR(255),
                username VARCHAR(64) UNIQUE,
                salt VARBINARY(16),
                pwd_hash CHAR(64)
            )
            """
        )
        self.conn.commit()

    # -------------------------------------------------------------------------
    # Registration and login
    # -------------------------------------------------------------------------
    def register_user(self, email: str, username: str, password: str) -> bool:
        """
        Register new user with salted SHA-256 password hash.
        Returns True if success, False if username/email already exists.
        """
        # Check duplicates
        self.cursor.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, email))
        if self.cursor.fetchone():
            return False  # user already exists

        salt = secrets.token_bytes(16)
        pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()

        self.cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
            (email, username, salt, pwd_hash),
        )
        self.conn.commit()
        return True

    def verify_login(self, email: str, password: str) -> bool:
        """
        Verify user credentials.
        Returns True if credentials are valid, False otherwise.
        """
        self.cursor.execute("SELECT salt, pwd_hash FROM users WHERE email=%s", (email,))
        row = self.cursor.fetchone()
        if not row:
            return False

        salt, stored_hash = row
        computed = hashlib.sha256(salt + password.encode()).hexdigest()
        return computed == stored_hash

    # -------------------------------------------------------------------------
    # Cleanup
    # -------------------------------------------------------------------------
    def close(self):
        """Close database connection."""
        try:
            self.cursor.close()
            self.conn.close()
        except Exception:
            pass


# --- CLI Testing Helper ---
if __name__ == "__main__":
    print("[+] Testing MySQL user database")

    # You can configure credentials through environment variables
    host = os.getenv("DB_HOST", "localhost")
    user = os.getenv("DB_USER", "secureuser")
    password = os.getenv("DB_PASS", "securepass")
    database = os.getenv("DB_NAME", "securechat")

    db = UserDatabase(host, user, password, database)

    print("[*] Registering test user...")
    ok = db.register_user("alice@example.com", "alice", "mypassword123")
    print("Register result:", ok)

    print("[*] Verifying login...")
    login_ok = db.verify_login("alice@example.com", "mypassword123")
    print("Login OK:", login_ok)

    db.close()
