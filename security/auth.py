#!/usr/bin/env python3
"""
Authentication Module for Picoclaw Security Hardening
Token validation decorator for Flask routes with SQLite storage
"""

import os
import sqlite3
import secrets
import logging
import functools
from typing import Optional, Callable
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g

logger = logging.getLogger(__name__)

# Database path
DEFAULT_DB_PATH = '/home/cogniwatch/data/picoclaw.db'
TOKENS_TABLE = 'auth_tokens'

# Token configuration
TOKEN_PREFIX = 'pcw_'
TOKEN_LENGTH = 32
DEFAULT_TOKEN_EXPIRY_HOURS = 24 * 7  # 7 days


class AuthError(Exception):
    """Custom exception for authentication errors"""
    pass


class TokenManager:
    """
    Manages authentication tokens with SQLite storage.
    
    Token format: pcw_<random_32_chars>
    Total length: 36 characters (pcw_ prefix + 32 random chars)
    """
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.environ.get('PICOCLAW_DB', DEFAULT_DB_PATH)
        self._init_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_db(self):
        """Initialize the tokens table"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {TOKENS_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                last_used TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                metadata JSON
            )
        ''')
        
        # Create index for faster lookups
        cursor.execute(f'''
            CREATE INDEX IF NOT EXISTS idx_tokens_token 
            ON {TOKENS_TABLE} (token)
        ''')
        cursor.execute(f'''
            CREATE INDEX IF NOT EXISTS idx_tokens_active 
            ON {TOKENS_TABLE} (is_active, expires_at)
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Initialized tokens table in {self.db_path}")
    
    def _generate_token(self) -> str:
        """Generate a secure random token"""
        random_part = secrets.token_urlsafe(TOKEN_LENGTH)
        # Ensure we have exactly 32 characters (base64url encoded, might be longer)
        random_part = secrets.token_hex(TOKEN_LENGTH // 2 + 1)[:TOKEN_LENGTH]
        return f"{TOKEN_PREFIX}{random_part}"
    
    def create_token(
        self,
        name: Optional[str] = None,
        expiry_hours: int = DEFAULT_TOKEN_EXPIRY_HOURS,
        metadata: Optional[dict] = None
    ) -> str:
        """
        Create a new authentication token.
        
        Args:
            name: Optional name/label for the token
            expiry_hours: Token expiration time in hours (default: 7 days)
            metadata: Optional metadata dictionary
        
        Returns:
            The generated token string
        """
        token = self._generate_token()
        expires_at = datetime.now() + timedelta(hours=expiry_hours)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(f'''
            INSERT INTO {TOKENS_TABLE} (token, name, expires_at, metadata)
            VALUES (?, ?, ?, ?)
        ''', (token, name, expires_at.isoformat(), 
              str(metadata) if metadata else None))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Created token: {token[:8]}... for '{name or 'unnamed'}'")
        return token
    
    def validate_token(self, token: str) -> bool:
        """
        Validate a token.
        
        Args:
            token: The token to validate
        
        Returns:
            True if valid, False otherwise
        """
        if not token or not token.startswith(TOKEN_PREFIX):
            return False
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(f'''
            SELECT id, expires_at, is_active FROM {TOKENS_TABLE}
            WHERE token = ?
        ''', (token,))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return False
        
        # Check if active
        if not row['is_active']:
            conn.close()
            return False
        
        # Check expiration
        expires_at = datetime.fromisoformat(row['expires_at'])
        if datetime.now() > expires_at:
            conn.close()
            return False
        
        # Update last_used timestamp
        cursor.execute(f'''
            UPDATE {TOKENS_TABLE} SET last_used = ? WHERE id = ?
        ''', (datetime.now().isoformat(), row['id']))
        
        conn.commit()
        conn.close()
        
        return True
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke (deactivate) a token.
        
        Args:
            token: The token to revoke
        
        Returns:
            True if revoked, False if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(f'''
            UPDATE {TOKENS_TABLE} SET is_active = 0 WHERE token = ?
        ''', (token,))
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        return affected > 0
    
    def delete_token(self, token: str) -> bool:
        """
        Delete a token from storage.
        
        Args:
            token: The token to delete
        
        Returns:
            True if deleted, False if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(f'''
            DELETE FROM {TOKENS_TABLE} WHERE token = ?
        ''', (token,))
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        return affected > 0
    
    def list_tokens(self, include_inactive: bool = False) -> list:
        """
        List all tokens (without revealing full token values).
        
        Args:
            include_inactive: Whether to include revoked/expired tokens
        
        Returns:
            List of token metadata dictionaries
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        if include_inactive:
            cursor.execute(f'''
                SELECT id, token, name, created_at, expires_at, last_used, is_active
                FROM {TOKENS_TABLE}
                ORDER BY created_at DESC
            ''')
        else:
            cursor.execute(f'''
                SELECT id, token, name, created_at, expires_at, last_used, is_active
                FROM {TOKENS_TABLE}
                WHERE is_active = 1 AND expires_at > ?
                ORDER BY created_at DESC
            ''', (datetime.now().isoformat(),))
        
        tokens = []
        for row in cursor.fetchall():
            tokens.append({
                'id': row['id'],
                'token_preview': row['token'][:8] + '...',
                'name': row['name'],
                'created_at': row['created_at'],
                'expires_at': row['expires_at'],
                'last_used': row['last_used'],
                'is_active': bool(row['is_active'])
            })
        
        conn.close()
        return tokens
    
    def cleanup_expired(self) -> int:
        """
        Remove expired tokens from storage.
        
        Returns:
            Number of tokens removed
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute(f'''
            DELETE FROM {TOKENS_TABLE}
            WHERE expires_at < ? OR is_active = 0
        ''', (datetime.now().isoformat(),))
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        logger.info(f"Cleaned up {affected} expired/revoked tokens")
        return affected


def extract_bearer_token() -> Optional[str]:
    """
    Extract Bearer token from Authorization header.
    
    Returns:
        Token string if found and valid format, None otherwise
    """
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        return None
    
    # Check for Bearer prefix
    parts = auth_header.split()
    if len(parts) != 2:
        return None
    
    if parts[0].lower() != 'bearer':
        return None
    
    token = parts[1]
    
    # Validate token format
    if not token.startswith(TOKEN_PREFIX):
        return None
    
    return token


def require_auth(f: Callable) -> Callable:
    """
    Decorator to require authentication for Flask routes.
    
    Validates Bearer token from Authorization header.
    Token format must be: pcw_<random_32_chars>
    
    Usage:
        @app.route('/api/protected')
        @require_auth
        def protected_endpoint():
            return jsonify({"status": "authenticated"})
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Extract token from Authorization header
        token = extract_bearer_token()
        
        if not token:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Missing or invalid Authorization header. Use: Bearer pcw_<token>'
            }), 401
        
        # Get token manager
        token_manager = get_token_manager()
        
        # Validate token
        if not token_manager.validate_token(token):
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Invalid or expired token'
            }), 401
        
        # Store validated token in flask.g for potential use
        g.auth_token = token
        
        return f(*args, **kwargs)
    
    return decorated_function


def optional_auth(f: Callable) -> Callable:
    """
    Decorator for optional authentication.
    If token is present and valid, sets g.auth_token.
    Does not reject requests without valid token.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = extract_bearer_token()
        
        if token:
            token_manager = get_token_manager()
            if token_manager.validate_token(token):
                g.auth_token = token
        
        return f(*args, **kwargs)
    
    return decorated_function


# Singleton instance
_token_manager = None

def get_token_manager() -> TokenManager:
    """Get or create singleton TokenManager instance"""
    global _token_manager
    if _token_manager is None:
        _token_manager = TokenManager()
    return _token_manager
