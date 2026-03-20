#!/usr/bin/env python3
"""
Secret Management Module for Picoclaw Security Hardening
Integrates with system keychain with encrypted file fallback
"""

import os
import json
import logging
import hashlib
import base64
from typing import Optional
from pathlib import Path
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

# Default paths
DEFAULT_SECRETS_DIR = Path('/home/cogniwatch/.picoclaw/secrets')
DEFAULT_MASTER_KEY_PATH = Path('/home/cogniwatch/.picoclaw/master.key')

# Secret storage modes
STORAGE_KEYRING = 'keyring'
STORAGE_ENCRYPTED_FILE = 'encrypted_file'


class SecretsError(Exception):
    """Custom exception for secrets management errors"""
    pass


class SecretNotFoundError(SecretsError):
    """Raised when a secret is not found"""
    pass


class SecretStorage:
    """
    Abstract base class for secret storage backends
    """
    
    def get(self, name: str) -> Optional[str]:
        raise NotImplementedError
    
    def set(self, name: str, value: str) -> bool:
        raise NotImplementedError
    
    def delete(self, name: str) -> bool:
        raise NotImplementedError
    
    def list_secrets(self) -> list:
        raise NotImplementedError


class KeyringStorage(SecretStorage):
    """
    System keychain-based secret storage using the keyring library.
    This is the preferred storage method when available.
    """
    
    SERVICE_NAME = 'picoclaw'
    
    def __init__(self):
        self._keyring = None
        self._available = False
        
        try:
            import keyring
            self._keyring = keyring
            # Test if keyring is working
            self._keyring.get_password(self.SERVICE_NAME, '__test__')
            self._available = True
            logger.info("System keyring initialized successfully")
        except ImportError:
            logger.warning("keyring library not installed, falling back to encrypted file storage")
        except Exception as e:
            logger.warning(f"System keyring not available: {e}")
    
    @property
    def available(self) -> bool:
        return self._available
    
    def get(self, name: str) -> Optional[str]:
        if not self._available:
            return None
        try:
            return self._keyring.get_password(self.SERVICE_NAME, name)
        except Exception as e:
            logger.error(f"Failed to get secret '{name}' from keyring: {e}")
            return None
    
    def set(self, name: str, value: str) -> bool:
        if not self._available:
            return False
        try:
            self._keyring.set_password(self.SERVICE_NAME, name, value)
            return True
        except Exception as e:
            logger.error(f"Failed to set secret '{name}' in keyring: {e}")
            return False
    
    def delete(self, name: str) -> bool:
        if not self._available:
            return False
        try:
            self._keyring.delete_password(self.SERVICE_NAME, name)
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret '{name}' from keyring: {e}")
            return False
    
    def list_secrets(self) -> list:
        # keyring doesn't support listing, return empty list
        return []


class EncryptedFileStorage(SecretStorage):
    """
    Encrypted file-based secret storage.
    Used as fallback when system keychain is not available.
    Secrets are stored in encrypted JSON files.
    """
    
    def __init__(
        self,
        secrets_dir: Path = DEFAULT_SECRETS_DIR,
        master_key_path: Path = DEFAULT_MASTER_KEY_PATH
    ):
        self.secrets_dir = Path(secrets_dir)
        self.master_key_path = Path(master_key_path)
        self._fernet = None
        
        # Ensure secrets directory exists with secure permissions
        self.secrets_dir.mkdir(parents=True, exist_ok=True)
        self.secrets_dir.chmod(0o700)
        
        # Initialize encryption
        self._init_encryption()
    
    def _init_encryption(self):
        """Initialize Fernet encryption key"""
        try:
            # Try to load existing master key
            if self.master_key_path.exists():
                with open(self.master_key_path, 'rb') as f:
                    key = f.read()
                self._fernet = Fernet(key)
                logger.info("Loaded existing encryption key")
            else:
                # Generate new master key
                key = Fernet.generate_key()
                self.master_key_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.master_key_path, 'wb') as f:
                    f.write(key)
                self.master_key_path.chmod(0o600)
                self._fernet = Fernet(key)
                logger.info("Generated new encryption key")
        except Exception as e:
            logger.error(f"Failed to initialize encryption: {e}")
            raise SecretsError(f"Encryption initialization failed: {e}")
    
    def _get_secret_path(self, name: str) -> Path:
        """Get path to encrypted secret file"""
        # Hash the name to create safe filename
        name_hash = hashlib.sha256(name.encode()).hexdigest()[:16]
        return self.secrets_dir / f"{name_hash}.enc"
    
    def get(self, name: str) -> Optional[str]:
        secret_path = self._get_secret_path(name)
        
        if not secret_path.exists():
            return None
        
        try:
            with open(secret_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self._fernet.decrypt(encrypted_data)
            secret_obj = json.loads(decrypted_data.decode())
            
            return secret_obj.get('value')
        except Exception as e:
            logger.error(f"Failed to decrypt secret '{name}': {e}")
            return None
    
    def set(self, name: str, value: str) -> bool:
        secret_path = self._get_secret_path(name)
        
        try:
            secret_obj = {
                'name': name,
                'value': value,
                'created': datetime.now().isoformat(),
                'updated': datetime.now().isoformat()
            }
            
            encrypted_data = self._fernet.encrypt(json.dumps(secret_obj).encode())
            
            with open(secret_path, 'wb') as f:
                f.write(encrypted_data)
            
            secret_path.chmod(0o600)
            return True
        except Exception as e:
            logger.error(f"Failed to encrypt and save secret '{name}': {e}")
            return False
    
    def delete(self, name: str) -> bool:
        secret_path = self._get_secret_path(name)
        
        if not secret_path.exists():
            return False
        
        try:
            secret_path.unlink()
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret '{name}': {e}")
            return False
    
    def list_secrets(self) -> list:
        secrets = []
        for path in self.secrets_dir.glob('*.enc'):
            try:
                with open(path, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self._fernet.decrypt(encrypted_data)
                secret_obj = json.loads(decrypted_data.decode())
                secrets.append({
                    'name': secret_obj.get('name'),
                    'created': secret_obj.get('created')
                })
            except Exception as e:
                logger.warning(f"Failed to read secret file {path}: {e}")
        return secrets


class SecretsManager:
    """
    Main secrets manager that handles storage backend selection.
    Uses system keyring when available, falls back to encrypted file storage.
    """
    
    def __init__(self):
        self._keyring_storage = KeyringStorage()
        self._file_storage = None
        self._active_storage = None
        
        if self._keyring_storage.available:
            self._active_storage = self._keyring_storage
            self._storage_mode = STORAGE_KEYRING
        else:
            self._file_storage = EncryptedFileStorage()
            self._active_storage = self._file_storage
            self._storage_mode = STORAGE_ENCRYPTED_FILE
    
    @property
    def storage_mode(self) -> str:
        return self._storage_mode
    
    def get_secret(self, name: str) -> str:
        """
        Retrieve a secret by name.
        
        Args:
            name: Secret identifier
        
        Returns:
            The secret value
        
        Raises:
            SecretNotFoundError: If secret doesn't exist
            SecretsError: For other storage errors
        """
        value = self._active_storage.get(name)
        
        if value is None:
            raise SecretNotFoundError(f"Secret '{name}' not found")
        
        return value
    
    def set_secret(self, name: str, value: str) -> bool:
        """
        Store a secret.
        
        Args:
            name: Secret identifier
            value: Secret value to store
        
        Returns:
            True if successful, False otherwise
        """
        return self._active_storage.set(name, value)
    
    def delete_secret(self, name: str) -> bool:
        """
        Delete a secret.
        
        Args:
            name: Secret identifier
        
        Returns:
            True if successful, False otherwise
        """
        return self._active_storage.delete(name)
    
    def list_secrets(self) -> list:
        """
        List all stored secrets (names only, not values).
        
        Returns:
            List of secret metadata
        """
        return self._active_storage.list_secrets()
    
    def get_secret_metadata(self, name: str) -> dict:
        """
        Get metadata about a secret (without the actual value).
        Only available for encrypted file storage.
        
        Args:
            name: Secret identifier
        
        Returns:
            Dictionary with metadata
        """
        if self._storage_mode == STORAGE_ENCRYPTED_FILE and self._file_storage:
            # For file storage, we can get more metadata
            secret_path = self._file_storage._get_secret_path(name)
            if secret_path.exists():
                stat = secret_path.stat()
                return {
                    'name': name,
                    'exists': True,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                }
        
        return {
            'name': name,
            'exists': self._active_storage.get(name) is not None
        }


# Singleton instance
_secrets_manager = None

def get_secrets_manager() -> SecretsManager:
    """Get or create singleton SecretsManager instance"""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager


# Convenience functions
def get_secret(name: str) -> str:
    """Get a secret value by name"""
    return get_secrets_manager().get_secret(name)


def set_secret(name: str, value: str) -> bool:
    """Set a secret value"""
    return get_secrets_manager().set_secret(name, value)


def delete_secret(name: str) -> bool:
    """Delete a secret by name"""
    return get_secrets_manager().delete_secret(name)
