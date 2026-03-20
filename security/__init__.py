#!/usr/bin/env python3
"""
Picoclaw Security Module

This module provides security hardening components for Picoclaw:

- Container Isolation: Docker-based sandboxing for tool execution
- Secrets Management: Secure credential storage with keyring/encrypted fallback
- Authentication: Token-based API authentication

Usage:
    from security import (
        ContainerIsolation,
        get_container_isolation,
        get_secret, set_secret, delete_secret,
        require_auth, get_token_manager
    )
    
    # Container isolation
    container = get_container_isolation()
    result = container.execute('ls -la')
    
    # Secrets
    set_secret('api_key', 'secret_value')
    api_key = get_secret('api_key')
    
    # Authentication
    @app.route('/api/protected')
    @require_auth
    def protected_route():
        return {'status': 'authenticated'}
"""

from .container_isolation import (
    ContainerIsolation,
    ContainerIsolationError,
    ExecutionResult,
    get_container_isolation
)

from .secrets import (
    SecretsManager,
    SecretsError,
    SecretNotFoundError,
    get_secrets_manager,
    get_secret,
    set_secret,
    delete_secret
)

from .auth import (
    TokenManager,
    AuthError,
    get_token_manager,
    require_auth,
    optional_auth,
    extract_bearer_token
)

__all__ = [
    # Container isolation
    'ContainerIsolation',
    'ContainerIsolationError',
    'ExecutionResult',
    'get_container_isolation',
    
    # Secrets management
    'SecretsManager',
    'SecretsError',
    'SecretNotFoundError',
    'get_secrets_manager',
    'get_secret',
    'set_secret',
    'delete_secret',
    
    # Authentication
    'TokenManager',
    'AuthError',
    'get_token_manager',
    'require_auth',
    'optional_auth',
    'extract_bearer_token'
]

__version__ = '1.1.0'
