"""
Consent Management for Picoclaw Governance Module.

This module provides user consent management for agent operations,
allowing users to grant, revoke, and manage permissions.
"""

from __future__ import annotations

import json
import secrets
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional
import asyncio
from threading import RLock


class ConsentScope(str, Enum):
    """Permission scopes for consent."""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"
    
    # Compound scopes
    READ_WRITE = "read:write"
    FULL = "full"
    
    # Specific resource scopes
    FILE_READ = "file:read"
    FILE_WRITE = "file:write"
    NETWORK_HTTP = "network:http"
    NETWORK_ALL = "network:all"
    PROCESS_SPAWN = "process:spawn"
    BROWSER_CONTROL = "browser:control"
    SHELL_EXECUTE = "shell:execute"
    DATA_PROCESSING = "data:processing"
    
    @classmethod
    def includes(cls, scope: "ConsentScope", other: "ConsentScope") -> bool:
        """Check if one scope includes another."""
        # Admin includes everything
        if scope == cls.ADMIN:
            return True
        
        # Full includes everything except admin
        if scope == cls.FULL:
            return other != cls.ADMIN
        
        # Read-write includes read and write
        if scope == cls.READ_WRITE and other in (cls.READ, cls.WRITE):
            return True
        
        # Network all includes network http
        if scope == cls.NETWORK_ALL and other == cls.NETWORK_HTTP:
            return True
        
        return scope == other
    
    @classmethod
    def expand(cls, scope: "ConsentScope") -> list["ConsentScope"]:
        """Expand a scope into its component scopes."""
        if scope == cls.ADMIN:
            return [cls.ADMIN, cls.FULL, cls.READ, cls.WRITE, cls.EXECUTE]
        if scope == cls.FULL:
            return [cls.READ, cls.WRITE, cls.EXECUTE]
        if scope == cls.READ_WRITE:
            return [cls.READ, cls.WRITE]
        return [scope]


class ConsentStatus(str, Enum):
    """Status of a consent grant."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"


@dataclass
class ConsentGrant:
    """
    Represents a consent grant from a user to an agent.
    
    Consent grants define what operations an agent can perform
    on behalf of a user.
    """
    grant_id: str
    user_id: str
    agent_id: str
    scope: ConsentScope
    resource_pattern: str = "*"  # Resource pattern (glob)
    granted_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    status: ConsentStatus = ConsentStatus.ACTIVE
    conditions: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    granted_by: Optional[str] = None  # For delegated grants
    revocation_reason: Optional[str] = None
    revoked_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Generate grant ID if not provided."""
        if not self.grant_id:
            self.grant_id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique grant ID."""
        data = f"{self.user_id}:{self.agent_id}:{self.scope.value}:{self.granted_at.isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    @property
    def is_expired(self) -> bool:
        """Check if grant has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    @property
    def is_active(self) -> bool:
        """Check if grant is active and valid."""
        return self.status == ConsentStatus.ACTIVE and not self.is_expired
    
    def matches_resource(self, resource: str) -> bool:
        """Check if resource matches the grant pattern."""
        import fnmatch
        return fnmatch.fnmatch(resource, self.resource_pattern)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize grant to dictionary."""
        return {
            "grant_id": self.grant_id,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "scope": self.scope.value,
            "resource_pattern": self.resource_pattern,
            "granted_at": self.granted_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status.value,
            "conditions": self.conditions,
            "metadata": self.metadata,
            "granted_by": self.granted_by,
            "revocation_reason": self.revocation_reason,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConsentGrant":
        """Deserialize grant from dictionary."""
        return cls(
            grant_id=data["grant_id"],
            user_id=data["user_id"],
            agent_id=data["agent_id"],
            scope=ConsentScope(data["scope"]),
            resource_pattern=data.get("resource_pattern", "*"),
            granted_at=datetime.fromisoformat(data["granted_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            status=ConsentStatus(data.get("status", "active")),
            conditions=data.get("conditions", {}),
            metadata=data.get("metadata", {}),
            granted_by=data.get("granted_by"),
            revocation_reason=data.get("revocation_reason"),
            revoked_at=datetime.fromisoformat(data["revoked_at"]) if data.get("revoked_at") else None,
        )


@dataclass
class ConsentRequest:
    """
    A request for consent from a user.
    
    Used when an agent needs to request permission for an operation.
    """
    request_id: str
    agent_id: str
    user_id: str
    scope: ConsentScope
    resource: str
    reason: str
    requested_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    status: str = "pending"  # pending, approved, denied, expired
    approved_grant_id: Optional[str] = None
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize request to dictionary."""
        return {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "scope": self.scope.value,
            "resource": self.resource,
            "reason": self.reason,
            "requested_at": self.requested_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status,
            "approved_grant_id": self.approved_grant_id,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConsentRequest":
        """Deserialize request from dictionary."""
        return cls(
            request_id=data["request_id"],
            agent_id=data["agent_id"],
            user_id=data["user_id"],
            scope=ConsentScope(data["scope"]),
            resource=data["resource"],
            reason=data["reason"],
            requested_at=datetime.fromisoformat(data["requested_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            status=data.get("status", "pending"),
            approved_grant_id=data.get("approved_grant_id"),
        )


class ConsentManager:
    """
    Manages user consent for agent operations.
    
    Provides granular control over what agents can do on behalf of users.
    """
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize the consent manager.
        
        Args:
            storage_path: Path to store consent data
        """
        self.storage_path = storage_path or Path.home() / ".picoclaw" / "governance" / "consent"
        self._grants: dict[str, ConsentGrant] = {}
        self._user_grants: dict[str, list[str]] = {}  # user_id -> grant_ids
        self._agent_grants: dict[str, list[str]] = {}  # agent_id -> grant_ids
        self._requests: dict[str, ConsentRequest] = {}
        self._pending_requests: dict[str, str] = {}  # user_id -> request_id
        self._lock = RLock()
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the consent manager and load existing grants."""
        with self._lock:
            if self._initialized:
                return
            
            self.storage_path.mkdir(parents=True, exist_ok=True)
            await self._load_grants()
            
            self._initialized = True
    
    async def _load_grants(self) -> None:
        """Load grants from storage."""
        grants_file = self.storage_path / "grants.jsonl"
        if not grants_file.exists():
            return
        
        loop = asyncio.get_event_loop()
        content = await loop.run_in_executor(None, grants_file.read_text)
        
        for line in content.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                grant = ConsentGrant.from_dict(data)
                self._index_grant(grant)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"Warning: Failed to load consent grant: {e}")
        
        # Load requests
        requests_file = self.storage_path / "requests.jsonl"
        if requests_file.exists():
            content = await loop.run_in_executor(None, requests_file.read_text)
            for line in content.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    request = ConsentRequest.from_dict(data)
                    self._requests[request.request_id] = request
                    if request.status == "pending":
                        self._pending_requests[request.user_id] = request.request_id
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    print(f"Warning: Failed to load consent request: {e}")
    
    def _index_grant(self, grant: ConsentGrant) -> None:
        """Index a grant for fast lookup."""
        self._grants[grant.grant_id] = grant
        
        if grant.user_id not in self._user_grants:
            self._user_grants[grant.user_id] = []
        if grant.grant_id not in self._user_grants[grant.user_id]:
            self._user_grants[grant.user_id].append(grant.grant_id)
        
        if grant.agent_id not in self._agent_grants:
            self._agent_grants[grant.agent_id] = []
        if grant.grant_id not in self._agent_grants[grant.agent_id]:
            self._agent_grants[grant.agent_id].append(grant.grant_id)
    
    async def _save_grants(self) -> None:
        """Save grants to storage."""
        grants_file = self.storage_path / "grants.jsonl"
        
        lines = []
        for grant in self._grants.values():
            if grant.status == ConsentStatus.ACTIVE or grant.revoked_at:
                lines.append(json.dumps(grant.to_dict()))
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            grants_file.write_text,
            "\n".join(lines) + "\n"
        )
    
    async def _save_requests(self) -> None:
        """Save requests to storage."""
        requests_file = self.storage_path / "requests.jsonl"
        
        lines = []
        for request in self._requests.values():
            lines.append(json.dumps(request.to_dict()))
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            requests_file.write_text,
            "\n".join(lines) + "\n"
        )
    
    async def grant_consent(
        self,
        user_id: str,
        agent_id: str,
        scope: ConsentScope,
        resource_pattern: str = "*",
        duration: Optional[timedelta] = None,
        conditions: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
        granted_by: Optional[str] = None,
    ) -> ConsentGrant:
        """
        Grant consent from user to agent.
        
        Args:
            user_id: User granting consent
            agent_id: Agent receiving consent
            scope: Permission scope
            resource_pattern: Resource pattern (glob)
            duration: Duration of consent (None for permanent)
            conditions: Additional conditions
            metadata: Additional metadata
            granted_by: Delegated granter (for admin grants)
        
        Returns:
            The created consent grant
        """
        async with self._get_lock():
            # Check for existing grant
            existing = await self._find_existing_grant(user_id, agent_id, scope, resource_pattern)
            if existing and existing.is_active:
                return existing
            
            # Create new grant
            expires_at = None
            if duration:
                expires_at = datetime.utcnow() + duration
            
            grant = ConsentGrant(
                grant_id="",
                user_id=user_id,
                agent_id=agent_id,
                scope=scope,
                resource_pattern=resource_pattern,
                expires_at=expires_at,
                conditions=conditions or {},
                metadata=metadata or {},
                granted_by=granted_by,
            )
            
            self._index_grant(grant)
            await self._save_grants()
            
            return grant
    
    async def _find_existing_grant(
        self,
        user_id: str,
        agent_id: str,
        scope: ConsentScope,
        resource_pattern: str,
    ) -> Optional[ConsentGrant]:
        """Find existing active grant."""
        for grant_id in self._user_grants.get(user_id, []):
            grant = self._grants.get(grant_id)
            if (
                grant
                and grant.agent_id == agent_id
                and grant.scope == scope
                and grant.resource_pattern == resource_pattern
                and grant.is_active
            ):
                return grant
        return None
    
    async def revoke_consent(
        self,
        user_id: str,
        agent_id: str,
        reason: str = "",
        scope: Optional[ConsentScope] = None,
    ) -> list[ConsentGrant]:
        """
        Revoke consent from user to agent.
        
        Args:
            user_id: User revoking consent
            agent_id: Agent losing consent
            reason: Reason for revocation
            scope: Specific scope to revoke (None for all)
        
        Returns:
            List of revoked grants
        """
        async with self._get_lock():
            revoked = []
            now = datetime.utcnow()
            
            grant_ids = self._user_grants.get(user_id, [])
            for grant_id in list(grant_ids):  # Copy to avoid modification during iteration
                grant = self._grants.get(grant_id)
                if not grant or grant.agent_id != agent_id:
                    continue
                if scope and grant.scope != scope:
                    continue
                
                grant.status = ConsentStatus.REVOKED
                grant.revoked_at = now
                grant.revocation_reason = reason
                
                revoked.append(grant)
            
            if revoked:
                await self._save_grants()
            
            return revoked
    
    async def check_consent(
        self,
        user_id: str,
        agent_id: str,
        scope: ConsentScope,
        resource: str = "*",
    ) -> bool:
        """
        Check if consent is valid for an operation.
        
        Args:
            user_id: User whose consent is needed
            agent_id: Agent requesting consent
            scope: Required scope
            resource: Resource being accessed
        
        Returns:
            True if consent is valid, False otherwise
        """
        with self._lock:
            grant_ids = self._user_grants.get(user_id, [])
            
            for grant_id in grant_ids:
                grant = self._grants.get(grant_id)
                if not grant or not grant.is_active:
                    continue
                if grant.agent_id != agent_id:
                    continue
                
                # Check scope
                if not ConsentScope.includes(grant.scope, scope):
                    continue
                
                # Check resource pattern
                if resource != "*" and not grant.matches_resource(resource):
                    continue
                
                # Check conditions
                if not self._check_conditions(grant, scope, resource):
                    continue
                
                return True
            
            return False
    
    def _check_conditions(
        self,
        grant: ConsentGrant,
        scope: ConsentScope,
        resource: str,
    ) -> bool:
        """Check if conditions for the grant are met."""
        conditions = grant.conditions
        
        if not conditions:
            return True
        
        # Check time restrictions
        if "allowed_hours" in conditions:
            current_hour = datetime.utcnow().hour
            allowed = conditions["allowed_hours"]
            if isinstance(allowed, list):
                if current_hour not in allowed:
                    return False
        
        # Check IP restrictions
        if "allowed_ips" in conditions:
            # This would need to be passed in context
            pass
        
        # Check max uses
        if "max_uses" in conditions:
            uses = grant.metadata.get("use_count", 0)
            if uses >= conditions["max_uses"]:
                return False
        
        # Check requires approval
        if conditions.get("requires_approval"):
            if not grant.metadata.get("approved"):
                return False
        
        return True
    
    async def record_usage(self, grant_id: str) -> None:
        """Record usage of a consent grant."""
        with self._lock:
            grant = self._grants.get(grant_id)
            if grant:
                grant.metadata["use_count"] = grant.metadata.get("use_count", 0) + 1
                grant.metadata["last_used"] = datetime.utcnow().isoformat()
    
    async def list_consents(
        self,
        user_id: str,
        agent_id: Optional[str] = None,
        scope: Optional[ConsentScope] = None,
        active_only: bool = True,
    ) -> list[ConsentGrant]:
        """
        List user's consents.
        
        Args:
            user_id: User to list consents for
            agent_id: Filter by agent
            scope: Filter by scope
            active_only: Only return active consents
        
        Returns:
            List of matching grants
        """
        with self._lock:
            grants = []
            
            for grant_id in self._user_grants.get(user_id, []):
                grant = self._grants.get(grant_id)
                if not grant:
                    continue
                
                if agent_id and grant.agent_id != agent_id:
                    continue
                
                if scope and grant.scope != scope:
                    continue
                
                if active_only and not grant.is_active:
                    continue
                
                grants.append(grant)
            
            return sorted(grants, key=lambda g: g.granted_at, reverse=True)
    
    async def get_consent(self, grant_id: str) -> Optional[ConsentGrant]:
        """Get a specific consent grant by ID."""
        return self._grants.get(grant_id)
    
    async def request_consent(
        self,
        agent_id: str,
        user_id: str,
        scope: ConsentScope,
        resource: str,
        reason: str,
        duration: Optional[timedelta] = None,
    ) -> ConsentRequest:
        """
        Create a consent request for user approval.
        
        Args:
            agent_id: Agent requesting consent
            user_id: User to request from
            scope: Scope being requested
            resource: Resource being accessed
            reason: Reason for the request
            duration: Requested duration
        
        Returns:
            The created consent request
        """
        request_id = secrets.token_hex(16)
        
        request = ConsentRequest(
            request_id=request_id,
            agent_id=agent_id,
            user_id=user_id,
            scope=scope,
            resource=resource,
            reason=reason,
            expires_at=datetime.utcnow() + timedelta(minutes=30) if not duration else datetime.utcnow() + duration,
        )
        
        async with self._get_lock():
            self._requests[request_id] = request
            self._pending_requests[user_id] = request_id
            await self._save_requests()
        
        return request
    
    async def approve_request(
        self,
        user_id: str,
        request_id: str,
        duration: Optional[timedelta] = None,
    ) -> Optional[ConsentGrant]:
        """Approve a pending consent request."""
        async with self._get_lock():
            request = self._requests.get(request_id)
            if not request or request.user_id != user_id:
                return None
            
            if request.status != "pending":
                return None
            
            request.status = "approved"
            
            # Create the grant
            grant = await self.grant_consent(
                user_id=user_id,
                agent_id=request.agent_id,
                scope=request.scope,
                resource_pattern=request.resource,
                duration=duration or timedelta(days=7),  # Default 7 days
            )
            
            request.approved_grant_id = grant.grant_id
            self._pending_requests.pop(user_id, None)
            
            await self._save_requests()
            
            return grant
    
    async def deny_request(self, user_id: str, request_id: str) -> bool:
        """Deny a pending consent request."""
        async with self._get_lock():
            request = self._requests.get(request_id)
            if not request or request.user_id != user_id:
                return False
            
            if request.status != "pending":
                return False
            
            request.status = "denied"
            self._pending_requests.pop(user_id, None)
            
            await self._save_requests()
            
            return True
    
    async def get_pending_requests(self, user_id: str) -> list[ConsentRequest]:
        """Get all pending consent requests for a user."""
        with self._lock:
            requests = []
            for request in self._requests.values():
                if request.user_id == user_id and request.status == "pending":
                    requests.append(request)
            return sorted(requests, key=lambda r: r.requested_at, reverse=True)
    
    async def suspend_consent(self, grant_id: str, reason: str = "") -> bool:
        """Temporarily suspend a consent grant."""
        with self._lock:
            grant = self._grants.get(grant_id)
            if not grant:
                return False
            
            grant.status = ConsentStatus.SUSPENDED
            grant.metadata["suspension_reason"] = reason
            grant.metadata["suspended_at"] = datetime.utcnow().isoformat()
            
        await self._save_grants()
        return True
    
    async def reactivate_consent(self, grant_id: str) -> bool:
        """Reactivate a suspended consent grant."""
        with self._lock:
            grant = self._grants.get(grant_id)
            if not grant or grant.status != ConsentStatus.SUSPENDED:
                return False
            
            grant.status = ConsentStatus.ACTIVE
            grant.metadata.pop("suspension_reason", None)
            grant.metadata.pop("suspended_at", None)
        
        await self._save_grants()
        return True
    
    async def get_consent_stats(self, user_id: Optional[str] = None) -> dict[str, Any]:
        """Get statistics about consent grants."""
        with self._lock:
            grants = list(self._grants.values())
            
            if user_id:
                grants = [g for g in grants if g.user_id == user_id]
            
            stats = {
                "total_grants": len(grants),
                "active_grants": sum(1 for g in grants if g.is_active),
                "expired_grants": sum(1 for g in grants if g.is_expired),
                "revoked_grants": sum(1 for g in grants if g.status == ConsentStatus.REVOKED),
                "suspended_grants": sum(1 for g in grants if g.status == ConsentStatus.SUSPENDED),
                "by_scope": {},
                "by_agent": {},
            }
            
            for grant in grants:
                scope_key = grant.scope.value
                stats["by_scope"][scope_key] = stats["by_scope"].get(scope_key, 0) + 1
                stats["by_agent"][grant.agent_id] = stats["by_agent"].get(grant.agent_id, 0) + 1
            
            return stats
    
    def _get_lock(self):
        """Get async-compatible lock wrapper."""
        return _ConsentAsyncLock(self._lock)


class _ConsentAsyncLock:
    """Async wrapper for RLock."""
    
    def __init__(self, lock: RLock):
        self._lock = lock
    
    async def __aenter__(self):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._lock.acquire)
        return self
    
    async def __aexit__(self, *args):
        self._lock.release()


# Convenience functions

_manager: Optional[ConsentManager] = None


def get_manager() -> ConsentManager:
    """Get or create the default consent manager."""
    global _manager
    if _manager is None:
        _manager = ConsentManager()
    return _manager


async def grant_consent(
    user_id: str,
    agent_id: str,
    scope: ConsentScope,
    duration: Optional[timedelta] = None,
    **kwargs,
) -> ConsentGrant:
    """Grant consent using default manager."""
    return await get_manager().grant_consent(user_id, agent_id, scope, duration=duration, **kwargs)


async def revoke_consent(user_id: str, agent_id: str, reason: str = "") -> list[ConsentGrant]:
    """Revoke consent using default manager."""
    return await get_manager().revoke_consent(user_id, agent_id, reason)


async def check_consent(
    user_id: str,
    agent_id: str,
    scope: ConsentScope,
    resource: str = "*",
) -> bool:
    """Check consent using default manager."""
    return await get_manager().check_consent(user_id, agent_id, scope, resource)


async def list_consents(user_id: str, **kwargs) -> list[ConsentGrant]:
    """List consents using default manager."""
    return await get_manager().list_consents(user_id, **kwargs)


__all__ = [
    "ConsentScope",
    "ConsentStatus",
    "ConsentGrant",
    "ConsentRequest",
    "ConsentManager",
    "get_manager",
    "grant_consent",
    "revoke_consent",
    "check_consent",
    "list_consents",
]