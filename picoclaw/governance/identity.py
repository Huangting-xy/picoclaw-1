"""
Agent Identity Management for Picoclaw Governance Module.

This module provides identity registration, verification, and management
for autonomous agents operating within the Picoclaw framework.
"""

from __future__ import annotations

import json
import secrets
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional
import asyncio
from threading import RLock


class Capability(str, Enum):
    """Standard agent capabilities."""
    FILE_READ = "file:read"
    FILE_WRITE = "file:write"
    FILE_DELETE = "file:delete"
    NETWORK_HTTP = "network:http"
    NETWORK_WEBSOCKET = "network:websocket"
    SHELL_EXECUTE = "shell:execute"
    PROCESS_SPAWN = "process:spawn"
    BROWSER_AUTOMATION = "browser:automation"
    CODE_GENERATION = "code:generation"
    DATA_PROCESSING = "data:processing"
    ADMIN = "admin"
    SUPERUSER = "superuser"


class IdentityStatus(str, Enum):
    """Identity lifecycle status."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class CapabilityAttestation:
    """Attestation of a specific capability by a trusted authority."""
    capability: Capability
    attested_by: str  # Identity ID of attester
    attested_at: datetime
    expires_at: Optional[datetime] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    
    def is_valid(self) -> bool:
        """Check if attestation is still valid."""
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize attestation to dictionary."""
        return {
            "capability": self.capability.value,
            "attested_by": self.attested_by,
            "attested_at": self.attested_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "metadata": self.metadata,
            "signature": self.signature,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CapabilityAttestation":
        """Deserialize attestation from dictionary."""
        return cls(
            capability=Capability(data["capability"]),
            attested_by=data["attested_by"],
            attested_at=datetime.fromisoformat(data["attested_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            metadata=data.get("metadata", {}),
            signature=data.get("signature", ""),
        )


@dataclass
class AgentIdentity:
    """
    Represents a unique agent identity in the system.
    
    Each identity has a unique ID, public key for verification,
    and a list of capabilities that define what the agent can do.
    """
    agent_id: str
    public_key: str
    capabilities: list[Capability] = field(default_factory=list)
    attestations: list[CapabilityAttestation] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    status: IdentityStatus = IdentityStatus.ACTIVE
    metadata: dict[str, Any] = field(default_factory=dict)
    parent_identity: Optional[str] = None  # For derived/spawned identities
    trust_level: int = 0  # 0-100 scale
    
    def __post_init__(self):
        """Post-initialization validation."""
        if not self.agent_id:
            raise ValueError("agent_id is required")
        if not self.public_key:
            raise ValueError("public_key is required")
    
    @property
    def is_expired(self) -> bool:
        """Check if identity has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    @property
    def is_active(self) -> bool:
        """Check if identity is active and usable."""
        return self.status == IdentityStatus.ACTIVE and not self.is_expired
    
    def has_capability(self, capability: Capability) -> bool:
        """Check if agent has a specific capability."""
        # Direct capability
        if capability in self.capabilities:
            return True
        
        # Check for superuser capability (has all permissions)
        if Capability.SUPERUSER in self.capabilities:
            return True
        
        # Check attested capabilities
        for attestation in self.attestations:
            if attestation.capability == capability and attestation.is_valid():
                return True
        
        return False
    
    def has_any_capability(self, capabilities: list[Capability]) -> bool:
        """Check if agent has any of the specified capabilities."""
        return any(self.has_capability(cap) for cap in capabilities)
    
    def has_all_capabilities(self, capabilities: list[Capability]) -> bool:
        """Check if agent has all of the specified capabilities."""
        return all(self.has_capability(cap) for cap in capabilities)
    
    def add_attestation(self, attestation: CapabilityAttestation) -> None:
        """Add a capability attestation."""
        # Remove any existing attestation for the same capability
        self.attestations = [
            a for a in self.attestations if a.capability != attestation.capability
        ]
        self.attestations.append(attestation)
        self.updated_at = datetime.utcnow()
    
    def remove_attestation(self, capability: Capability) -> bool:
        """Remove a capability attestation."""
        original_count = len(self.attestations)
        self.attestations = [
            a for a in self.attestations if a.capability != capability
        ]
        if len(self.attestations) < original_count:
            self.updated_at = datetime.utcnow()
            return True
        return False
    
    def get_valid_attestations(self) -> list[CapabilityAttestation]:
        """Get list of currently valid attestations."""
        return [a for a in self.attestations if a.is_valid()]
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize identity to dictionary."""
        return {
            "agent_id": self.agent_id,
            "public_key": self.public_key,
            "capabilities": [cap.value for cap in self.capabilities],
            "attestations": [a.to_dict() for a in self.attestations],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status.value,
            "metadata": self.metadata,
            "parent_identity": self.parent_identity,
            "trust_level": self.trust_level,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentIdentity":
        """Deserialize identity from dictionary."""
        return cls(
            agent_id=data["agent_id"],
            public_key=data["public_key"],
            capabilities=[Capability(c) for c in data.get("capabilities", [])],
            attestations=[CapabilityAttestation.from_dict(a) for a in data.get("attestations", [])],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            status=IdentityStatus(data.get("status", "active")),
            metadata=data.get("metadata", {}),
            parent_identity=data.get("parent_identity"),
            trust_level=data.get("trust_level", 0),
        )


@dataclass
class SignatureVerification:
    """Result of signature verification."""
    valid: bool
    identity: Optional[AgentIdentity] = None
    error: Optional[str] = None
    verified_at: datetime = field(default_factory=datetime.utcnow)


class IdentityManager:
    """
    Manages agent identities in the Picoclaw system.
    
    Provides registration, verification, and lifecycle management
    for autonomous agent identities.
    """
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize the identity manager.
        
        Args:
            storage_path: Path to store identity data (defaults to ~/.picoclaw/identities)
        """
        self.storage_path = storage_path or Path.home() / ".picoclaw" / "governance" / "identities"
        self._identities: dict[str, AgentIdentity] = {}
        self._public_key_index: dict[str, str] = {}  # public_key -> agent_id
        self._lock = RLock()
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the identity manager and load existing identities."""
        with self._lock:
            if self._initialized:
                return
            
            # Create storage directory if needed
            self.storage_path.mkdir(parents=True, exist_ok=True)
            
            # Load existing identities
            await self._load_identities()
            
            self._initialized = True
    
    async def _load_identities(self) -> None:
        """Load identities from storage."""
        identities_file = self.storage_path / "identities.jsonl"
        if not identities_file.exists():
            return
        
        loop = asyncio.get_event_loop()
        content = await loop.run_in_executor(None, identities_file.read_text)
        
        for line in content.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                identity = AgentIdentity.from_dict(data)
                self._identities[identity.agent_id] = identity
                self._public_key_index[identity.public_key] = identity.agent_id
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                # Log error but continue loading
                print(f"Warning: Failed to load identity: {e}")
    
    async def _save_identities(self) -> None:
        """Save identities to storage."""
        identities_file = self.storage_path / "identities.jsonl"
        
        lines = []
        for identity in self._identities.values():
            lines.append(json.dumps(identity.to_dict()))
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            identities_file.write_text,
            "\n".join(lines) + "\n"
        )
    
    def _generate_key_pair(self) -> tuple[str, str]:
        """Generate a new public/private key pair."""
        # For demonstration, using a simple key generation
        # In production, use proper cryptographic libraries like cryptography
        private_key = secrets.token_hex(32)
        public_key = hashlib.sha256(private_key.encode()).hexdigest()
        return public_key, private_key
    
    async def register_identity(
        self,
        agent: Any = None,
        agent_id: Optional[str] = None,
        capabilities: Optional[list[Capability]] = None,
        public_key: Optional[str] = None,
        private_key: Optional[str] = None,
        expires_in: Optional[timedelta] = None,
        metadata: Optional[dict[str, Any]] = None,
        parent_identity: Optional[str] = None,
        trust_level: int = 0,
    ) -> tuple[AgentIdentity, str]:
        """
        Register a new agent identity.
        
        Args:
            agent: Agent object with id and capabilities attributes
            agent_id: Unique identifier for the agent
            capabilities: List of capabilities to grant
            public_key: Existing public key (if None, generates new)
            private_key: Existing private key (if None, generates new)
            expires_in: Time until identity expires
            metadata: Additional metadata
            parent_identity: Parent identity ID for derived identities
            trust_level: Trust level (0-100)
        
        Returns:
            Tuple of (AgentIdentity, private_key)
        """
        async with self._get_lock():
            # Extract from agent object if provided
            if agent:
                agent_id = agent_id or getattr(agent, "id", None) or f"agent_{secrets.token_hex(8)}"
                agent_capabilities = getattr(agent, "capabilities", [])
                if isinstance(agent_capabilities[0], str) if agent_capabilities else False:
                    capabilities = [Capability(c) for c in agent_capabilities]
                else:
                    capabilities = capabilities or agent_capabilities
            
            # Generate ID if not provided
            if not agent_id:
                agent_id = f"agent_{secrets.token_hex(8)}"
            
            # Check for duplicate
            if agent_id in self._identities:
                raise ValueError(f"Identity {agent_id} already exists")
            
            # Generate or use provided keys
            if not public_key or not private_key:
                public_key, private_key = self._generate_key_pair()
            
            # Create identity
            expires_at = None
            if expires_in:
                expires_at = datetime.utcnow() + expires_in
            
            identity = AgentIdentity(
                agent_id=agent_id,
                public_key=public_key,
                capabilities=capabilities or [],
                expires_at=expires_at,
                metadata=metadata or {},
                parent_identity=parent_identity,
                trust_level=max(0, min(100, trust_level)),
            )
            
            # Store identity
            self._identities[identity.agent_id] = identity
            self._public_key_index[public_key] = identity.agent_id
            
            # Persist
            await self._save_identities()
            
            return identity, private_key
    
    async def verify_identity(
        self,
        agent_id: str,
        signature: str,
        message: Optional[str] = None,
    ) -> SignatureVerification:
        """
        Verify an agent identity using signature.
        
        Args:
            agent_id: The agent ID to verify
            signature: The signature to verify
            message: Optional message that was signed
        
        Returns:
            SignatureVerification result
        """
        async with self._get_lock():
            # Get identity
            identity = self._identities.get(agent_id)
            if not identity:
                return SignatureVerification(
                    valid=False,
                    error=f"Identity {agent_id} not found"
                )
            
            # Check status
            if not identity.is_active:
                return SignatureVerification(
                    valid=False,
                    identity=identity,
                    error=f"Identity is {identity.status.value}"
                )
            
            # Check expiration
            if identity.is_expired:
                return SignatureVerification(
                    valid=False,
                    identity=identity,
                    error="Identity has expired"
                )
            
            # Verify signature
            # For demonstration, using simple hash comparison
            # In production, use proper cryptographic verification
            expected_prefix = hashlib.sha256(
                (identity.public_key + (message or "")).encode()
            ).hexdigest()[:16]
            
            if signature.startswith(expected_prefix):
                return SignatureVerification(
                    valid=True,
                    identity=identity
                )
            
            return SignatureVerification(
                valid=False,
                identity=identity,
                error="Invalid signature"
            )
    
    async def revoke_identity(self, agent_id: str, reason: str = "") -> bool:
        """
        Revoke a compromised identity.
        
        Args:
            agent_id: The identity to revoke
            reason: Reason for revocation
        
        Returns:
            True if revoked, False if not found
        """
        async with self._get_lock():
            identity = self._identities.get(agent_id)
            if not identity:
                return False
            
            identity.status = IdentityStatus.REVOKED
            identity.updated_at = datetime.utcnow()
            identity.metadata["revocation_reason"] = reason
            identity.metadata["revoked_at"] = datetime.utcnow().isoformat()
            
            await self._save_identities()
            return True
    
    async def suspend_identity(self, agent_id: str, reason: str = "") -> bool:
        """Suspend an identity temporarily."""
        async with self._get_lock():
            identity = self._identities.get(agent_id)
            if not identity:
                return False
            
            identity.status = IdentityStatus.SUSPENDED
            identity.updated_at = datetime.utcnow()
            identity.metadata["suspension_reason"] = reason
            
            await self._save_identities()
            return True
    
    async def reactivate_identity(self, agent_id: str) -> bool:
        """Reactivate a suspended identity."""
        async with self._get_lock():
            identity = self._identities.get(agent_id)
            if not identity or identity.status not in (IdentityStatus.SUSPENDED, IdentityStatus.ACTIVE):
                return False
            
            identity.status = IdentityStatus.ACTIVE
            identity.updated_at = datetime.utcnow()
            identity.metadata.pop("suspension_reason", None)
            
            await self._save_identities()
            return True
    
    async def add_capability(
        self,
        agent_id: str,
        capability: Capability,
        attestation: Optional[CapabilityAttestation] = None,
    ) -> bool:
        """Add a capability to an identity."""
        async with self._get_lock():
            identity = self._identities.get(agent_id)
            if not identity:
                return False
            
            if capability not in identity.capabilities:
                identity.capabilities.append(capability)
            
            if attestation:
                identity.add_attestation(attestation)
            
            identity.updated_at = datetime.utcnow()
            await self._save_identities()
            return True
    
    async def remove_capability(self, agent_id: str, capability: Capability) -> bool:
        """Remove a capability from an identity."""
        async with self._get_lock():
            identity = self._identities.get(agent_id)
            if not identity:
                return False
            
            if capability in identity.capabilities:
                identity.capabilities.remove(capability)
                identity.updated_at = datetime.utcnow()
                await self._save_identities()
                return True
            return False
    
    def _get_lock(self):
        """Get async-compatible lock wrapper."""
        return _AsyncRLockWrapper(self._lock)


class _AsyncRLockWrapper:
    """Async wrapper for RLock."""
    
    def __init__(self, lock: RLock):
        self._lock = lock
    
    async def __aenter__(self):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._lock.acquire)
        return self
    
    async def __aexit__(self, *args):
        self._lock.release()


def list_identities(
    manager: IdentityManager,
    status: Optional[IdentityStatus] = None,
    capability: Optional[Capability] = None,
    trust_level_min: Optional[int] = None,
) -> list[AgentIdentity]:
    """
    List all registered identities with optional filtering.
    
    Args:
        manager: IdentityManager instance
        status: Filter by status
        capability: Filter by capability
        trust_level_min: Minimum trust level
    
    Returns:
        List of matching identities
    """
    identities = list(manager._identities.values())
    
    if status:
        identities = [i for i in identities if i.status == status]
    
    if capability:
        identities = [i for i in identities if i.has_capability(capability)]
    
    if trust_level_min is not None:
        identities = [i for i in identities if i.trust_level >= trust_level_min]
    
    return identities


def get_identity(manager: IdentityManager, agent_id: str) -> Optional[AgentIdentity]:
    """
    Get identity details by agent ID.
    
    Args:
        manager: IdentityManager instance
        agent_id: Agent ID to look up
    
    Returns:
        AgentIdentity if found, None otherwise
    """
    return manager._identities.get(agent_id)


def get_identity_by_public_key(
    manager: IdentityManager,
    public_key: str,
) -> Optional[AgentIdentity]:
    """
    Get identity by public key.
    
    Args:
        manager: IdentityManager instance
        public_key: Public key to look up
    
    Returns:
        AgentIdentity if found, None otherwise
    """
    agent_id = manager._public_key_index.get(public_key)
    if agent_id:
        return manager._identities.get(agent_id)
    return None


async def register_identity(
    manager: IdentityManager,
    agent: Any = None,
    **kwargs,
) -> tuple[AgentIdentity, str]:
    """
    Register a new agent identity.
    
    Convenience wrapper for IdentityManager.register_identity.
    """
    return await manager.register_identity(agent=agent, **kwargs)


async def verify_identity(
    manager: IdentityManager,
    agent_id: str,
    signature: str,
    message: Optional[str] = None,
) -> SignatureVerification:
    """
    Verify an agent identity using signature.
    
    Convenience wrapper for IdentityManager.verify_identity.
    """
    return await manager.verify_identity(agent_id, signature, message)


async def revoke_identity(
    manager: IdentityManager,
    agent_id: str,
    reason: str = "",
) -> bool:
    """
    Revoke a compromised identity.
    
    Convenience wrapper for IdentityManager.revoke_identity.
    """
    return await manager.revoke_identity(agent_id, reason)


# Initialize a default identity manager
_default_manager: Optional[IdentityManager] = None


def get_default_manager() -> IdentityManager:
    """Get or create the default identity manager."""
    global _default_manager
    if _default_manager is None:
        _default_manager = IdentityManager()
    return _default_manager


__all__ = [
    "Capability",
    "IdentityStatus",
    "CapabilityAttestation",
    "AgentIdentity",
    "SignatureVerification",
    "IdentityManager",
    "list_identities",
    "get_identity",
    "get_identity_by_public_key",
    "register_identity",
    "verify_identity",
    "revoke_identity",
    "get_default_manager",
]