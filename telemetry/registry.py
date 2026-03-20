"""
Agent Registry - Central directory of known agents.

This module provides a registry for tracking agent metadata,
capabilities, and supporting agent discovery and search.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Self

import aiofiles


class AgentCapability(Enum):
    """Known agent capabilities."""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    SHELL_EXEC = "shell_exec"
    WEB_FETCH = "web_fetch"
    WEB_SEARCH = "web_search"
    BROWSER_CONTROL = "browser_control"
    CODE_GENERATION = "code_generation"
    IMAGE_ANALYSIS = "image_analysis"
    VOICE = "voice"
    NOTIFICATIONS = "notifications"
    CONTAINER = "container"
    NETWORK = "network"
    DATABASE = "database"
    MESSAGING = "messaging"


class AgentPlatform(Enum):
    """Supported agent platforms."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    META = "meta"
    OPEN_SOURCE = "open_source"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class RegistryError(Exception):
    """Base exception for registry errors."""
    pass


class AgentAlreadyExistsError(RegistryError):
    """Agent already exists in registry."""
    pass


class AgentNotFoundError(RegistryError):
    """Agent not found in registry."""
    pass


@dataclass
class AgentMetadata:
    """Metadata for a registered agent."""
    name: str
    platform: AgentPlatform
    owner: str
    description: str = ""
    version: str = "1.0.0"
    capabilities: list[AgentCapability] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    endpoints: list[str] = field(default_factory=list)
    source_ip: str | None = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "platform": self.platform.value,
            "owner": self.owner,
            "description": self.description,
            "version": self.version,
            "capabilities": [c.value for c in self.capabilities],
            "tags": self.tags,
            "config": self.config,
            "endpoints": self.endpoints,
            "source_ip": self.source_ip,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Create from dictionary."""
        capabilities = []
        for cap in data.get("capabilities", []):
            try:
                capabilities.append(AgentCapability(cap))
            except ValueError:
                pass

        platform_str = data.get("platform", "unknown")
        try:
            platform = AgentPlatform(platform_str)
        except ValueError:
            platform = AgentPlatform.UNKNOWN

        return cls(
            name=data["name"],
            platform=platform,
            owner=data.get("owner", "unknown"),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            capabilities=capabilities,
            tags=data.get("tags", []),
            config=data.get("config", {}),
            endpoints=data.get("endpoints", []),
            source_ip=data.get("source_ip"),
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
        )


@dataclass
class RegisteredAgent:
    """A fully registered agent."""
    agent_id: str
    metadata: AgentMetadata
    registration_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    is_active: bool = True
    trust_level: int = 0  # 0=untrusted, 1=verified, 2=trusted, 3=admin
    notes: list[str] = field(default_factory=list)
    custom_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_id": self.agent_id,
            "metadata": self.metadata.to_dict(),
            "registration_time": self.registration_time,
            "last_seen": self.last_seen,
            "is_active": self.is_active,
            "trust_level": self.trust_level,
            "notes": self.notes,
            "custom_data": self.custom_data,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Create from dictionary."""
        return cls(
            agent_id=data["agent_id"],
            metadata=AgentMetadata.from_dict(data["metadata"]),
            registration_time=data.get("registration_time", time.time()),
            last_seen=data.get("last_seen", time.time()),
            is_active=data.get("is_active", True),
            trust_level=data.get("trust_level", 0),
            notes=data.get("notes", []),
            custom_data=data.get("custom_data", {}),
        )


class AgentRegistry:
    """
    Central registry for known agents.

    Features:
    - Agent registration with full metadata
    - Agent lookup by ID
    - Search by name, platform, owner, capabilities
    - Persistence to JSON file
    - Concurrency-safe operations
    """

    def __init__(self, storage_path: str | Path | None = None):
        """
        Initialize agent registry.

        Args:
            storage_path: Path to JSON file for persistence
        """
        self._agents: dict[str, RegisteredAgent] = {}
        self._name_index: dict[str, str] = {}  # name -> agent_id
        self._owner_index: dict[str, list[str]] = {}  # owner -> [agent_ids]
        self._platform_index: dict[AgentPlatform, list[str]] = {}  # platform -> [agent_ids]
        self._capability_index: dict[AgentCapability, list[str]] = {}  # capability -> [agent_ids]
        self._storage_path = Path(storage_path) if storage_path else None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Initialize the registry and load from disk."""
        async with self._lock:
            await self._load_from_disk()

    async def register(
        self,
        agent_id: str,
        name: str,
        platform: AgentPlatform | str,
        owner: str,
        description: str = "",
        version: str = "1.0.0",
        capabilities: list[AgentCapability | str] | None = None,
        tags: list[str] | None = None,
        config: dict[str, Any] | None = None,
        endpoints: list[str] | None = None,
        source_ip: str | None = None,
        trust_level: int = 0,
        custom_data: dict[str, Any] | None = None,
        overwrite: bool = False,
    ) -> RegisteredAgent:
        """
        Register a new agent with full metadata.

        Args:
            agent_id: Unique agent identifier
            name: Human-readable agent name
            platform: Agent platform
            owner: Agent owner identifier
            description: Agent description
            version: Agent version
            capabilities: List of agent capabilities
            tags: List of tags
            config: Configuration dictionary
            endpoints: List of endpoint URLs
            source_ip: Source IP address
            trust_level: Trust level (0-3)
            custom_data: Custom data dictionary
            overwrite: Overwrite existing registration

        Returns:
            The registered agent

        Raises:
            AgentAlreadyExistsError: If agent already exists and overwrite=False
        """
        # Normalize capabilities
        norm_capabilities: list[AgentCapability] = []
        for cap in (capabilities or []):
            if isinstance(cap, AgentCapability):
                norm_capabilities.append(cap)
            else:
                try:
                    norm_capabilities.append(AgentCapability(cap))
                except ValueError:
                    pass

        # Normalize platform
        if isinstance(platform, str):
            try:
                platform = AgentPlatform(platform)
            except ValueError:
                platform = AgentPlatform.UNKNOWN

        # Create metadata
        metadata = AgentMetadata(
            name=name,
            platform=platform,
            owner=owner,
            description=description,
            version=version,
            capabilities=norm_capabilities,
            tags=tags or [],
            config=config or {},
            endpoints=endpoints or [],
            source_ip=source_ip,
        )

        # Create agent
        now = time.time()
        agent = RegisteredAgent(
            agent_id=agent_id,
            metadata=metadata,
            registration_time=now,
            last_seen=now,
            is_active=True,
            trust_level=max(0, min(3, trust_level)),
            custom_data=custom_data or {},
        )

        async with self._lock:
            if agent_id in self._agents and not overwrite:
                raise AgentAlreadyExistsError(f"Agent already exists: {agent_id}")

            # Remove old indexes if updating
            if agent_id in self._agents:
                await self._remove_indexes(self._agents[agent_id])

            # Add agent
            self._agents[agent_id] = agent

            # Update indexes
            await self._update_indexes(agent)

            # Save to disk
            await self._save_to_disk()

        return agent

    async def _remove_indexes(self, agent: RegisteredAgent) -> None:
        """Remove agent from indexes."""
        # Name index
        if agent.metadata.name in self._name_index:
            del self._name_index[agent.metadata.name]

        # Owner index
        if agent.metadata.owner in self._owner_index:
            if agent.agent_id in self._owner_index[agent.metadata.owner]:
                self._owner_index[agent.metadata.owner].remove(agent.agent_id)

        # Platform index
        if agent.metadata.platform in self._platform_index:
            if agent.agent_id in self._platform_index[agent.metadata.platform]:
                self._platform_index[agent.metadata.platform].remove(agent.agent_id)

        # Capability index
        for cap in agent.metadata.capabilities:
            if cap in self._capability_index:
                if agent.agent_id in self._capability_index[cap]:
                    self._capability_index[cap].remove(agent.agent_id)

    async def _update_indexes(self, agent: RegisteredAgent) -> None:
        """Update indexes for agent."""
        # Name index
        self._name_index[agent.metadata.name] = agent.agent_id

        # Owner index
        if agent.metadata.owner not in self._owner_index:
            self._owner_index[agent.metadata.owner] = []
        if agent.agent_id not in self._owner_index[agent.metadata.owner]:
            self._owner_index[agent.metadata.owner].append(agent.agent_id)

        # Platform index
        if agent.metadata.platform not in self._platform_index:
            self._platform_index[agent.metadata.platform] = []
        if agent.agent_id not in self._platform_index[agent.metadata.platform]:
            self._platform_index[agent.metadata.platform].append(agent.agent_id)

        # Capability index
        for cap in agent.metadata.capabilities:
            if cap not in self._capability_index:
                self._capability_index[cap] = []
            if agent.agent_id not in self._capability_index[cap]:
                self._capability_index[cap].append(agent.agent_id)

    def get(self, agent_id: str) -> RegisteredAgent:
        """
        Get agent by ID.

        Args:
            agent_id: Agent identifier

        Returns:
            The registered agent

        Raises:
            AgentNotFoundError: If agent not found
        """
        if agent_id not in self._agents:
            raise AgentNotFoundError(f"Agent not found: {agent_id}")
        return self._agents[agent_id]

    def get_by_name(self, name: str) -> RegisteredAgent | None:
        """
        Get agent by name.

        Args:
            name: Agent name

        Returns:
            The registered agent or None
        """
        agent_id = self._name_index.get(name)
        if agent_id:
            return self._agents.get(agent_id)
        return None

    def search(
        self,
        query: str,
        fields: list[str] | None = None,
        limit: int = 100,
    ) -> list[RegisteredAgent]:
        """
        Search agents by name, platform, owner, etc.

        Args:
            query: Search query (case-insensitive substring match)
            fields: Fields to search (name, platform, owner, description, tags)
            limit: Maximum results to return

        Returns:
            List of matching agents
        """
        if fields is None:
            fields = ["name", "platform", "owner", "description", "tags"]

        query_lower = query.lower()
        results = []

        for agent in self._agents.values():
            match = False

            if "name" in fields and query_lower in agent.metadata.name.lower():
                match = True
            elif "platform" in fields and query_lower in agent.metadata.platform.value.lower():
                match = True
            elif "owner" in fields and query_lower in agent.metadata.owner.lower():
                match = True
            elif "description" in fields and query_lower in agent.metadata.description.lower():
                match = True
            elif "tags" in fields:
                for tag in agent.metadata.tags:
                    if query_lower in tag.lower():
                        match = True
                        break

            if match:
                results.append(agent)
                if len(results) >= limit:
                    break

        return results

    def search_by_capability(
        self,
        capability: AgentCapability | str,
    ) -> list[RegisteredAgent]:
        """
        Search agents by capability.

        Args:
            capability: Capability to search for

        Returns:
            List of agents with the capability
        """
        if isinstance(capability, str):
            try:
                capability = AgentCapability(capability)
            except ValueError:
                return []

        agent_ids = self._capability_index.get(capability, [])
        return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def search_by_owner(self, owner: str) -> list[RegisteredAgent]:
        """
        Search agents by owner.

        Args:
            owner: Owner identifier

        Returns:
            List of agents owned by the specified owner
        """
        agent_ids = self._owner_index.get(owner, [])
        return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def search_by_platform(
        self,
        platform: AgentPlatform | str,
    ) -> list[RegisteredAgent]:
        """
        Search agents by platform.

        Args:
            platform: Platform to search for

        Returns:
            List of agents on the specified platform
        """
        if isinstance(platform, str):
            try:
                platform = AgentPlatform(platform)
            except ValueError:
                return []

        agent_ids = self._platform_index.get(platform, [])
        return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def list_all(self) -> list[RegisteredAgent]:
        """
        List all registered agents.

        Returns:
            List of all registered agents
        """
        return list(self._agents.values())

    async def update(
        self,
        agent_id: str,
        **updates: Any,
    ) -> RegisteredAgent:
        """
        Update agent metadata.

        Args:
            agent_id: Agent identifier
            **updates: Fields to update

        Returns:
            Updated agent

        Raises:
            AgentNotFoundError: If agent not found
        """
        async with self._lock:
            if agent_id not in self._agents:
                raise AgentNotFoundError(f"Agent not found: {agent_id}")

            agent = self._agents[agent_id]

            # Update metadata
            metadata_updates = {}
            for key in ["name", "platform", "owner", "description", "version", "tags", "config", "endpoints", "source_ip"]:
                if key in updates:
                    metadata_updates[key] = updates.pop(key)

            if metadata_updates:
                # Need to reindex if name/platform/owner changes
                old_name = agent.metadata.name
                old_platform = agent.metadata.platform
                old_owner = agent.metadata.owner

                for key, value in metadata_updates.items():
                    if key == "platform" and isinstance(value, str):
                        try:
                            value = AgentPlatform(value)
                        except ValueError:
                            value = AgentPlatform.UNKNOWN
                    setattr(agent.metadata, key, value)

                agent.metadata.updated_at = time.time()

                # Reindex if needed
                if old_name != agent.metadata.name or old_platform != agent.metadata.platform or old_owner != agent.metadata.owner:
                    await self._remove_indexes(RegisteredAgent(
                        agent_id=agent_id,
                        metadata=AgentMetadata(name=old_name, platform=old_platform, owner=old_owner),
                    ))
                    await self._update_indexes(agent)

            # Update other fields
            if "is_active" in updates:
                agent.is_active = updates.pop("is_active")
            if "trust_level" in updates:
                agent.trust_level = max(0, min(3, updates.pop("trust_level")))
            if "custom_data" in updates:
                agent.custom_data.update(updates.pop("custom_data"))
            if "notes" in updates:
                agent.notes.append(updates.pop("notes"))

            agent.last_seen = time.time()

            await self._save_to_disk()
            return agent

    async def unregister(self, agent_id: str) -> bool:
        """
        Unregister an agent.

        Args:
            agent_id: Agent identifier

        Returns:
            True if agent was removed

        Raises:
            AgentNotFoundError: If agent not found
        """
        async with self._lock:
            if agent_id not in self._agents:
                raise AgentNotFoundError(f"Agent not found: {agent_id}")

            agent = self._agents[agent_id]
            await self._remove_indexes(agent)
            del self._agents[agent_id]

            await self._save_to_disk()
            return True

    def get_statistics(self) -> dict[str, Any]:
        """Get registry statistics."""
        platform_counts: dict[str, int] = {}
        owner_counts: dict[str, int] = {}
        capability_counts: dict[str, int] = {}

        for agent in self._agents.values():
            # Platform counts
            platform = agent.metadata.platform.value
            platform_counts[platform] = platform_counts.get(platform, 0) + 1

            # Owner counts
            owner = agent.metadata.owner
            owner_counts[owner] = owner_counts.get(owner, 0) + 1

            # Capability counts
            for cap in agent.metadata.capabilities:
                capability_counts[cap.value] = capability_counts.get(cap.value, 0) + 1

        return {
            "total_agents": len(self._agents),
            "active_agents": sum(1 for a in self._agents.values() if a.is_active),
            "platforms": platform_counts,
            "owners": owner_counts,
            "capabilities": capability_counts,
        }

    async def _load_from_disk(self) -> None:
        """Load registry from disk."""
        if not self._storage_path:
            return

        if not self._storage_path.exists():
            return

        try:
            async with aiofiles.open(self._storage_path, "r") as f:
                content = await f.read()
                data = json.loads(content)

            for agent_data in data.get("agents", []):
                try:
                    agent = RegisteredAgent.from_dict(agent_data)
                    self._agents[agent.agent_id] = agent
                    await self._update_indexes(agent)
                except (KeyError, ValueError) as e:
                    print(f"Error loading agent: {e}")

        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading registry: {e}")

    async def _save_to_disk(self) -> None:
        """Save registry to disk."""
        if not self._storage_path:
            return

        self._storage_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "version": "1.0",
            "timestamp": time.time(),
            "agents": [agent.to_dict() for agent in self._agents.values()],
        }

        async with aiofiles.open(self._storage_path, "w") as f:
            await f.write(json.dumps(data, indent=2))


# Context manager for easy usage
class AgentRegistryContext:
    """Context manager for AgentRegistry."""

    def __init__(self, registry: AgentRegistry):
        self.registry = registry

    async def __aenter__(self) -> AgentRegistry:
        await self.registry.initialize()
        return self.registry

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        # Registry auto-saves on changes
        pass