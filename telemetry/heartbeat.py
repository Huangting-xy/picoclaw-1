"""
Agent Heartbeat System - Track active agents and their status.

This module provides real-time tracking of agent health through heartbeats,
with automatic pruning of stale agents and JSONL persistence.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Self

import aiofiles


class AgentStatus(Enum):
    """Agent operational status."""
    UNKNOWN = "unknown"
    ONLINE = "online"
    BUSY = "busy"
    IDLE = "idle"
    ERROR = "error"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"


class HeartbeatError(Exception):
    """Base exception for heartbeat errors."""
    pass


class AgentNotFoundError(HeartbeatError):
    """Agent not found in registry."""
    pass


@dataclass
class HeartbeatRecord:
    """Single heartbeat record."""
    agent_id: str
    timestamp: float
    status: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Create from dictionary."""
        return cls(
            agent_id=data["agent_id"],
            timestamp=data["timestamp"],
            status=data["status"],
            metadata=data.get("metadata", {}),
        )


@dataclass
class AgentInfo:
    """Agent registration information."""
    agent_id: str
    registered_at: float
    last_heartbeat: float
    status: AgentStatus = AgentStatus.UNKNOWN
    metadata: dict[str, Any] = field(default_factory=dict)
    heartbeat_history: list[HeartbeatRecord] = field(default_factory=list)
    total_heartbeats: int = 0
    consecutive_failures: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_id": self.agent_id,
            "registered_at": self.registered_at,
            "last_heartbeat": self.last_heartbeat,
            "status": self.status.value,
            "metadata": self.metadata,
            "heartbeat_history": [h.to_dict() for h in self.heartbeat_history[-100:]],
            "total_heartbeats": self.total_heartbeats,
            "consecutive_failures": self.consecutive_failures,
        }

    @property
    def seconds_since_heartbeat(self) -> float:
        """Seconds since last heartbeat."""
        return time.time() - self.last_heartbeat

    def is_stale(self, threshold_seconds: float = 300.0) -> bool:
        """Check if agent heartbeat is stale."""
        return self.seconds_since_heartbeat > threshold_seconds


class HeartbeatManager:
    """
    Manages agent heartbeats and tracks active agents.

    Features:
    - Agent registration with metadata
    - Heartbeat recording and history
    - Active agent discovery
    - Automatic stale agent pruning
    - JSONL persistence with rotation
    """

    # Maximum history size per agent
    MAX_HISTORY_SIZE = 1000
    # Maximum total agents tracked
    MAX_AGENTS = 10000
    # Default stale threshold in seconds
    DEFAULT_STALE_THRESHOLD = 300

    def __init__(
        self,
        storage_path: str | Path | None = None,
        auto_save: bool = True,
        stale_threshold: float = DEFAULT_STALE_THRESHOLD,
    ):
        """
        Initialize heartbeat manager.

        Args:
            storage_path: Path for JSONL storage file
            auto_save: Automatically save heartbeats to disk
            stale_threshold: Seconds before agent is considered stale
        """
        self._agents: dict[str, AgentInfo] = {}
        self._storage_path = Path(storage_path) if storage_path else None
        self._auto_save = auto_save
        self._stale_threshold = stale_threshold
        self._lock = asyncio.Lock()
        self._background_task: asyncio.Task | None = None
        self._running = False
        self._subscriber_queues: list[asyncio.Queue] = []

    async def start(self) -> None:
        """Start the heartbeat manager (load state, start background tasks)."""
        async with self._lock:
            if self._running:
                return

            self._running = True
            await self._load_from_disk()
            self._background_task = asyncio.create_task(self._background_cleanup())

    async def stop(self) -> None:
        """Stop the heartbeat manager (save state, stop background tasks)."""
        async with self._lock:
            self._running = False
            if self._background_task:
                self._background_task.cancel()
                try:
                    await self._background_task
                except asyncio.CancelledError:
                    pass
            await self._save_to_disk()

    async def register_agent(
        self,
        agent_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> AgentInfo:
        """
        Register a new agent.

        Args:
            agent_id: Unique agent identifier
            metadata: Additional agent metadata

        Returns:
            AgentInfo for the registered agent
        """
        async with self._lock:
            if agent_id in self._agents:
                # Update existing registration
                agent = self._agents[agent_id]
                if metadata:
                    agent.metadata.update(metadata)
                return agent

            if len(self._agents) >= self.MAX_AGENTS:
                raise HeartbeatError(f"Maximum agents limit reached: {self.MAX_AGENTS}")

            now = time.time()
            agent = AgentInfo(
                agent_id=agent_id,
                registered_at=now,
                last_heartbeat=now,
                status=AgentStatus.UNKNOWN,
                metadata=metadata or {},
                heartbeat_history=[],
                total_heartbeats=0,
                consecutive_failures=0,
            )
            self._agents[agent_id] = agent

            await self._notify_subscribers("agent_registered", agent.to_dict())
            await self._save_heartbeat(agent_id, "registered", metadata)

            return agent

    async def heartbeat(
        self,
        agent_id: str,
        status: str | AgentStatus = AgentStatus.ONLINE,
        metadata: dict[str, Any] | None = None,
    ) -> HeartbeatRecord:
        """
        Record a heartbeat from an agent.

        Args:
            agent_id: Agent identifier
            status: Current agent status
            metadata: Additional heartbeat metadata

        Returns:
            The recorded heartbeat

        Raises:
            AgentNotFoundError: If agent is not registered
        """
        if isinstance(status, AgentStatus):
            status_str = status.value
            status_enum = status
        else:
            status_str = status
            status_enum = AgentStatus(status) if status in AgentStatus._value2member_map_ else AgentStatus.UNKNOWN

        async with self._lock:
            if agent_id not in self._agents:
                raise AgentNotFoundError(f"Agent not found: {agent_id}")

            agent = self._agents[agent_id]
            now = time.time()

            record = HeartbeatRecord(
                agent_id=agent_id,
                timestamp=now,
                status=status_str,
                metadata=metadata or {},
            )

            agent.last_heartbeat = now
            agent.status = status_enum
            agent.total_heartbeats += 1
            agent.consecutive_failures = 0

            if metadata:
                agent.metadata.update(metadata)

            # Add to history with size limit
            agent.heartbeat_history.append(record)
            if len(agent.heartbeat_history) > self.MAX_HISTORY_SIZE:
                agent.heartbeat_history = agent.heartbeat_history[-self.MAX_HISTORY_SIZE:]

            await self._notify_subscribers("heartbeat", record.to_dict())

            if self._auto_save:
                await self._save_heartbeat(agent_id, status_str, metadata)

            return record

    def get_active_agents(
        self,
        status_filter: set[AgentStatus] | None = None,
        include_stale: bool = False,
    ) -> list[AgentInfo]:
        """
        List agents with recent heartbeats.

        Args:
            status_filter: Filter by agent status
            include_stale: Include stale agents (no recent heartbeat)

        Returns:
            List of active agent information
        """
        now = time.time()
        agents = []

        for agent in self._agents.values():
            # Check staleness
            if not include_stale and agent.is_stale(self._stale_threshold):
                continue

            # Check status filter
            if status_filter and agent.status not in status_filter:
                continue

            agents.append(agent)

        # Sort by last heartbeat (most recent first)
        agents.sort(key=lambda a: a.last_heartbeat, reverse=True)
        return agents

    def get_agent_status(self, agent_id: str) -> AgentInfo:
        """
        Get detailed status for one agent.

        Args:
            agent_id: Agent identifier

        Returns:
            Agent information

        Raises:
            AgentNotFoundError: If agent is not found
        """
        if agent_id not in self._agents:
            raise AgentNotFoundError(f"Agent not found: {agent_id}")
        return self._agents[agent_id]

    async def prune_stale(self, stale_seconds: float | None = None) -> list[str]:
        """
        Remove agents with no heartbeat for stale_seconds.

        Args:
            stale_seconds: Threshold for staleness (default: uses instance threshold)

        Returns:
            List of pruned agent IDs
        """
        threshold = stale_seconds or self._stale_threshold
        pruned = []

        async with self._lock:
            now = time.time()
            to_remove = [
                agent_id
                for agent_id, agent in self._agents.items()
                if (now - agent.last_heartbeat) > threshold
            ]

            for agent_id in to_remove:
                del self._agents[agent_id]
                pruned.append(agent_id)
                await self._notify_subscribers("agent_pruned", {"agent_id": agent_id})

            if pruned:
                await self._save_to_disk()

        return pruned

    def get_heartbeat_history(
        self,
        agent_id: str,
        since: float | None = None,
        limit: int = 100,
    ) -> list[HeartbeatRecord]:
        """
        Get heartbeat history for an agent.

        Args:
            agent_id: Agent identifier
            since: Unix timestamp to get heartbeats after
            limit: Maximum number of records to return

        Returns:
            List of heartbeat records
        """
        if agent_id not in self._agents:
            raise AgentNotFoundError(f"Agent not found: {agent_id}")

        agent = self._agents[agent_id]
        history = agent.heartbeat_history

        if since:
            history = [h for h in history if h.timestamp >= since]

        return history[-limit:]

    async def _background_cleanup(self) -> None:
        """Background task for periodic cleanup."""
        while self._running:
            try:
                await asyncio.sleep(60)  # Check every minute
                await self.prune_stale()
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue
                print(f"Heartbeat cleanup error: {e}")

    async def _load_from_disk(self) -> None:
        """Load state from disk."""
        if not self._storage_path:
            return

        if not self._storage_path.exists():
            return

        try:
            # Load from rotated backup if it exists
            backup_path = self._storage_path.with_suffix(".jsonl.bak")
            load_paths = [backup_path, self._storage_path]

            for path in load_paths:
                if path.exists():
                    async with aiofiles.open(path, "r") as f:
                        async for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                data = json.loads(line)
                                if data.get("type") == "load_snapshot":
                                    for agent_data in data.get("agents", []):
                                        agent = AgentInfo(
                                            agent_id=agent_data["agent_id"],
                                            registered_at=agent_data["registered_at"],
                                            last_heartbeat=agent_data["last_heartbeat"],
                                            status=AgentStatus(agent_data.get("status", "unknown")),
                                            metadata=agent_data.get("metadata", {}),
                                            heartbeat_history=[
                                                HeartbeatRecord.from_dict(h)
                                                for h in agent_data.get("heartbeat_history", [])
                                            ],
                                            total_heartbeats=agent_data.get("total_heartbeats", 0),
                                            consecutive_failures=agent_data.get("consecutive_failures", 0),
                                        )
                                        self._agents[agent.agent_id] = agent
                                    break
                            except (json.JSONDecodeError, KeyError) as e:
                                print(f"Error loading heartbeat data: {e}")
                                continue
        except Exception as e:
            print(f"Error loading heartbeats: {e}")

    async def _save_to_disk(self) -> None:
        """Save state to disk."""
        if not self._storage_path:
            return

        self._storage_path.parent.mkdir(parents=True, exist_ok=True)

        # Rotate backup
        if self._storage_path.exists():
            backup_path = self._storage_path.with_suffix(".jsonl.bak")
            if backup_path.exists():
                backup_path.unlink()
            self._storage_path.rename(backup_path)

        # Write snapshot
        snapshot = {
            "type": "load_snapshot",
            "timestamp": time.time(),
            "agents": [agent.to_dict() for agent in self._agents.values()],
        }

        async with aiofiles.open(self._storage_path, "w") as f:
            await f.write(json.dumps(snapshot) + "\n")

    async def _save_heartbeat(
        self,
        agent_id: str,
        status: str,
        metadata: dict[str, Any] | None,
    ) -> None:
        """Save a single heartbeat record."""
        if not self._storage_path:
            return

        record = {
            "type": "heartbeat",
            "agent_id": agent_id,
            "timestamp": time.time(),
            "status": status,
            "metadata": metadata or {},
        }

        self._storage_path.parent.mkdir(parents=True, exist_ok=True)

        async with aiofiles.open(self._storage_path, "a") as f:
            await f.write(json.dumps(record) + "\n")

    async def subscribe(self) -> AsyncIterator[dict[str, Any]]:
        """Subscribe to heartbeat events."""
        queue: asyncio.Queue = asyncio.Queue()
        self._subscriber_queues.append(queue)

        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            self._subscriber_queues.remove(queue)

    async def _notify_subscribers(self, event_type: str, data: dict[str, Any]) -> None:
        """Notify all subscribers of an event."""
        event = {"type": event_type, "data": data, "timestamp": time.time()}
        for queue in self._subscriber_queues:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass  # Skip if queue is full

    def mark_failure(self, agent_id: str) -> None:
        """Mark a failed heartbeat attempt for an agent."""
        if agent_id in self._agents:
            self._agents[agent_id].consecutive_failures += 1

    def get_statistics(self) -> dict[str, Any]:
        """Get overall statistics about tracked agents."""
        status_counts: dict[AgentStatus, int] = {}
        for agent in self._agents.values():
            status_counts[agent.status] = status_counts.get(agent.status, 0) + 1

        stale_count = sum(
            1 for agent in self._agents.values()
            if agent.is_stale(self._stale_threshold)
        )

        return {
            "total_agents": len(self._agents),
            "active_agents": len(self._agents) - stale_count,
            "stale_agents": stale_count,
            "status_distribution": {
                status.value: count
                for status, count in status_counts.items()
            },
        }


# Context manager for easy usage
class HeartbeatManagerContext:
    """Context manager for HeartbeatManager."""

    def __init__(self, manager: HeartbeatManager):
        self.manager = manager

    async def __aenter__(self) -> HeartbeatManager:
        await self.manager.start()
        return self.manager

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.manager.stop()