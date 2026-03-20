"""
Resource Quotas for Picoclaw Governance Module.

This module provides resource quota management for agents,
limiting resource consumption and tracking usage.
"""

from __future__ import annotations

import json
import time
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from collections import defaultdict
from threading import RLock


class ResourceType(str, Enum):
    """Types of quota-limited resources."""
    API_CALLS = "api_calls"
    FILE_OPERATIONS = "file_operations"
    FILE_READS = "file_reads"
    FILE_WRITES = "file_writes"
    NETWORK_BYTES = "network_bytes"
    NETWORK_REQUESTS = "network_requests"
    COMPUTE_SECONDS = "compute_seconds"
    MEMORY_MB_SECONDS = "memory_mb_seconds"
    STORAGE_BYTES = "storage_bytes"
    TOKEN_COUNT = "token_count"
    MESSAGE_COUNT = "message_count"
    BROWSER_AUTOMATION = "browser_automation"
    SHELL_COMMANDS = "shell_commands"
    PROCESS_COUNT = "process_count"


class QuotaPeriod(str, Enum):
    """Quota reset periods."""
    PER_SECOND = "second"
    PER_MINUTE = "minute"
    PER_HOUR = "hour"
    PER_DAY = "day"
    PER_WEEK = "week"
    PER_MONTH = "month"
    TOTAL = "total"  # Never resets


@dataclass
class QuotaLimit:
    """
    Defines a quota limit for a resource.
    
    Specifies the maximum amount and reset period for a resource type.
    """
    resource: ResourceType
    limit: int
    period: QuotaPeriod = QuotaPeriod.PER_DAY
    burst_limit: Optional[int] = None  # Allow bursting above limit temporarily
    burst_window_seconds: int = 60  # Window for burst calculation
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def get_reset_time(self, from_time: Optional[datetime] = None) -> datetime:
        """Calculate when quota resets from a given time."""
        base = from_time or datetime.utcnow()
        
        if self.period == QuotaPeriod.PER_SECOND:
            return base + timedelta(seconds=1)
        elif self.period == QuotaPeriod.PER_MINUTE:
            return base + timedelta(minutes=1)
        elif self.period == QuotaPeriod.PER_HOUR:
            return base + timedelta(hours=1)
        elif self.period == QuotaPeriod.PER_DAY:
            return base + timedelta(days=1)
        elif self.period == QuotaPeriod.PER_WEEK:
            return base + timedelta(weeks=1)
        elif self.period == QuotaPeriod.PER_MONTH:
            # Approximate month as 30 days
            return base + timedelta(days=30)
        else:
            # Total - never resets
            return datetime.max.replace(tzinfo=None)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize limit to dictionary."""
        return {
            "resource": self.resource.value,
            "limit": self.limit,
            "period": self.period.value,
            "burst_limit": self.burst_limit,
            "burst_window_seconds": self.burst_window_seconds,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "QuotaLimit":
        """Deserialize limit from dictionary."""
        return cls(
            resource=ResourceType(data["resource"]),
            limit=data["limit"],
            period=QuotaPeriod(data.get("period", "day")),
            burst_limit=data.get("burst_limit"),
            burst_window_seconds=data.get("burst_window_seconds", 60),
            metadata=data.get("metadata", {}),
        )


@dataclass
class QuotaUsage:
    """
    Tracks current quota usage.
    
    Maintains counts and timestamps for quota enforcement.
    """
    resource: ResourceType
    used: int = 0
    last_updated: datetime = field(default_factory=datetime.utcnow)
    period_start: datetime = field(default_factory=datetime.utcnow)
    burst_used: int = 0
    burst_window_start: Optional[datetime] = None
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize usage to dictionary."""
        return {
            "resource": self.resource.value,
            "used": self.used,
            "last_updated": self.last_updated.isoformat(),
            "period_start": self.period_start.isoformat(),
            "burst_used": self.burst_used,
            "burst_window_start": self.burst_window_start.isoformat() if self.burst_window_start else None,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "QuotaUsage":
        """Deserialize usage from dictionary."""
        return cls(
            resource=ResourceType(data["resource"]),
            used=data.get("used", 0),
            last_updated=datetime.fromisoformat(data["last_updated"]),
            period_start=datetime.fromisoformat(data["period_start"]),
            burst_used=data.get("burst_used", 0),
            burst_window_start=datetime.fromisoformat(data["burst_window_start"]) if data.get("burst_window_start") else None,
        )


@dataclass
class QuotaStatus:
    """Status report for a quota."""
    resource: ResourceType
    limit: int
    used: int
    remaining: int
    percentage_used: float
    resets_at: datetime
    is_over_limit: bool
    burst_available: Optional[int] = None
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize status to dictionary."""
        return {
            "resource": self.resource.value,
            "limit": self.limit,
            "used": self.used,
            "remaining": self.remaining,
            "percentage_used": self.percentage_used,
            "resets_at": self.resets_at.isoformat(),
            "is_over_limit": self.is_over_limit,
            "burst_available": self.burst_available,
        }


class QuotaManager:
    """
    Manages resource quotas for agents.
    
    Provides quota setting, checking, and usage tracking capabilities.
    """
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize the quota manager.
        
        Args:
            storage_path: Path to store quota data
        """
        self.storage_path = storage_path or Path.home() / ".picoclaw" / "governance" / "quotas"
        self._limits: dict[str, dict[ResourceType, QuotaLimit]] = defaultdict(dict)  # agent_id -> resource -> limit
        self._usage: dict[str, dict[ResourceType, QuotaUsage]] = defaultdict(dict)  # agent_id -> resource -> usage
        self._global_limits: dict[ResourceType, QuotaLimit] = {}  # Default limits for all agents
        self._lock = RLock()
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the quota manager and load existing data."""
        with self._lock:
            if self._initialized:
                return
            
            self.storage_path.mkdir(parents=True, exist_ok=True)
            await self._load_data()
            
            # Set default global limits
            self._set_default_limits()
            
            self._initialized = True
    
    def _set_default_limits(self) -> None:
        """Set default global resource limits."""
        default_limits = [
            (ResourceType.API_CALLS, 10000, QuotaPeriod.PER_DAY),
            (ResourceType.FILE_OPERATIONS, 5000, QuotaPeriod.PER_DAY),
            (ResourceType.NETWORK_BYTES, 10_000_000_000, QuotaPeriod.PER_DAY),  # 10GB
            (ResourceType.NETWORK_REQUESTS, 5000, QuotaPeriod.PER_DAY),
            (ResourceType.COMPUTE_SECONDS, 3600, QuotaPeriod.PER_DAY),  # 1 hour
            (ResourceType.TOKEN_COUNT, 1_000_000, QuotaPeriod.PER_DAY),
            (ResourceType.MESSAGE_COUNT, 10000, QuotaPeriod.PER_DAY),
            (ResourceType.SHELL_COMMANDS, 500, QuotaPeriod.PER_DAY),
            (ResourceType.PROCESS_COUNT, 100, QuotaPeriod.PER_DAY),
        ]
        
        for resource, limit, period in default_limits:
            self._global_limits[resource] = QuotaLimit(
                resource=resource,
                limit=limit,
                period=period,
            )
    
    async def _load_data(self) -> None:
        """Load quota limits and usage from storage."""
        limits_file = self.storage_path / "limits.jsonl"
        if limits_file.exists():
            loop = asyncio.get_event_loop()
            content = await loop.run_in_executor(None, limits_file.read_text)
            for line in content.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    agent_id = data["agent_id"]
                    limit = QuotaLimit.from_dict(data["limit"])
                    self._limits[agent_id][limit.resource] = limit
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    print(f"Warning: Failed to load quota limit: {e}")
        
        usage_file = self.storage_path / "usage.jsonl"
        if usage_file.exists():
            loop = asyncio.get_event_loop()
            content = await loop.run_in_executor(None, usage_file.read_text)
            for line in content.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    agent_id = data["agent_id"]
                    usage = QuotaUsage.from_dict(data["usage"])
                    self._usage[agent_id][usage.resource] = usage
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    print(f"Warning: Failed to load quota usage: {e}")
    
    async def _save_limits(self) -> None:
        """Save quota limits to storage."""
        limits_file = self.storage_path / "limits.jsonl"
        
        lines = []
        for agent_id, limits in self._limits.items():
            for resource, limit in limits.items():
                lines.append(json.dumps({
                    "agent_id": agent_id,
                    "limit": limit.to_dict(),
                }))
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            limits_file.write_text,
            "\n".join(lines) + "\n"
        )
    
    async def _save_usage(self) -> None:
        """Save quota usage to storage."""
        usage_file = self.storage_path / "usage.jsonl"
        
        lines = []
        for agent_id, usages in self._usage.items():
            for resource, usage in usages.items():
                lines.append(json.dumps({
                    "agent_id": agent_id,
                    "usage": usage.to_dict(),
                }))
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            usage_file.write_text,
            "\n".join(lines) + "\n"
        )
    
    def set_quota(
        self,
        agent_id: str,
        resource: ResourceType,
        limit: int,
        period: QuotaPeriod = QuotaPeriod.PER_DAY,
        burst_limit: Optional[int] = None,
    ) -> QuotaLimit:
        """
        Set quota for a resource.
        
        Args:
            agent_id: Agent to set quota for
            resource: Resource type
            limit: Maximum allowed
            period: Reset period
            burst_limit: Optional burst limit
        
        Returns:
            The created quota limit
        """
        with self._lock:
            quota_limit = QuotaLimit(
                resource=resource,
                limit=limit,
                period=period,
                burst_limit=burst_limit,
            )
            self._limits[agent_id][resource] = quota_limit
            return quota_limit
    
    async def set_quota_async(
        self,
        agent_id: str,
        resource: ResourceType,
        limit: int,
        period: QuotaPeriod = QuotaPeriod.PER_DAY,
        burst_limit: Optional[int] = None,
    ) -> QuotaLimit:
        """Set quota and persist."""
        result = self.set_quota(agent_id, resource, limit, period, burst_limit)
        await self._save_limits()
        return result
    
    def set_global_quota(
        self,
        resource: ResourceType,
        limit: int,
        period: QuotaPeriod = QuotaPeriod.PER_DAY,
    ) -> QuotaLimit:
        """Set default quota for all agents."""
        with self._lock:
            quota_limit = QuotaLimit(
                resource=resource,
                limit=limit,
                period=period,
            )
            self._global_limits[resource] = quota_limit
            return quota_limit
    
    def get_quota(
        self,
        agent_id: str,
        resource: ResourceType,
    ) -> Optional[QuotaLimit]:
        """Get quota limit for a resource."""
        with self._lock:
            # Check agent-specific limit first
            if agent_id in self._limits and resource in self._limits[agent_id]:
                return self._limits[agent_id][resource]
            
            # Fall back to global limit
            return self._global_limits.get(resource)
    
    def remove_quota(self, agent_id: str, resource: ResourceType) -> bool:
        """
        Remove quota for a resource.
        
        Falls back to global limit after removal.
        
        Returns:
            True if removed, False if not found
        """
        with self._lock:
            if agent_id in self._limits and resource in self._limits[agent_id]:
                del self._limits[agent_id][resource]
                return True
            return False
    
    def check_quota(
        self,
        agent_id: str,
        resource: ResourceType,
        amount: int = 1,
    ) -> bool:
        """
        Check if within quota for operation.
        
        Args:
            agent_id: Agent to check
            resource: Resource type
            amount: Amount to check
        
        Returns:
            True if within quota, False if would exceed
        """
        with self._lock:
            # Get the limit
            limit = self.get_quota(agent_id, resource)
            if limit is None:
                return True  # No limit = unlimited
            
            # Get current usage
            usage = self._usage.get(agent_id, {}).get(resource)
            if usage is None:
                return True
            
            # Check if period has reset
            now = datetime.utcnow()
            reset_time = limit.get_reset_time(usage.period_start)
            
            if now >= reset_time:
                return True  # Period reset, usage is 0
            
            # Check against limit
            if usage.used + amount > limit.limit:
                # Check burst limit if available
                if limit.burst_limit:
                    burst_remaining = limit.burst_limit - usage.burst_used
                    if burst_remaining >= amount:
                        return True
                return False
            
            return True
    
    def check_burst(
        self,
        agent_id: str,
        resource: ResourceType,
        amount: int = 1,
    ) -> bool:
        """Check if burst capacity is available."""
        with self._lock:
            limit = self.get_quota(agent_id, resource)
            if limit is None or limit.burst_limit is None:
                return False
            
            usage = self._usage.get(agent_id, {}).get(resource)
            if usage is None:
                return True
            
            # Check burst window
            now = datetime.utcnow()
            if usage.burst_window_start is None:
                return True
            
            window_end = usage.burst_window_start + timedelta(seconds=limit.burst_window_seconds)
            if now >= window_end:
                return True  # Window reset
            
            return usage.burst_used + amount <= limit.burst_limit
    
    def record_usage(
        self,
        agent_id: str,
        resource: ResourceType,
        amount: int = 1,
        is_burst: bool = False,
    ) -> QuotaUsage:
        """
        Record resource usage.
        
        Args:
            agent_id: Agent using resource
            resource: Resource type
            amount: Amount used
            is_burst: Whether this is burst usage
        
        Returns:
            Updated usage record
        """
        with self._lock:
            limit = self.get_quota(agent_id, resource)
            now = datetime.utcnow()
            
            # Get or create usage record
            if agent_id not in self._usage:
                self._usage[agent_id] = {}
            
            usage = self._usage[agent_id].get(resource)
            if usage is None:
                usage = QuotaUsage(resource=resource)
                self._usage[agent_id][resource] = usage
            
            # Check for period reset
            if limit:
                reset_time = limit.get_reset_time(usage.period_start)
                if now >= reset_time:
                    usage.used = 0
                    usage.period_start = now
            
            # Update usage
            usage.used += amount
            usage.last_updated = now
            
            # Track burst usage
            if is_burst and limit and limit.burst_limit:
                if usage.burst_window_start is None:
                    usage.burst_window_start = now
                    usage.burst_used = 0
                
                window_end = usage.burst_window_start + timedelta(seconds=limit.burst_window_seconds)
                if now >= window_end:
                    # Window reset
                    usage.burst_window_start = now
                    usage.burst_used = 0
                
                usage.burst_used += amount
            
            return usage
    
    async def record_usage_async(
        self,
        agent_id: str,
        resource: ResourceType,
        amount: int = 1,
        is_burst: bool = False,
    ) -> QuotaUsage:
        """Record usage and persist."""
        result = self.record_usage(agent_id, resource, amount, is_burst)
        await self._save_usage()
        return result
    
    def get_usage(
        self,
        agent_id: str,
        resource: ResourceType,
    ) -> QuotaUsage:
        """
        Get current usage for a resource.
        
        Returns usage (0 if not tracked).
        """
        with self._lock:
            if agent_id in self._usage and resource in self._usage[agent_id]:
                return self._usage[agent_id][resource]
            
            return QuotaUsage(resource=resource)
    
    def get_quota_status(
        self,
        agent_id: str,
        resource: Optional[ResourceType] = None,
    ) -> dict[ResourceType, QuotaStatus]:
        """
        Get quota status for an agent.
        
        Args:
            agent_id: Agent to check
            resource: Specific resource (None for all)
        
        Returns:
            Dictionary of resource -> status
        """
        with self._lock:
            statuses = {}
            
            # Determine which resources to check
            resources_to_check = [resource] if resource else list(ResourceType)
            
            for res in resources_to_check:
                limit = self.get_quota(agent_id, res)
                if limit is None:
                    continue
                
                usage = self.get_usage(agent_id, res)
                now = datetime.utcnow()
                
                # Check for reset
                reset_time = limit.get_reset_time(usage.period_start)
                if now >= reset_time:
                    effective_used = 0
                else:
                    effective_used = usage.used
                
                remaining = max(0, limit.limit - effective_used)
                percentage = (effective_used / limit.limit * 100) if limit.limit > 0 else 100
                
                burst_available = None
                if limit.burst_limit:
                    if usage.burst_window_start:
                        window_end = usage.burst_window_start + timedelta(seconds=limit.burst_window_seconds)
                        if now < window_end:
                            burst_available = max(0, limit.burst_limit - usage.burst_used)
                        else:
                            burst_available = limit.burst_limit
                    else:
                        burst_available = limit.burst_limit
                
                statuses[res] = QuotaStatus(
                    resource=res,
                    limit=limit.limit,
                    used=effective_used,
                    remaining=remaining,
                    percentage_used=round(percentage, 2),
                    resets_at=reset_time,
                    is_over_limit=effective_used > limit.limit,
                    burst_available=burst_available,
                )
            
            return statuses
    
    def get_all_quotas(self, agent_id: str) -> list[QuotaLimit]:
        """Get all quotas for an agent."""
        with self._lock:
            quotas = []
            
            # Agent-specific quotas
            if agent_id in self._limits:
                quotas.extend(self._limits[agent_id].values())
            
            # Global quotas not overridden
            for resource, limit in self._global_limits.items():
                if agent_id not in self._limits or resource not in self._limits[agent_id]:
                    quotas.append(limit)
            
            return quotas
    
    def reset_usage(
        self,
        agent_id: str,
        resource: Optional[ResourceType] = None,
    ) -> None:
        """Reset usage for an agent (all or specific resource)."""
        with self._lock:
            if resource:
                if agent_id in self._usage and resource in self._usage[agent_id]:
                    self._usage[agent_id][resource] = QuotaUsage(resource=resource)
            else:
                if agent_id in self._usage:
                    self._usage[agent_id] = {}
    
    async def reset_usage_async(
        self,
        agent_id: str,
        resource: Optional[ResourceType] = None,
    ) -> None:
        """Reset usage and persist."""
        self.reset_usage(agent_id, resource)
        await self._save_usage()
    
    def increment_usage(
        self,
        agent_id: str,
        resource: ResourceType,
        amount: int = 1,
    ) -> QuotaUsage:
        """Increment usage (alias for record_usage)."""
        return self.record_usage(agent_id, resource, amount)
    
    async def check_and_record(
        self,
        agent_id: str,
        resource: ResourceType,
        amount: int = 1,
    ) -> tuple[bool, QuotaStatus]:
        """
        Check quota and record usage if allowed.
        
        Returns:
            Tuple of (allowed, status)
        """
        with self._lock:
            can_proceed = self.check_quota(agent_id, resource, amount)
            
            if can_proceed:
                self.record_usage(agent_id, resource, amount)
            
            statuses = self.get_quota_status(agent_id, resource)
            status = statuses.get(resource, QuotaStatus(
                resource=resource,
                limit=0,
                used=amount if can_proceed else 0,
                remaining=0,
                percentage_used=100.0,
                resets_at=datetime.max,
                is_over_limit=not can_proceed,
            ))
            
        return can_proceed, status
    
    def get_summary(self, agent_id: str) -> dict[str, Any]:
        """Get quota summary for an agent."""
        statuses = self.get_quota_status(agent_id)
        
        summary = {
            "agent_id": agent_id,
            "quotas": {},
            "warnings": [],
            "critical": [],
        }
        
        for resource, status in statuses.items():
            summary["quotas"][resource.value] = status.to_dict()
            
            if status.percentage_used >= 90:
                summary["critical"].append(resource.value)
            elif status.percentage_used >= 75:
                summary["warnings"].append(resource.value)
        
        return summary
    
    async def cleanup_old_usage(self, days: int = 30) -> int:
        """Clean up old usage records."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        count = 0
        for agent_id in list(self._usage.keys()):
            for resource in list(self._usage[agent_id].keys()):
                usage = self._usage[agent_id][resource]
                if usage.last_updated < cutoff and usage.used == 0:
                    del self._usage[agent_id][resource]
                    count += 1
        
        if count > 0:
            await self._save_usage()
        
        return count


# Convenience functions

_manager: Optional[QuotaManager] = None


def get_manager() -> QuotaManager:
    """Get or create the default quota manager."""
    global _manager
    if _manager is None:
        _manager = QuotaManager()
    return _manager


def set_quota(agent_id: str, resource: ResourceType, limit: int, **kwargs) -> QuotaLimit:
    """Set quota using default manager."""
    return get_manager().set_quota(agent_id, resource, limit, **kwargs)


def check_quota(agent_id: str, resource: ResourceType, amount: int = 1) -> bool:
    """Check quota using default manager."""
    return get_manager().check_quota(agent_id, resource, amount)


def record_usage(agent_id: str, resource: ResourceType, amount: int = 1) -> QuotaUsage:
    """Record usage using default manager."""
    return get_manager().record_usage(agent_id, resource, amount)


def get_usage(agent_id: str, resource: ResourceType) -> QuotaUsage:
    """Get usage using default manager."""
    return get_manager().get_usage(agent_id, resource)


def get_quota_status(agent_id: str, resource: Optional[ResourceType] = None) -> dict[ResourceType, QuotaStatus]:
    """Get quota status using default manager."""
    return get_manager().get_quota_status(agent_id, resource)


__all__ = [
    "ResourceType",
    "QuotaPeriod",
    "QuotaLimit",
    "QuotaUsage",
    "QuotaStatus",
    "QuotaManager",
    "get_manager",
    "set_quota",
    "check_quota",
    "record_usage",
    "get_usage",
    "get_quota_status",
]