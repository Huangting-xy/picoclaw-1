"""
Audit Logging for Picoclaw Governance Module.

This module provides comprehensive audit logging with async support,
querying capabilities, and compliance export functionality.
"""

from __future__ import annotations

import json
import time
import hashlib
import asyncio
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional, AsyncIterator
from collections import defaultdict
from threading import RLock
import gzip


class AuditOutcome(str, Enum):
    """Outcome of an audited action."""
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    ERROR = "error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class AuditSeverity(str, Enum):
    """Severity level of audit events."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SUSPICIOUS = "suspicious"


@dataclass
class AuditEntry:
    """
    A single audit log entry.
    
    Captures all relevant information about an agent action for
    compliance, security analysis, and debugging.
    """
    entry_id: str
    agent_id: str
    action: str
    resource: str
    outcome: AuditOutcome
    timestamp: datetime
    reason: str = ""
    severity: AuditSeverity = AuditSeverity.INFO
    duration_ms: Optional[int] = None
    context: dict[str, Any] = field(default_factory=dict)
    result_hash: Optional[str] = None
    parent_entry_id: Optional[str] = None  # For nested operations
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    
    def __post_init__(self):
        """Generate entry ID if not provided."""
        if not self.entry_id:
            self.entry_id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique entry ID."""
        data = f"{self.agent_id}:{self.action}:{self.timestamp.isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize entry to dictionary."""
        return {
            "entry_id": self.entry_id,
            "agent_id": self.agent_id,
            "action": self.action,
            "resource": self.resource,
            "outcome": self.outcome.value,
            "timestamp": self.timestamp.isoformat(),
            "reason": self.reason,
            "severity": self.severity.value,
            "duration_ms": self.duration_ms,
            "context": self.context,
            "result_hash": self.result_hash,
            "parent_entry_id": self.parent_entry_id,
            "tags": self.tags,
            "metadata": self.metadata,
            "ip_address": self.ip_address,
            "session_id": self.session_id,
            "request_id": self.request_id,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEntry":
        """Deserialize entry from dictionary."""
        return cls(
            entry_id=data["entry_id"],
            agent_id=data["agent_id"],
            action=data["action"],
            resource=data["resource"],
            outcome=AuditOutcome(data["outcome"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            reason=data.get("reason", ""),
            severity=AuditSeverity(data.get("severity", "info")),
            duration_ms=data.get("duration_ms"),
            context=data.get("context", {}),
            result_hash=data.get("result_hash"),
            parent_entry_id=data.get("parent_entry_id"),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
            ip_address=data.get("ip_address"),
            session_id=data.get("session_id"),
            request_id=data.get("request_id"),
        )
    
    def is_suspicious(self) -> bool:
        """Check if entry should be flagged as suspicious."""
        if self.severity == AuditSeverity.SUSPICIOUS:
            return True
        if self.outcome == AuditOutcome.DENIED:
            return True
        if "unauthorized" in self.reason.lower():
            return True
        if self.action.startswith("admin:") or self.action.startswith("system:"):
            return True
        return False


class AuditLogWriter:
    """Handles writing audit entries to storage."""
    
    def __init__(self, file_path: Path, max_size_mb: int = 100):
        self.file_path = file_path
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._current_file: Optional[Any] = None
        self._current_size = 0
        self._lock = asyncio.Lock()
        self._rotation_index = 0
    
    async def write(self, entry: AuditEntry) -> None:
        """Write an entry to the log file."""
        async with self._lock:
            line = json.dumps(entry.to_dict()) + "\n"
            line_bytes = line.encode("utf-8")
            
            # Check for rotation
            if self._current_size + len(line_bytes) > self.max_size_bytes:
                await self._rotate()
            
            # Write to file
            if self._current_file is None:
                self._current_file = await asyncio.get_event_loop().run_in_executor(
                    None, open, self.file_path, "a"
                )
            
            await asyncio.get_event_loop().run_in_executor(
                None, self._current_file.write, line
            )
            self._current_file.flush()
            self._current_size += len(line_bytes)
    
    async def _rotate(self) -> None:
        """Rotate the log file."""
        if self._current_file:
            await asyncio.get_event_loop().run_in_executor(
                None, self._current_file.close
            )
            self._current_file = None
        
        # Compress old file
        if self.file_path.exists():
            self._rotation_index += 1
            compressed_path = self.file_path.with_suffix(f".{self._rotation_index}.jsonl.gz")
            await self._compress_file(self.file_path, compressed_path)
        
        self._current_size = 0
    
    async def _compress_file(self, source: Path, dest: Path) -> None:
        """Compress a file."""
        def _compress():
            with open(source, "rb") as f_in:
                with gzip.open(dest, "wb") as f_out:
                    f_out.writelines(f_in)
            source.unlink()
        
        await asyncio.get_event_loop().run_in_executor(None, _compress)
    
    async def close(self) -> None:
        """Close the writer."""
        if self._current_file:
            await asyncio.get_event_loop().run_in_executor(
                None, self._current_file.close
            )
            self._current_file = None


class AuditLog:
    """
    Async audit logging system.
    
    Provides comprehensive logging with persistence, querying,
    and compliance export capabilities.
    """
    
    def __init__(
        self,
        storage_path: Optional[Path] = None,
        retention_days: int = 90,
        auto_flush: bool = True,
    ):
        """
        Initialize the audit log.
        
        Args:
            storage_path: Path to store audit logs
            retention_days: Number of days to retain logs
            auto_flush: Whether to automatically flush writes
        """
        self.storage_path = storage_path or Path.home() / ".picoclaw" / "governance" / "audit"
        self.retention_days = retention_days
        self.auto_flush = auto_flush
        
        self._entries: list[AuditEntry] = []
        self._writer: Optional[AuditLogWriter] = None
        self._entry_index: dict[str, AuditEntry] = {}
        self._agent_index: dict[str, list[str]] = defaultdict(list)
        self._action_index: dict[str, list[str]] = defaultdict(list)
        self._suspicious_index: set[str] = set()
        self._lock = RLock()
        self._async_lock = asyncio.Lock()
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the audit log and load existing entries."""
        async with self._async_lock:
            if self._initialized:
                return
            
            self.storage_path.mkdir(parents=True, exist_ok=True)
            
            log_file = self.storage_path / "audit.jsonl"
            if log_file.exists():
                self._writer = AuditLogWriter(log_file)
                await self._load_entries()
            
            self._initialized = True
    
    async def _load_entries(self) -> None:
        """Load existing entries into memory indices."""
        log_file = self.storage_path / "audit.jsonl"
        if not log_file.exists():
            return
        
        loop = asyncio.get_event_loop()
        content = await loop.run_in_executor(None, log_file.read_text)
        
        # Load only last 24 hours into memory for fast queries
        cutoff = datetime.utcnow() - timedelta(hours=24)
        
        for line in content.strip().split("\n")[-10000:]:  # Limit to last 10k entries
            if not line:
                continue
            try:
                data = json.loads(line)
                entry = AuditEntry.from_dict(data)
                if entry.timestamp > cutoff:
                    self._index_entry(entry)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"Warning: Failed to load audit entry: {e}")
    
    def _index_entry(self, entry: AuditEntry) -> None:
        """Index an entry for fast queries."""
        self._entries.append(entry)
        self._entry_index[entry.entry_id] = entry
        self._agent_index[entry.agent_id].append(entry.entry_id)
        self._action_index[entry.action].append(entry.entry_id)
        
        if entry.is_suspicious():
            self._suspicious_index.add(entry.entry_id)
        
        # Trim indices to prevent memory bloat
        if len(self._entries) > 10000:
            self._trim_indices()
    
    def _trim_indices(self) -> None:
        """Trim in-memory entries to prevent memory bloat."""
        cutoff = datetime.utcnow() - timedelta(hours=24)
        
        # Remove old entries
        while self._entries and self._entries[0].timestamp < cutoff:
            old_entry = self._entries.pop(0)
            self._entry_index.pop(old_entry.entry_id, None)
            self._agent_index[old_entry.agent_id] = [
                e for e in self._agent_index[old_entry.agent_id]
                if e != old_entry.entry_id
            ]
            self._action_index[old_entry.action] = [
                e for e in self._action_index[old_entry.action]
                if e != old_entry.entry_id
            ]
            self._suspicious_index.discard(old_entry.entry_id)
    
    async def log_action(
        self,
        agent_id: str,
        action: str,
        resource: str,
        outcome: AuditOutcome,
        reason: str = "",
        severity: AuditSeverity = AuditSeverity.INFO,
        duration_ms: Optional[int] = None,
        context: Optional[dict[str, Any]] = None,
        result_hash: Optional[str] = None,
        parent_entry_id: Optional[str] = None,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> AuditEntry:
        """
        Log an agent action.
        
        Args:
            agent_id: Agent performing the action
            action: Action being performed
            resource: Resource being accessed
            outcome: Outcome of the action
            reason: Reason for outcome (especially for denials)
            severity: Severity level
            duration_ms: Duration in milliseconds
            context: Additional context
            result_hash: Hash of result (for verification)
            parent_entry_id: ID of parent entry (for nested operations)
            tags: Tags for categorization
            metadata: Additional metadata
            ip_address: Client IP address
            session_id: Session identifier
            request_id: Request identifier
        
        Returns:
            The created audit entry
        """
        entry = AuditEntry(
            entry_id="",
            agent_id=agent_id,
            action=action,
            resource=resource,
            outcome=outcome,
            timestamp=datetime.utcnow(),
            reason=reason,
            severity=severity,
            duration_ms=duration_ms,
            context=context or {},
            result_hash=result_hash,
            parent_entry_id=parent_entry_id,
            tags=tags or [],
            metadata=metadata or {},
            ip_address=ip_address,
            session_id=session_id,
            request_id=request_id,
        )
        
        async with self._async_lock:
            self._index_entry(entry)
            
            if self._writer:
                await self._writer.write(entry)
        
        return entry
    
    async def log_success(
        self,
        agent_id: str,
        action: str,
        resource: str,
        context: Optional[dict[str, Any]] = None,
        duration_ms: Optional[int] = None,
        **kwargs,
    ) -> AuditEntry:
        """Log a successful action."""
        return await self.log_action(
            agent_id=agent_id,
            action=action,
            resource=resource,
            outcome=AuditOutcome.SUCCESS,
            context=context,
            duration_ms=duration_ms,
            **kwargs,
        )
    
    async def log_failure(
        self,
        agent_id: str,
        action: str,
        resource: str,
        reason: str,
        context: Optional[dict[str, Any]] = None,
        duration_ms: Optional[int] = None,
        **kwargs,
    ) -> AuditEntry:
        """Log a failed action."""
        return await self.log_action(
            agent_id=agent_id,
            action=action,
            resource=resource,
            outcome=AuditOutcome.FAILURE,
            reason=reason,
            severity=AuditSeverity.WARNING,
            context=context,
            duration_ms=duration_ms,
            **kwargs,
        )
    
    async def log_denied(
        self,
        agent_id: str,
        action: str,
        resource: str,
        reason: str,
        context: Optional[dict[str, Any]] = None,
        **kwargs,
    ) -> AuditEntry:
        """Log a denied action."""
        return await self.log_action(
            agent_id=agent_id,
            action=action,
            resource=resource,
            outcome=AuditOutcome.DENIED,
            reason=reason,
            severity=AuditSeverity.SUSPICIOUS,
            context=context,
            **kwargs,
        )
    
    async def query_by_agent(
        self,
        agent_id: str,
        hours: int = 24,
        outcome: Optional[AuditOutcome] = None,
        severity: Optional[AuditSeverity] = None,
    ) -> list[AuditEntry]:
        """
        Query actions by agent.
        
        Args:
            agent_id: Agent ID to query
            hours: Hours to look back
            outcome: Filter by outcome
            severity: Filter by severity
        
        Returns:
            List of matching entries
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        entries = []
        for entry_id in self._agent_index.get(agent_id, []):
            entry = self._entry_index.get(entry_id)
            if entry and entry.timestamp > cutoff:
                if outcome and entry.outcome != outcome:
                    continue
                if severity and entry.severity != severity:
                    continue
                entries.append(entry)
        
        return sorted(entries, key=lambda e: e.timestamp, reverse=True)
    
    async def query_by_action(
        self,
        action: str,
        hours: int = 24,
        outcome: Optional[AuditOutcome] = None,
    ) -> list[AuditEntry]:
        """
        Query specific actions.
        
        Args:
            action: Action type to query
            hours: Hours to look back
            outcome: Filter by outcome
        
        Returns:
            List of matching entries
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        entries = []
        # Support wildcard matching
        for act, entry_ids in self._action_index.items():
            if action == "*" or action == act or act.startswith(action):
                for entry_id in entry_ids:
                    entry = self._entry_index.get(entry_id)
                    if entry and entry.timestamp > cutoff:
                        if outcome and entry.outcome != outcome:
                            continue
                        entries.append(entry)
        
        return sorted(entries, key=lambda e: e.timestamp, reverse=True)
    
    async def query_by_resource(
        self,
        resource_pattern: str,
        hours: int = 24,
    ) -> list[AuditEntry]:
        """Query by resource pattern."""
        import fnmatch
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        entries = []
        for entry in self._entries:
            if entry.timestamp > cutoff:
                if fnmatch.fnmatch(entry.resource, resource_pattern):
                    entries.append(entry)
        
        return sorted(entries, key=lambda e: e.timestamp, reverse=True)
    
    async def query_suspicious(self, hours: int = 24) -> list[AuditEntry]:
        """
        Query flagged/suspicious actions.
        
        Args:
            hours: Hours to look back
        
        Returns:
            List of suspicious entries
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        entries = []
        for entry_id in self._suspicious_index:
            entry = self._entry_index.get(entry_id)
            if entry and entry.timestamp > cutoff:
                entries.append(entry)
        
        return sorted(entries, key=lambda e: e.timestamp, reverse=True)
    
    async def query_by_time_range(
        self,
        start: datetime,
        end: datetime,
    ) -> list[AuditEntry]:
        """Query by time range."""
        entries = [
            e for e in self._entries
            if start <= e.timestamp <= end
        ]
        return sorted(entries, key=lambda e: e.timestamp, reverse=True)
    
    async def get_entry(self, entry_id: str) -> Optional[AuditEntry]:
        """Get a specific entry by ID."""
        return self._entry_index.get(entry_id)
    
    async def get_children(self, parent_entry_id: str) -> list[AuditEntry]:
        """Get child entries of a parent entry."""
        return [
            e for e in self._entries
            if e.parent_entry_id == parent_entry_id
        ]
    
    async def export_audit(
        self,
        hours: int = 24,
        format: str = "jsonl",
        include_metadata: bool = True,
    ) -> str:
        """
        Export audit log for compliance.
        
        Args:
            hours: Hours to export
            format: Export format (jsonl, json, csv)
            include_metadata: Include full metadata
        
        Returns:
            Exported data as string
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        entries = [
            e for e in self._entries
            if e.timestamp > cutoff
        ]
        
        if format == "jsonl":
            return "\n".join(
                json.dumps(e.to_dict()) for e in entries
            )
        elif format == "json":
            data = {
                "export_time": datetime.utcnow().isoformat(),
                "hours": hours,
                "total_entries": len(entries),
                "entries": [e.to_dict() for e in entries],
            }
            return json.dumps(data, indent=2)
        elif format == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow([
                "entry_id", "agent_id", "action", "resource", "outcome",
                "timestamp", "reason", "severity", "duration_ms"
            ])
            
            # Rows
            for e in entries:
                writer.writerow([
                    e.entry_id, e.agent_id, e.action, e.resource, e.outcome.value,
                    e.timestamp.isoformat(), e.reason, e.severity.value, e.duration_ms or ""
                ])
            
            return output.getvalue()
        else:
            raise ValueError(f"Unknown format: {format}")
    
    async def get_statistics(self, hours: int = 24) -> dict[str, Any]:
        """Get audit statistics."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        entries = [e for e in self._entries if e.timestamp > cutoff]
        
        stats = {
            "total_entries": len(entries),
            "by_outcome": defaultdict(int),
            "by_severity": defaultdict(int),
            "by_action": defaultdict(int),
            "by_agent": defaultdict(int),
            "suspicious_count": 0,
            "failure_rate": 0.0,
            "denied_rate": 0.0,
        }
        
        for entry in entries:
            stats["by_outcome"][entry.outcome.value] += 1
            stats["by_severity"][entry.severity.value] += 1
            stats["by_action"][entry.action] += 1
            stats["by_agent"][entry.agent_id] += 1
            
            if entry.is_suspicious():
                stats["suspicious_count"] += 1
        
        # Convert defaultdicts to regular dicts
        stats["by_outcome"] = dict(stats["by_outcome"])
        stats["by_severity"] = dict(stats["by_severity"])
        stats["by_action"] = dict(stats["by_action"])
        stats["by_agent"] = dict(stats["by_agent"])
        
        if entries:
            stats["failure_rate"] = (
                stats["by_outcome"].get("failure", 0) / len(entries)
            )
            stats["denied_rate"] = (
                stats["by_outcome"].get("denied", 0) / len(entries)
            )
        
        return stats
    
    async def cleanup_old_entries(self) -> int:
        """Clean up entries older than retention period."""
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)
        
        # Remove from file storage
        log_file = self.storage_path / "audit.jsonl"
        if log_file.exists():
            loop = asyncio.get_event_loop()
            content = await loop.run_in_executor(None, log_file.read_text)
            
            lines = []
            removed = 0
            for line in content.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    ts = datetime.fromisoformat(data["timestamp"])
                    if ts > cutoff:
                        lines.append(line)
                    else:
                        removed += 1
                except:
                    lines.append(line)  # Keep malformed lines
            
            await loop.run_in_executor(
                None,
                log_file.write_text,
                "\n".join(lines) + "\n"
            )
            
            return removed
        
        return 0
    
    async def close(self) -> None:
        """Close the audit log."""
        if self._writer:
            await self._writer.close()


# Convenience functions

_audit_log: Optional[AuditLog] = None


def get_audit_log() -> AuditLog:
    """Get or create the default audit log."""
    global _audit_log
    if _audit_log is None:
        _audit_log = AuditLog()
    return _audit_log


async def log_action(
    agent_id: str,
    action: str,
    resource: str,
    outcome: AuditOutcome,
    reason: str = "",
    **kwargs,
) -> AuditEntry:
    """Log action to default audit log."""
    return await get_audit_log().log_action(
        agent_id, action, resource, outcome, reason, **kwargs
    )


async def query_by_agent(agent_id: str, hours: int = 24) -> list[AuditEntry]:
    """Query by agent from default audit log."""
    return await get_audit_log().query_by_agent(agent_id, hours)


async def query_by_action(action: str, hours: int = 24) -> list[AuditEntry]:
    """Query by action from default audit log."""
    return await get_audit_log().query_by_action(action, hours)


async def query_suspicious(hours: int = 24) -> list[AuditEntry]:
    """Query suspicious entries from default audit log."""
    return await get_audit_log().query_suspicious(hours)


async def export_audit(hours: int = 24, format: str = "jsonl") -> str:
    """Export from default audit log."""
    return await get_audit_log().export_audit(hours, format)


__all__ = [
    "AuditOutcome",
    "AuditSeverity",
    "AuditEntry",
    "AuditLogWriter",
    "AuditLog",
    "get_audit_log",
    "log_action",
    "query_by_agent",
    "query_by_action",
    "query_suspicious",
    "export_audit",
]