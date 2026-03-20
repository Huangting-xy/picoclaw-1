"""
Tool-Call Logging Module for Picoclaw

Provides async-safe logging of tool calls with:
- Timestamp, tool_name, input_params, context, intent, outcome
- JSONL file output with configurable rotation
- Request ID tracking for session correlation
- Timing metrics (start_time, end_time, duration_ms)
"""

import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional
import aiofiles
import aiofiles.os


@dataclass
class ToolCallLog:
    """Represents a single tool call log entry."""
    timestamp: str
    tool_name: str
    input_params: dict[str, Any]
    context: str
    intent: str
    outcome: str  # 'success', 'failure', 'pending'
    request_id: str
    start_time: str
    end_time: Optional[str] = None
    duration_ms: Optional[float] = None
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON line for file storage."""
        return json.dumps(self.to_dict())


class ToolLogger:
    """
    Async-safe logger for tool calls with file rotation.
    
    Features:
    - JSONL file output
    - Configurable rotation (size-based)
    - Request ID tracking for session correlation
    - Timing metrics
    - Query capabilities
    
    Usage:
        logger = ToolLogger("./logs")
        
        # Context manager approach
        async with logger.log_tool_call(
            tool_name="read_file",
            params={"path": "/etc/passwd"},
            context="Inspecting system configuration",
            intent="Check for misconfigurations"
        ):
            result = await read_file("/etc/passwd")
            return result
        
        # Decorator approach
        @log_tool_call
        async def my_tool(arg1: str, arg2: int) -> dict:
            ...
    """
    
    # File naming pattern
    LOG_FILENAME = "tool_calls.jsonl"
    
    def __init__(
        self,
        log_dir: str,
        max_size_mb: int = 10,
        max_files: int = 5,
        request_id: Optional[str] = None
    ):
        """
        Initialize the tool logger.
        
        Args:
            log_dir: Directory to store log files
            max_size_mb: Maximum size per log file in MB (default: 10)
            max_files: Maximum number of rotated files to keep (default: 5)
            request_id: Current session request ID (auto-generated if None)
        """
        self.log_dir = Path(log_dir)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_files = max_files
        self.request_id = request_id or self._generate_request_id()
        self._lock = asyncio.Lock()
        self._current_file: Optional[str] = None
        
        # Create log directory if needed
        self.log_dir.mkdir(parents=True, exist_ok=True)
    
    @staticmethod
    def _generate_request_id() -> str:
        """Generate a unique request ID."""
        return f"req_{uuid.uuid4().hex[:12]}"
    
    def _get_log_path(self, index: int = 0) -> Path:
        """Get the path for a log file by index."""
        if index == 0:
            return self.log_dir / self.LOG_FILENAME
        else:
            # Rotated files have .1, .2, etc. suffix
            base = self.log_dir / self.LOG_FILENAME
            return self.log_dir / f"{base.stem}.{index}.jsonl"
    
    async def _get_current_file_size(self) -> int:
        """Get the current log file size."""
        log_path = self._get_log_path()
        if not await aiofiles.os.path.exists(log_path):
            return 0
        stat = await aiofiles.os.stat(log_path)
        return stat.st_size
    
    async def _rotate_logs(self) -> None:
        """
        Rotate log files when size limit is reached.
        
        Moves current.jsonl -> current.1.jsonl, current.1.jsonl -> current.2.jsonl, etc.
        Deletes oldest file if exceeding max_files.
        """
        # Delete oldest file if it exists
        oldest_path = self._get_log_path(self.max_files)
        if await aiofiles.os.path.exists(oldest_path):
            await aiofiles.os.remove(oldest_path)
        
        # Shift all files up
        for i in range(self.max_files - 1, 0, -1):
            old_path = self._get_log_path(i)
            new_path = self._get_log_path(i + 1)
            if await aiofiles.os.path.exists(old_path):
                await aiofiles.os.rename(old_path, new_path)
        
        # Move current to .1
        current_path = self._get_log_path()
        next_path = self._get_log_path(1)
        if await aiofiles.os.path.exists(current_path):
            await aiofiles.os.rename(current_path, next_path)
    
    async def _write_log_entry(self, entry: ToolCallLog) -> None:
        """Write a log entry to the JSONL file with rotation check."""
        async with self._lock:
            # Check if rotation needed
            current_size = await self._get_current_file_size()
            entry_size = len(entry.to_json()) + 1  # +1 for newline
            
            if current_size + entry_size > self.max_size_bytes:
                await self._rotate_logs()
            
            # Append to log file
            log_path = self._get_log_path()
            async with aiofiles.open(log_path, mode='a') as f:
                await f.write(entry.to_json() + '\n')
    
    @asynccontextmanager
    async def log_tool_call(
        self,
        tool_name: str,
        params: dict[str, Any],
        context: str,
        intent: str
    ):
        """
        Context manager that logs tool call entry and exit.
        
        Automatically captures timing metrics and outcome status.
        
        Args:
            tool_name: Name of the tool being called
            params: Input parameters to the tool
            context: What the agent was doing when calling this tool
            intent: Why the tool was called
        
        Yields:
            ToolCallLog: The log entry being constructed
        
        Example:
            async with logger.log_tool_call(
                tool_name="read_file",
                params={"path": "/etc/passwd"},
                context="Inspecting system configuration",
                intent="Check for misconfigurations"
            ) as log:
                result = await read_file("/etc/passwd")
                log.result_summary = "Found 42 entries"
                return result
        """
        start_dt = datetime.now(timezone.utc)
        start_time = start_dt.isoformat()
        timestamp = start_time
        
        # Create initial log entry with 'pending' outcome
        entry = ToolCallLog(
            timestamp=timestamp,
            tool_name=tool_name,
            input_params=params,
            context=context,
            intent=intent,
            outcome='pending',
            request_id=self.request_id,
            start_time=start_time,
            end_time=None,
            duration_ms=None
        )
        
        error = None
        try:
            yield entry
            entry.outcome = 'success'
        except Exception as e:
            entry.outcome = 'failure'
            entry.error = str(e)
            error = e
        finally:
            # Complete timing
            end_dt = datetime.now(timezone.utc)
            entry.end_time = end_dt.isoformat()
            entry.duration_ms = (end_dt - start_dt).total_seconds() * 1000
            
            # Write the completed log entry
            await self._write_log_entry(entry)
            
            # Re-raise exception if there was one
            if error:
                raise error
    
    def log_tool_call_decorator(
        self,
        tool_name: Optional[str] = None,
        context: str = "",
        intent: str = ""
    ) -> Callable:
        """
        Decorator factory for wrapping tool functions.
        
        Args:
            tool_name: Tool name (defaults to function name)
            context: What the agent was doing
            intent: Why the tool was called
        
        Returns:
            Decorator function
        
        Example:
            @logger.log_tool_call_decorator(context="Reading config", intent="Check settings")
            async def read_config(path: str) -> dict:
                async with aiofiles.open(path) as f:
                    return json.loads(await f.read())
        """
        def decorator(func: Callable) -> Callable:
            # Use function name if tool_name not provided
            name = tool_name or func.__name__
            
            if asyncio.iscoroutinefunction(func):
                async def async_wrapper(*args, **kwargs):
                    async with self.log_tool_call(
                        tool_name=name,
                        params={'args': args, 'kwargs': kwargs},
                        context=context,
                        intent=intent
                    ):
                        return await func(*args, **kwargs)
                return async_wrapper
            else:
                def sync_wrapper(*args, **kwargs):
                    # For sync functions, we need to run the async context
                    async def run_with_logging():
                        async with self.log_tool_call(
                            tool_name=name,
                            params={'args': args, 'kwargs': kwargs},
                            context=context,
                            intent=intent
                        ):
                            return func(*args, **kwargs)
                    return asyncio.run(run_with_logging())
                return sync_wrapper
        
        return decorator
    
    async def _read_all_logs(self) -> list[dict]:
        """Read all log entries from all log files."""
        entries = []
        
        # Read from all rotated files and current
        for i in range(0, self.max_files + 1):
            log_path = self._get_log_path(i if i == 0 else i)
            if i == 0:
                log_path = self._get_log_path()
            else:
                log_path = self._get_log_path(i)
            
            if not await aiofiles.os.path.exists(log_path):
                continue
            
            try:
                async with aiofiles.open(log_path, mode='r') as f:
                    content = await f.read()
                    for line in content.strip().split('\n'):
                        if line.strip():
                            try:
                                entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
            except FileNotFoundError:
                continue
        
        # Sort by timestamp (most recent first)
        entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return entries
    
    def _filter_by_hours(self, entries: list[dict], hours: int) -> list[dict]:
        """Filter entries within the specified hours window."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        cutoff_str = cutoff.isoformat()
        
        filtered = []
        for entry in entries:
            timestamp = entry.get('timestamp', '')
            if timestamp >= cutoff_str:
                filtered.append(entry)
        
        return filtered
    
    async def query_by_tool(self, tool_name: str, hours: int = 24) -> list[dict]:
        """
        Query recent tool calls by name.
        
        Args:
            tool_name: Name of the tool to query
            hours: Number of hours to look back (default: 24)
        
        Returns:
            List of matching log entries (newest first)
        """
        all_entries = await self._read_all_logs()
        recent = self._filter_by_hours(all_entries, hours)
        
        return [
            entry for entry in recent
            if entry.get('tool_name') == tool_name
        ]
    
    async def query_by_outcome(self, success: bool, hours: int = 24) -> list[dict]:
        """
        Query recent tool calls by outcome.
        
        Args:
            success: True for successful calls, False for failures
            hours: Number of hours to look back (default: 24)
        
        Returns:
            List of matching log entries (newest first)
        """
        all_entries = await self._read_all_logs()
        recent = self._filter_by_hours(all_entries, hours)
        
        target_outcome = 'success' if success else 'failure'
        
        return [
            entry for entry in recent
            if entry.get('outcome') == target_outcome
        ]
    
    async def query_by_request_id(self, request_id: str) -> list[dict]:
        """
        Query all tool calls within a session by request ID.
        
        Args:
            request_id: The session request ID to query
        
        Returns:
            List of matching log entries (chronological order)
        """
        all_entries = await self._read_all_logs()
        
        matched = [
            entry for entry in all_entries
            if entry.get('request_id') == request_id
        ]
        
        # Sort chronologically (oldest first)
        matched.sort(key=lambda x: x.get('timestamp', ''))
        return matched
    
    async def get_statistics(self, hours: int = 24) -> dict[str, Any]:
        """
        Get summary statistics for tool calls.
        
        Args:
            hours: Number of hours to analyze (default: 24)
        
        Returns:
            Dictionary with statistics
        """
        all_entries = await self._read_all_logs()
        recent = self._filter_by_hours(all_entries, hours)
        
        stats = {
            'total_calls': len(recent),
            'successful': sum(1 for e in recent if e.get('outcome') == 'success'),
            'failed': sum(1 for e in recent if e.get('outcome') == 'failure'),
            'by_tool': {},
            'avg_duration_ms': 0,
            'max_duration_ms': 0,
            'min_duration_ms': 0
        }
        
        # Count by tool
        for entry in recent:
            tool = entry.get('tool_name', 'unknown')
            stats['by_tool'][tool] = stats['by_tool'].get(tool, 0) + 1
        
        # Calculate duration stats
        durations = [
            entry['duration_ms'] 
            for entry in recent 
            if entry.get('duration_ms') is not None
        ]
        
        if durations:
            stats['avg_duration_ms'] = sum(durations) / len(durations)
            stats['max_duration_ms'] = max(durations)
            stats['min_duration_ms'] = min(durations)
        
        return stats
    
    def set_request_id(self, request_id: str) -> None:
        """
        Set a new request ID for subsequent tool calls.
        
        Use this to correlate tool calls within a session.
        
        Args:
            request_id: New request ID to use
        """
        self.request_id = request_id
    
    def new_request_id(self) -> str:
        """
        Generate and set a new request ID.
        
        Returns:
            The new request ID
        """
        self.request_id = self._generate_request_id()
        return self.request_id


# Convenience function for creating a decorator
def log_tool_call(logger: ToolLogger):
    """
    Create a decorator for logging tool calls.
    
    This is a convenience wrapper around ToolLogger.log_tool_call_decorator.
    
    Args:
        logger: ToolLogger instance to use
    
    Example:
        tool_logger = ToolLogger("./logs")
        
        @log_tool_call(tool_logger)
        async def my_tool(path: str) -> dict:
            ...
        
        # Or with explicit parameters:
        @log_tool_call(tool_logger)
        def my_tool(context="Reading file", intent="Load configuration"):
            ...
    """
    return logger.log_tool_call_decorator