#!/usr/bin/env python3
"""
Behavior Baseline Module for Picoclaw Observability
Learns normal agent behavior patterns over time for anomaly detection
"""

import os
import json
import logging
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
import threading

logger = logging.getLogger(__name__)


@dataclass
class ToolCallStats:
    """Statistics for a specific tool call"""
    count: int = 0
    last_seen: Optional[str] = None
    first_seen: Optional[str] = None
    avg_duration_ms: float = 0.0
    total_duration_ms: int = 0
    
    def record(self, duration_ms: int = 0):
        """Record a tool call occurrence"""
        now = datetime.now().isoformat()
        self.count += 1
        self.total_duration_ms += duration_ms
        self.avg_duration_ms = self.total_duration_ms / self.count
        self.last_seen = now
        if self.first_seen is None:
            self.first_seen = now


@dataclass
class SequenceStats:
    """Statistics for tool call sequences"""
    count: int = 0
    last_seen: Optional[str] = None
    

@dataclass
class TimingStats:
    """Statistics for timing patterns"""
    hourly_counts: Dict[int, int] = field(default_factory=dict)
    daily_counts: Dict[int, int] = field(default_factory=dict)  # 0-6 for days of week
    last_updated: Optional[str] = None


@dataclass
class ResourceStats:
    """Statistics for resource usage"""
    samples: List[Dict[str, Any]] = field(default_factory=list)
    avg_memory_mb: float = 0.0
    avg_cpu_percent: float = 0.0
    max_memory_mb: float = 0.0
    max_cpu_percent: float = 0.0
    min_memory_mb: float = float('inf')
    min_cpu_percent: float = float('inf')


@dataclass
class AgentBaseline:
    """Complete baseline for a single agent"""
    agent_id: str
    operation_count: int = 0
    tool_calls: Dict[str, ToolCallStats] = field(default_factory=dict)
    sequences: Dict[str, SequenceStats] = field(default_factory=dict)  # "tool1->tool2->tool3"
    timing: TimingStats = field(default_factory=TimingStats)
    resources: ResourceStats = field(default_factory=ResourceStats)
    sensitive_tools_accessed: Dict[str, int] = field(default_factory=dict)
    created_at: Optional[str] = None
    last_updated: Optional[str] = None
    training_complete: bool = False
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()


# Sensitive tools that may indicate privilege escalation
SENSITIVE_TOOLS = {
    'exec', 'shell', 'bash', 'command', 'run', 'execute',
    'write', 'edit', 'delete', 'remove', 'unlink', 'rmdir',
    'upload', 'download', 'fetch', 'request',
    'browser', 'navigate', 'click', 'type',
    'process', 'kill', 'terminate',
    'nodes', 'invoke', 'run',
    'message', 'send', 'broadcast',
    'canvas', 'present'
}


class BehaviorBaseline:
    """
    Behavior baseline model for learning normal agent behavior patterns.
    
    Tracks:
    - Tool call frequency and duration
    - Typical tool sequences
    - Resource usage patterns (memory, CPU)
    - Timing patterns (hourly, daily)
    - Sensitive tool access patterns
    
    Supports a "training window" concept where the first N operations
    are used for learning before anomaly detection begins.
    """
    
    def __init__(
        self,
        storage_dir: str,
        training_window: int = 1000,
        sequence_length: int = 3,
        sensitive_tools: Optional[set] = None,
        auto_save: bool = True
    ):
        """
        Initialize the behavior baseline.
        
        Args:
            storage_dir: Directory to persist baseline data
            training_window: Number of operations for training phase (default 1000)
            sequence_length: Length of tool sequences to track (default 3)
            sensitive_tools: Set of sensitive tool names (uses default if None)
            auto_save: Whether to auto-save baselines after updates
        """
        self.storage_dir = Path(storage_dir)
        self.training_window = training_window
        self.sequence_length = sequence_length
        self.sensitive_tools = sensitive_tools or SENSITIVE_TOOLS.copy()
        self.auto_save = auto_save
        
        # In-memory baselines
        self._baselines: Dict[str, AgentBaseline] = {}
        
        # Recent operation history for sequence tracking
        self._recent_operations: Dict[str, List[str]] = defaultdict(list)
        self._recent_operations_lock = threading.Lock()
        
        # Ensure storage directory exists
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing baselines
        self._load_baselines()
        
        logger.info(f"BehaviorBaseline initialized with training_window={training_window}")
    
    def _load_baselines(self):
        """Load existing baselines from storage"""
        baseline_files = list(self.storage_dir.glob("baseline_*.json"))
        
        for filepath in baseline_files:
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                
                agent_id = data.get('agent_id')
                if agent_id:
                    baseline = self._dict_to_baseline(data)
                    self._baselines[agent_id] = baseline
                    logger.debug(f"Loaded baseline for agent {agent_id}")
                    
            except Exception as e:
                logger.warning(f"Failed to load baseline from {filepath}: {e}")
        
        logger.info(f"Loaded {len(self._baselines)} existing baselines")
    
    def _dict_to_baseline(self, data: dict) -> AgentBaseline:
        """Convert dictionary to AgentBaseline object"""
        baseline = AgentBaseline(
            agent_id=data.get('agent_id', 'unknown'),
            operation_count=data.get('operation_count', 0),
            timing=TimingStats(**data.get('timing', {})),
            created_at=data.get('created_at'),
            last_updated=data.get('last_updated'),
            training_complete=data.get('training_complete', False),
            sensitive_tools_accessed=data.get('sensitive_tools_accessed', {})
        )
        
        # Reconstruct tool calls
        for tool_name, stats in data.get('tool_calls', {}).items():
            baseline.tool_calls[tool_name] = ToolCallStats(**stats)
        
        # Reconstruct sequences
        for seq, stats in data.get('sequences', {}).items():
            baseline.sequences[seq] = SequenceStats(**stats)
        
        # Reconstruct resources
        resource_data = data.get('resources', {})
        if resource_data:
            baseline.resources = ResourceStats(**resource_data)
        
        return baseline
    
    def _baseline_to_dict(self, baseline: AgentBaseline) -> dict:
        """Convert AgentBaseline to dictionary for serialization"""
        data = {
            'agent_id': baseline.agent_id,
            'operation_count': baseline.operation_count,
            'tool_calls': {k: asdict(v) for k, v in baseline.tool_calls.items()},
            'sequences': {k: asdict(v) for k, v in baseline.sequences.items()},
            'timing': asdict(baseline.timing),
            'resources': asdict(baseline.resources),
            'sensitive_tools_accessed': baseline.sensitive_tools_accessed,
            'created_at': baseline.created_at,
            'last_updated': baseline.last_updated,
            'training_complete': baseline.training_complete
        }
        return data
    
    def _save_baseline(self, agent_id: str):
        """Save a single baseline to storage"""
        if agent_id not in self._baselines:
            return
        
        baseline = self._baselines[agent_id]
        filepath = self.storage_dir / f"baseline_{agent_id}.json"
        
        try:
            data = self._baseline_to_dict(baseline)
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved baseline for agent {agent_id}")
        except Exception as e:
            logger.error(f"Failed to save baseline for {agent_id}: {e}")
    
    def _get_or_create_baseline(self, agent_id: str) -> AgentBaseline:
        """Get existing baseline or create new one"""
        if agent_id not in self._baselines:
            self._baselines[agent_id] = AgentBaseline(agent_id=agent_id)
            logger.info(f"Created new baseline for agent {agent_id}")
        return self._baselines[agent_id]
    
    def _extract_tool_name(self, operation: dict) -> Optional[str]:
        """Extract tool name from operation"""
        # Handle various operation formats
        if 'tool' in operation:
            return operation['tool']
        if 'tool_name' in operation:
            return operation['tool_name']
        if 'name' in operation:
            return operation['name']
        if 'function' in operation:
            return operation['function'].get('name')
        if 'action' in operation:
            return operation['action']
        return None
    
    def _extract_resources(self, operation: dict) -> Optional[Dict[str, float]]:
        """Extract resource usage from operation"""
        resources = {}
        
        if 'memory_mb' in operation:
            resources['memory_mb'] = operation['memory_mb']
        if 'cpu_percent' in operation:
            resources['cpu_percent'] = operation['cpu_percent']
        if 'resources' in operation:
            res = operation['resources']
            if isinstance(res, dict):
                resources.update(res)
        
        return resources if resources else None
    
    def _update_sequence(self, baseline: AgentBaseline, tool_name: str):
        """Update sequence patterns"""
        with self._recent_operations_lock:
            # Get recent operations for this agent
            recent = self._recent_operations[baseline.agent_id]
            
            # Add current tool
            recent.append(tool_name)
            
            # Keep only last sequence_length + 1 operations
            max_len = self.sequence_length + 1
            if len(recent) > max_len:
                self._recent_operations[baseline.agent_id] = recent[-max_len:]
                recent = self._recent_operations[baseline.agent_id]
            
            # Record sequences of various lengths
            for length in range(2, min(len(recent) + 1, self.sequence_length + 1)):
                seq = '->'.join(recent[-length:])
                if seq not in baseline.sequences:
                    baseline.sequences[seq] = SequenceStats()
                baseline.sequences[seq].count += 1
                baseline.sequences[seq].last_seen = datetime.now().isoformat()
    
    def _update_timing(self, baseline: AgentBaseline):
        """Update timing statistics"""
        now = datetime.now()
        hour = now.hour
        day_of_week = now.weekday()  # 0 = Monday, 6 = Sunday
        
        baseline.timing.hourly_counts[hour] = baseline.timing.hourly_counts.get(hour, 0) + 1
        baseline.timing.daily_counts[day_of_week] = baseline.timing.daily_counts.get(day_of_week, 0) + 1
        baseline.timing.last_updated = now.isoformat()
    
    def _update_resources(self, baseline: AgentBaseline, resources: Dict[str, float]):
        """Update resource statistics"""
        res = baseline.resources
        
        # Store sample (keep last 100)
        res.samples.append({
            'timestamp': datetime.now().isoformat(),
            **resources
        })
        if len(res.samples) > 100:
            res.samples = res.samples[-100:]
        
        # Update statistics
        if 'memory_mb' in resources:
            mem = resources['memory_mb']
            res.avg_memory_mb = (res.avg_memory_mb * (len(res.samples) - 1) + mem) / len(res.samples)
            res.max_memory_mb = max(res.max_memory_mb, mem)
            res.min_memory_mb = min(res.min_memory_mb, mem) if res.min_memory_mb != float('inf') else mem
        
        if 'cpu_percent' in resources:
            cpu = resources['cpu_percent']
            res.avg_cpu_percent = (res.avg_cpu_percent * (len(res.samples) - 1) + cpu) / len(res.samples)
            res.max_cpu_percent = max(res.max_cpu_percent, cpu)
            res.min_cpu_percent = min(res.min_cpu_percent, cpu) if res.min_cpu_percent != float('inf') else cpu
    
    async def record_operation(self, agent_id: str, operation: dict):
        """
        Record an operation for baseline learning/detection.
        
        This method should be called for every operation an agent performs.
        During the training window, it builds the baseline;
        after training, it can detect anomalies.
        
        Args:
            agent_id: Unique identifier for the agent
            operation: Operation data containing tool, resources, etc.
        """
        baseline = self._get_or_create_baseline(agent_id)
        
        # Extract tool name
        tool_name = self._extract_tool_name(operation)
        if not tool_name:
            logger.debug(f"Could not extract tool name from operation: {operation}")
            return
        
        # Update tool call statistics
        duration_ms = operation.get('duration_ms', 0)
        if tool_name not in baseline.tool_calls:
            baseline.tool_calls[tool_name] = ToolCallStats()
        baseline.tool_calls[tool_name].record(duration_ms)
        
        # Update sequence patterns
        self._update_sequence(baseline, tool_name)
        
        # Update timing
        self._update_timing(baseline)
        
        # Update resource usage if present
        resources = self._extract_resources(operation)
        if resources:
            self._update_resources(baseline, resources)
        
        # Track sensitive tool access
        if tool_name in self.sensitive_tools:
            baseline.sensitive_tools_accessed[tool_name] = \
                baseline.sensitive_tools_accessed.get(tool_name, 0) + 1
        
        # Update operation count and timestamp
        baseline.operation_count += 1
        baseline.last_updated = datetime.now().isoformat()
        
        # Check if training is complete
        if baseline.operation_count >= self.training_window and not baseline.training_complete:
            baseline.training_complete = True
            logger.info(f"Training complete for agent {agent_id} after {baseline.operation_count} operations")
        
        # Auto-save if enabled
        if self.auto_save:
            self._save_baseline(agent_id)
    
    def get_baseline(self, agent_id: str) -> dict:
        """
        Return learned baseline for agent.
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            Dictionary containing baseline statistics
        """
        if agent_id not in self._baselines:
            return {}
        
        baseline = self._baselines[agent_id]
        return self._baseline_to_dict(baseline)
    
    def is_trained(self, agent_id: str) -> bool:
        """
        Check if baseline has enough data (training window completed).
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            True if the agent has completed training, False otherwise
        """
        if agent_id not in self._baselines:
            return False
        
        return self._baselines[agent_id].training_complete
    
    def get_tool_frequency(self, agent_id: str) -> Dict[str, float]:
        """
        Get normalized tool call frequency (calls per 100 operations).
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            Dictionary of tool_name -> frequency
        """
        if agent_id not in self._baselines:
            return {}
        
        baseline = self._baselines[agent_id]
        total = baseline.operation_count
        
        if total == 0:
            return {}
        
        return {
            tool: (stats.count / total) * 100
            for tool, stats in baseline.tool_calls.items()
        }
    
    def get_common_sequences(self, agent_id: str, top_n: int = 10) -> List[tuple]:
        """
        Get most common tool sequences for an agent.
        
        Args:
            agent_id: Agent identifier
            top_n: Number of top sequences to return
        
        Returns:
            List of (sequence, count) tuples, sorted by count
        """
        if agent_id not in self._baselines:
            return []
        
        baseline = self._baselines[agent_id]
        sequences = [
            (seq, stats.count)
            for seq, stats in baseline.sequences.items()
        ]
        
        # Sort by count descending
        sequences.sort(key=lambda x: x[1], reverse=True)
        
        return sequences[:top_n]
    
    def get_sensitive_tools_used(self, agent_id: str) -> Dict[str, int]:
        """
        Get sensitive tools that have been used by an agent.
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            Dictionary of tool_name -> usage_count
        """
        if agent_id not in self._baselines:
            return {}
        
        return self._baselines[agent_id].sensitive_tools_accessed.copy()
    
    def get_timing_patterns(self, agent_id: str) -> dict:
        """
        Get timing patterns for an agent.
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            Dictionary with hourly_counts and daily_counts
        """
        if agent_id not in self._baselines:
            return {'hourly_counts': {}, 'daily_counts': {}}
        
        baseline = self._baselines[agent_id]
        return {
            'hourly_counts': dict(baseline.timing.hourly_counts),
            'daily_counts': dict(baseline.timing.daily_counts)
        }
    
    def get_resource_patterns(self, agent_id: str) -> dict:
        """
        Get resource usage patterns for an agent.
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            Dictionary with resource statistics
        """
        if agent_id not in self._baselines:
            return {}
        
        baseline = self._baselines[agent_id]
        res = baseline.resources
        
        return {
            'avg_memory_mb': res.avg_memory_mb,
            'avg_cpu_percent': res.avg_cpu_percent,
            'max_memory_mb': res.max_memory_mb if res.max_memory_mb != 0 else None,
            'max_cpu_percent': res.max_cpu_percent if res.max_cpu_percent != 0 else None,
            'min_memory_mb': res.min_memory_mb if res.min_memory_mb != float('inf') else None,
            'min_cpu_percent': res.min_cpu_percent if res.min_cpu_percent != float('inf') else None,
            'sample_count': len(res.samples)
        }
    
    def reset_baseline(self, agent_id: str) -> bool:
        """
        Reset (clear) baseline for an agent.
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            True if baseline was reset, False if not found
        """
        if agent_id not in self._baselines:
            return False
        
        # Remove from memory
        del self._baselines[agent_id]
        
        # Remove from storage
        filepath = self.storage_dir / f"baseline_{agent_id}.json"
        if filepath.exists():
            filepath.unlink()
        
        # Clear recent operations
        with self._recent_operations_lock:
            if agent_id in self._recent_operations:
                del self._recent_operations[agent_id]
        
        logger.info(f"Reset baseline for agent {agent_id}")
        return True
    
    def get_all_agents(self) -> List[str]:
        """
        Get list of all agents with baselines.
        
        Returns:
            List of agent IDs
        """
        return list(self._baselines.keys())
    
    def get_training_progress(self, agent_id: str) -> dict:
        """
        Get training progress for an agent.
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            Dictionary with training progress info
        """
        if agent_id not in self._baselines:
            return {
                'agent_id': agent_id,
                'operations': 0,
                'required': self.training_window,
                'progress': 0.0,
                'trained': False
            }
        
        baseline = self._baselines[agent_id]
        progress = min(1.0, baseline.operation_count / self.training_window)
        
        return {
            'agent_id': agent_id,
            'operations': baseline.operation_count,
            'required': self.training_window,
            'progress': progress * 100,
            'trained': baseline.training_complete
        }
    
    def save_all(self):
        """Save all baselines to storage"""
        for agent_id in self._baselines:
            self._save_baseline(agent_id)
        logger.info(f"Saved all baselines ({len(self._baselines)} agents)")
    
    def load_baseline(self, agent_id: str) -> bool:
        """
        Load a specific baseline from storage.
        
        Args:
            agent_id: Agent identifier
        
        Returns:
            True if loaded successfully, False if not found
        """
        filepath = self.storage_dir / f"baseline_{agent_id}.json"
        
        if not filepath.exists():
            return False
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            baseline = self._dict_to_baseline(data)
            self._baselines[agent_id] = baseline
            logger.info(f"Loaded baseline for agent {agent_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load baseline from {filepath}: {e}")
            return False


# Singleton instance
_behavior_baseline = None

def get_behavior_baseline(
    storage_dir: str = None,
    training_window: int = 1000
) -> BehaviorBaseline:
    """
    Get or create singleton BehaviorBaseline instance.
    
    Args:
        storage_dir: Directory for baseline storage (default: /home/cogniwatch/data/baselines)
        training_window: Number of operations for training
    
    Returns:
        BehaviorBaseline instance
    """
    global _behavior_baseline
    
    if _behavior_baseline is None:
        if storage_dir is None:
            storage_dir = os.environ.get(
                'PICOCLAW_BASELINE_DIR',
                '/home/cogniwatch/data/baselines'
            )
        _behavior_baseline = BehaviorBaseline(
            storage_dir=storage_dir,
            training_window=training_window
        )
    
    return _behavior_baseline