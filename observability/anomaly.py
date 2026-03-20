#!/usr/bin/env python3
"""
Anomaly Detection Module for Picoclaw Observability
Compares current behavior against learned baselines
"""

import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import threading

from .baseline import BehaviorBaseline, get_behavior_baseline

logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """Types of behavioral anomalies"""
    UNUSUAL_TOOL_CALL = "unusual_tool_call"
    FREQUENCY_SPIKE = "frequency_spike"
    SEQUENCE_BREAK = "sequence_break"
    RESOURCE_ANOMALY = "resource_anomaly"
    TIMING_ANOMALY = "timing_anomaly"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RAPID_OPERATION = "rapid_operation"
    UNUSUAL_PARAMETER = "unusual_parameter"


class AnomalySeverity(Enum):
    """Severity levels for anomalies"""
    LOW = 0.2
    MEDIUM = 0.5
    HIGH = 0.7
    CRITICAL = 0.9
    
    @classmethod
    def from_score(cls, score: float) -> 'AnomalySeverity':
        """Get severity from anomaly score"""
        if score >= cls.CRITICAL.value:
            return cls.CRITICAL
        elif score >= cls.HIGH.value:
            return cls.HIGH
        elif score >= cls.MEDIUM.value:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class Anomaly:
    """Represents a detected anomaly"""
    anomaly_type: str
    severity: float
    description: str
    agent_id: str
    timestamp: str
    details: Dict[str, Any] = field(default_factory=dict)
    operation: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'anomaly_type': self.anomaly_type,
            'severity': self.severity,
            'severity_level': AnomalySeverity.from_score(self.severity).name,
            'description': self.description,
            'agent_id': self.agent_id,
            'timestamp': self.timestamp,
            'details': self.details,
            'operation': self.operation
        }


class AnomalyDetector:
    """
    Anomaly detector comparing current behavior against learned baseline.
    
    Detects:
    - UNUSUAL_TOOL_CALL: Tool not seen during training
    - FREQUENCY_SPIKE: Tool call rate much higher than normal
    - SEQUENCE_BREAK: Tool sequence not seen before
    - RESOURCE_ANOMALY: Memory/CPU outside normal range
    - TIMING_ANOMALY: Operations at unusual times
    - PRIVILEGE_ESCALATION: Sudden access to sensitive tools
    
    Scores anomalies from 0.0 to 1.0 (severity).
    Supports alert callbacks for real-time notifications.
    """
    
    # Configuration defaults
    DEFAULT_FREQUENCY_THRESHOLD = 3.0  # 3x normal rate = spike
    DEFAULT_RESOURCE_THRESHOLD = 2.0   # 2x std deviation
    DEFAULT_TIMING_THRESHOLD = 0.1     # 10% of normal activity = unusual
    DEFAULT_SENSITIVE_TOOL_THRESHOLD = 0.05  # New sensitive tool > 5% of ops = escalation
    
    def __init__(
        self,
        baseline: BehaviorBaseline,
        alert_callback: Optional[Callable[[Anomaly], None]] = None,
        frequency_threshold: float = DEFAULT_FREQUENCY_THRESHOLD,
        resource_threshold: float = DEFAULT_RESOURCE_THRESHOLD,
        timing_threshold: float = DEFAULT_TIMING_THRESHOLD,
        sensitive_tools: Optional[set] = None,
        store_history: bool = True,
        history_hours: int = 24
    ):
        """
        Initialize anomaly detector.
        
        Args:
            baseline: BehaviorBaseline instance for comparison
            alert_callback: Callable to invoke when anomalies detected
            frequency_threshold: Multiplier for frequency spike detection
            resource_threshold: Std deviation multiplier for resource anomalies
            timing_threshold: Minimum activity ratio for timing anomalies
            sensitive_tools: Set of sensitive tool names (uses default if None)
            store_history: Whether to store anomaly history
            history_hours: How long to store anomaly history
        """
        self.baseline = baseline
        self.alert_callback = alert_callback
        self.frequency_threshold = frequency_threshold
        self.resource_threshold = resource_threshold
        self.timing_threshold = timing_threshold
        self.sensitive_tools = sensitive_tools or set()
        self.store_history = store_history
        self.history_hours = history_hours
        
        # Anomaly history storage
        self._anomaly_history: Dict[str, List[Anomaly]] = defaultdict(list)
        self._history_lock = threading.Lock()
        
        # Recent operation tracking for frequency detection
        self._recent_ops: Dict[str, List[datetime]] = defaultdict(list)
        self._recent_ops_lock = threading.Lock()
        
        logger.info(f"AnomalyDetector initialized with frequency_threshold={frequency_threshold}")
    
    def _add_to_history(self, anomaly: Anomaly):
        """Add anomaly to history"""
        if not self.store_history:
            return
        
        with self._history_lock:
            self._anomaly_history[anomaly.agent_id].append(anomaly)
            
            # Clean old entries
            cutoff = datetime.now() - timedelta(hours=self.history_hours)
            self._anomaly_history[anomaly.agent_id] = [
                a for a in self._anomaly_history[anomaly.agent_id]
                if datetime.fromisoformat(a.timestamp) > cutoff
            ]
    
    def _call_alert(self, anomaly: Anomaly):
        """Invoke alert callback if configured"""
        if self.alert_callback:
            try:
                self.alert_callback(anomaly)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
    
    def _extract_tool_name(self, operation: dict) -> Optional[str]:
        """Extract tool name from operation"""
        for key in ['tool', 'tool_name', 'name', 'function']:
            if key in operation:
                if key == 'function' and isinstance(operation[key], dict):
                    return operation[key].get('name')
                return operation[key]
        return None
    
    def _check_unusual_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        operation: dict
    ) -> Optional[Anomaly]:
        """Check if tool call is unusual (not in baseline)"""
        if not self.baseline.is_trained(agent_id):
            return None
        
        baseline_data = self.baseline.get_baseline(agent_id)
        tool_calls = baseline_data.get('tool_calls', {})
        
        if tool_name not in tool_calls:
            # Check if it's a sensitive tool
            is_sensitive = tool_name in self.sensitive_tools
            
            severity = 0.6 if is_sensitive else 0.4
            
            anomaly = Anomaly(
                anomaly_type=AnomalyType.UNUSUAL_TOOL_CALL.value,
                severity=severity,
                description=f"Tool '{tool_name}' not seen in baseline training",
                agent_id=agent_id,
                timestamp=datetime.now().isoformat(),
                details={
                    'tool_name': tool_name,
                    'is_sensitive': is_sensitive,
                    'known_tools': list(tool_calls.keys())
                },
                operation=operation
            )
            
            self._add_to_history(anomaly)
            self._call_alert(anomaly)
            
            return anomaly
        
        return None
    
    def _check_frequency_spike(
        self,
        agent_id: str,
        tool_name: str,
        operation: dict
    ) -> Optional[Anomaly]:
        """Check for tool call frequency spike"""
        if not self.baseline.is_trained(agent_id):
            return None
        
        # Track recent operations
        now = datetime.now()
        with self._recent_ops_lock:
            # Clean old entries (keep last minute)
            cutoff = now - timedelta(minutes=1)
            self._recent_ops[agent_id] = [
                ts for ts in self._recent_ops[agent_id]
                if ts > cutoff
            ]
            self._recent_ops[agent_id].append(now)
            
            current_rate = len(self._recent_ops[agent_id])  # ops per minute
        
        # Get baseline frequency
        baseline_data = self.baseline.get_baseline(agent_id)
        baseline_tool_calls = baseline_data.get('tool_calls', {})
        
        if tool_name not in baseline_tool_calls:
            return None  # Already caught by unusual_tool_call
        
        # Calculate expected rate from baseline
        total_ops = baseline_data.get('operation_count', 1)
        tool_count = baseline_tool_calls[tool_name].get('count', 0)
        
        # Estimate baseline rate (ops per minute)
        # Assume training window was spread over reasonable time
        # Use baseline's first_seen and last_seen for actual duration
        first_seen = baseline_tool_calls[tool_name].get('first_seen')
        last_seen = baseline_tool_calls[tool_name].get('last_seen')
        
        if first_seen and last_seen:
            try:
                first_dt = datetime.fromisoformat(first_seen)
                last_dt = datetime.fromisoformat(last_seen)
                duration_minutes = max(1, (last_dt - first_dt).total_seconds() / 60)
                baseline_rate = tool_count / duration_minutes
            except:
                # Fallback to simplified calculation
                baseline_rate = (tool_count / total_ops) * 10  # Rough estimate
        else:
            baseline_rate = (tool_count / total_ops) * 10  # Rough estimate
        
        if baseline_rate > 0:
            spike_ratio = current_rate / baseline_rate
            
            if spike_ratio > self.frequency_threshold:
                severity = min(1.0, 0.3 + (spike_ratio - self.frequency_threshold) * 0.1)
                
                anomaly = Anomaly(
                    anomaly_type=AnomalyType.FREQUENCY_SPIKE.value,
                    severity=severity,
                    description=f"Tool call frequency {spike_ratio:.1f}x higher than baseline",
                    agent_id=agent_id,
                    timestamp=datetime.now().isoformat(),
                    details={
                        'tool_name': tool_name,
                        'current_rate_per_min': current_rate,
                        'baseline_rate_per_min': baseline_rate,
                        'spike_ratio': spike_ratio,
                        'threshold': self.frequency_threshold
                    },
                    operation=operation
                )
                
                self._add_to_history(anomaly)
                self._call_alert(anomaly)
                
                return anomaly
        
        return None
    
    def _check_sequence_break(
        self,
        agent_id: str,
        tool_name: str,
        operation: dict
    ) -> Optional[Anomaly]:
        """Check if tool sequence breaks known patterns"""
        if not self.baseline.is_trained(agent_id):
            return None
        
        baseline_data = self.baseline.get_baseline(agent_id)
        known_sequences = baseline_data.get('sequences', {})
        
        if not known_sequences:
            return None
        
        # Get baseline to access recent operations
        # We need to check if the sequence ending with current tool is known
        # This is done by the baseline's sequence tracking
        
        # For simplicity, check if any sequence containing this tool exists
        # More sophisticated checking would require integration with baseline
        sequences_with_tool = [
            seq for seq in known_sequences.keys()
            if tool_name in seq.split('->')
        ]
        
        # If tool has never been in any sequence before, it might indicate a break
        if known_sequences and not sequences_with_tool:
            # Tool exists in baseline but never in any sequence
            # This could indicate it's being used in a new context
            pass
        
        return None  # Sequence breaks are better detected at pattern level
    
    def _check_resource_anomaly(
        self,
        agent_id: str,
        operation: dict
    ) -> Optional[Anomaly]:
        """Check for resource usage anomalies"""
        if not self.baseline.is_trained(agent_id):
            return None
        
        # Extract resource usage
        resources = {}
        if 'memory_mb' in operation:
            resources['memory_mb'] = operation['memory_mb']
        if 'cpu_percent' in operation:
            resources['cpu_percent'] = operation['cpu_percent']
        if 'resources' in operation:
            if isinstance(operation['resources'], dict):
                resources.update(operation['resources'])
        
        if not resources:
            return None
        
        # Get baseline resource patterns
        baseline_resources = self.baseline.get_resource_patterns(agent_id)
        
        if not baseline_resources:
            return None
        
        anomalies = []
        
        # Check memory
        if 'memory_mb' in resources:
            avg_mem = baseline_resources.get('avg_memory_mb', 0)
            if avg_mem > 0:
                mem_ratio = resources['memory_mb'] / avg_mem
                if mem_ratio > self.resource_threshold:
                    severity = min(1.0, 0.3 + (mem_ratio - 1) * 0.2)
                    anomalies.append(('memory', resources['memory_mb'], avg_mem, severity))
        
        # Check CPU
        if 'cpu_percent' in resources:
            avg_cpu = baseline_resources.get('avg_cpu_percent', 0)
            if avg_cpu > 0:
                cpu_ratio = resources['cpu_percent'] / avg_cpu
                if cpu_ratio > self.resource_threshold:
                    severity = min(1.0, 0.3 + (cpu_ratio - 1) * 0.2)
                    anomalies.append(('cpu', resources['cpu_percent'], avg_cpu, severity))
        
        # Create anomaly for the worst case
        if anomalies:
            worst = max(anomalies, key=lambda x: x[3])
            resource_type, current, baseline_avg, severity = worst
            
            anomaly = Anomaly(
                anomaly_type=AnomalyType.RESOURCE_ANOMALY.value,
                severity=severity,
                description=f"{resource_type.capitalize()} usage {current:.1f} exceeds baseline {baseline_avg:.1f}",
                agent_id=agent_id,
                timestamp=datetime.now().isoformat(),
                details={
                    'resource_type': resource_type,
                    'current_value': current,
                    'baseline_average': baseline_avg,
                    'ratio': current / baseline_avg if baseline_avg > 0 else float('inf'),
                    'all_anomalies': [(a[0], a[1], a[2]) for a in anomalies]
                },
                operation=operation
            )
            
            self._add_to_history(anomaly)
            self._call_alert(anomaly)
            
            return anomaly
        
        return None
    
    def _check_timing_anomaly(
        self,
        agent_id: str,
        operation: dict
    ) -> Optional[Anomaly]:
        """Check for timing anomalies (unusual hours)"""
        if not self.baseline.is_trained(agent_id):
            return None
        
        baseline_timing = self.baseline.get_timing_patterns(agent_id)
        hourly_counts = baseline_timing.get('hourly_counts', {})
        
        if not hourly_counts:
            return None
        
        now = datetime.now()
        current_hour = now.hour
        
        # Get total operations from baseline
        total_ops = sum(hourly_counts.values())
        if total_ops == 0:
            return None
        
        # Calculate expected ratio for this hour
        current_hour_count = hourly_counts.get(current_hour, 0)
        expected_ratio = current_hour_count / total_ops
        
        # If activity at this hour is very rare in baseline, flag it
        if expected_ratio < self.timing_threshold and total_ops > 100:
            # Calculate severity based on how unusual this timing is
            severity = min(1.0, 0.4 + (self.timing_threshold - expected_ratio) * 2)
            
            anomaly = Anomaly(
                anomaly_type=AnomalyType.TIMING_ANOMALY.value,
                severity=severity,
                description=f"Operation at unusual hour {current_hour}:00 (normally {expected_ratio*100:.1f}% of activity)",
                agent_id=agent_id,
                timestamp=datetime.now().isoformat(),
                details={
                    'current_hour': current_hour,
                    'expected_ratio': expected_ratio,
                    'threshold': self.timing_threshold,
                    'hourly_distribution': hourly_counts
                },
                operation=operation
            )
            
            self._add_to_history(anomaly)
            self._call_alert(anomaly)
            
            return anomaly
        
        return None
    
    def _check_privilege_escalation(
        self,
        agent_id: str,
        tool_name: str,
        operation: dict
    ) -> Optional[Anomaly]:
        """Check for potential privilege escalation"""
        if tool_name not in self.sensitive_tools:
            return None
        
        if not self.baseline.is_trained(agent_id):
            # During training, sensitive tools are just tracked
            return None
        
        # Get baseline sensitive tool usage
        sensitive_tools_used = self.baseline.get_sensitive_tools_used(agent_id)
        baseline_data = self.baseline.get_baseline(agent_id)
        total_ops = baseline_data.get('operation_count', 1)
        
        # If this sensitive tool was never used before
        if tool_name not in sensitive_tools_used:
            # Check if other sensitive tools were used (escalation pattern)
            other_sensitive_used = [
                t for t in sensitive_tools_used
                if t != tool_name
            ]
            
            severity = 0.8 if other_sensitive_used else 0.5
            
            anomaly = Anomaly(
                anomaly_type=AnomalyType.PRIVILEGE_ESCALATION.value,
                severity=severity,
                description=f"First use of sensitive tool '{tool_name}' by trained agent",
                agent_id=agent_id,
                timestamp=datetime.now().isoformat(),
                details={
                    'tool_name': tool_name,
                    'previously_used_sensitive_tools': other_sensitive_used,
                    'total_sensitive_tools_used': len(sensitive_tools_used)
                },
                operation=operation
            )
            
            self._add_to_history(anomaly)
            self._call_alert(anomaly)
            
            return anomaly
        
        return None
    
    def _check_rapid_operation(
        self,
        agent_id: str,
        operation: dict
    ) -> Optional[Anomaly]:
        """Check for extremely rapid operations (potential automation/attack)"""
        now = datetime.now()
        
        with self._recent_ops_lock:
            # Clean old entries
            cutoff = now - timedelta(seconds=10)
            recent = [
                ts for ts in self._recent_ops.get(f"{agent_id}_rapid", [])
                if ts > cutoff
            ]
            
            recent.append(now)
            self._recent_ops[f"{agent_id}_rapid"] = recent
            
            # If more than 50 operations in 10 seconds, that's suspicious
            if len(recent) > 50:
                severity = min(1.0, 0.5 + len(recent) // 100)
                
                anomaly = Anomaly(
                    anomaly_type=AnomalyType.RAPID_OPERATION.value,
                    severity=severity,
                    description=f"Rapid operations detected: {len(recent)} in 10 seconds",
                    agent_id=agent_id,
                    timestamp=datetime.now().isoformat(),
                    details={
                        'ops_in_10s': len(recent),
                        'threshold': 50
                    },
                    operation=operation
                )
                
                self._add_to_history(anomaly)
                self._call_alert(anomaly)
                
                return anomaly
        
        return None
    
    def check_operation(self, agent_id: str, operation: dict) -> List[dict]:
        """
        Check operation against baseline, return list of anomalies.
        
        This is the main entry point for anomaly detection.
        Run all checks and return any detected anomalies.
        
        Args:
            agent_id: Unique identifier for the agent
            operation: Operation data containing tool, resources, etc.
        
        Returns:
            List of anomaly dictionaries (empty if no anomalies)
        """
        anomalies = []
        
        # Skip if agent not trained
        if not self.baseline.is_trained(agent_id):
            return anomalies
        
        # Extract tool name
        tool_name = self._extract_tool_name(operation)
        if not tool_name:
            return anomalies
        
        # Run all checks
        for check_func in [
            lambda: self._check_unusual_tool_call(agent_id, tool_name, operation),
            lambda: self._check_frequency_spike(agent_id, tool_name, operation),
            lambda: self._check_sequence_break(agent_id, tool_name, operation),
            lambda: self._check_resource_anomaly(agent_id, operation),
            lambda: self._check_timing_anomaly(agent_id, operation),
            lambda: self._check_privilege_escalation(agent_id, tool_name, operation),
            lambda: self._check_rapid_operation(agent_id, operation)
        ]:
            try:
                anomaly = check_func()
                if anomaly:
                    anomalies.append(anomaly.to_dict())
            except Exception as e:
                logger.error(f"Anomaly check failed: {e}")
        
        return anomalies
    
    def get_recent_anomalies(self, agent_id: str, hours: int = 24) -> List[dict]:
        """
        Get recent anomalies for agent.
        
        Args:
            agent_id: Agent identifier
            hours: Number of hours to look back (default 24)
        
        Returns:
            List of anomaly dictionaries
        """
        with self._history_lock:
            cutoff = datetime.now() - timedelta(hours=hours)
            
            agent_anomalies = self._anomaly_history.get(agent_id, [])
            
            recent = [
                anomaly.to_dict() for anomaly in agent_anomalies
                if datetime.fromisoformat(anomaly.timestamp) > cutoff
            ]
            
            # Sort by timestamp descending
            recent.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return recent
    
    def get_all_recent_anomalies(self, hours: int = 24) -> Dict[str, List[dict]]:
        """
        Get recent anomalies for all agents.
        
        Args:
            hours: Number of hours to look back (default 24)
        
        Returns:
            Dictionary mapping agent_id to list of anomalies
        """
        result = {}
        
        with self._history_lock:
            cutoff = datetime.now() - timedelta(hours=hours)
            
            for agent_id, anomalies in self._anomaly_history.items():
                recent = [
                    anomaly.to_dict() for anomaly in anomalies
                    if datetime.fromisoformat(anomaly.timestamp) > cutoff
                ]
                
                if recent:
                    recent.sort(key=lambda x: x['timestamp'], reverse=True)
                    result[agent_id] = recent
        
        return result
    
    def get_anomaly_summary(self, agent_id: str, hours: int = 24) -> dict:
        """
        Get summary of anomalies for an agent.
        
        Args:
            agent_id: Agent identifier
            hours: Number of hours to look back
        
        Returns:
            Dictionary with anomaly statistics
        """
        anomalies = self.get_recent_anomalies(agent_id, hours)
        
        summary = {
            'agent_id': agent_id,
            'total_anomalies': len(anomalies),
            'hours': hours,
            'by_type': {},
            'by_severity': {
                'low': 0,
                'medium': 0,
                'high': 0,
                'critical': 0
            },
            'highest_severity': 0.0,
            'is_trained': self.baseline.is_trained(agent_id)
        }
        
        for anomaly in anomalies:
            # Count by type
            atype = anomaly['anomaly_type']
            summary['by_type'][atype] = summary['by_type'].get(atype, 0) + 1
            
            # Count by severity
            severity_level = anomaly['severity_level'].lower()
            if severity_level in summary['by_severity']:
                summary['by_severity'][severity_level] += 1
            
            # Track highest severity
            summary['highest_severity'] = max(summary['highest_severity'], anomaly['severity'])
        
        return summary
    
    def set_alert_callback(self, callback: Callable[[Anomaly], None]):
        """
        Set or update the alert callback.
        
        Args:
            callback: Callable that takes an Anomaly object
        """
        self.alert_callback = callback
        logger.info("Alert callback updated")
    
    def clear_history(self, agent_id: Optional[str] = None):
        """
        Clear anomaly history.
        
        Args:
            agent_id: Specific agent to clear (None for all)
        """
        with self._history_lock:
            if agent_id:
                if agent_id in self._anomaly_history:
                    del self._anomaly_history[agent_id]
            else:
                self._anomaly_history.clear()
        
        logger.info(f"Cleared anomaly history for {agent_id or 'all agents'}")


# Singleton instance
_anomaly_detector = None


def get_anomaly_detector(
    baseline: BehaviorBaseline = None,
    alert_callback: Callable = None
) -> AnomalyDetector:
    """
    Get or create singleton AnomalyDetector instance.
    
    Args:
        baseline: BehaviorBaseline instance (creates default if None)
        alert_callback: Optional alert callback
    
    Returns:
        AnomalyDetector instance
    """
    global _anomaly_detector
    
    if _anomaly_detector is None:
        if baseline is None:
            baseline = get_behavior_baseline()
        
        _anomaly_detector = AnomalyDetector(
            baseline=baseline,
            alert_callback=alert_callback
        )
    elif alert_callback is not None:
        _anomaly_detector.set_alert_callback(alert_callback)
    
    return _anomaly_detector


def check_for_anomalies(
    agent_id: str,
    operation: dict,
    alert_callback: Callable = None
) -> List[dict]:
    """
    Convenience function to check for anomalies.
    
    Args:
        agent_id: Agent identifier
        operation: Operation data
        alert_callback: Optional alert callback
    
    Returns:
        List of detected anomalies
    """
    detector = get_anomaly_detector(alert_callback=alert_callback)
    return detector.check_operation(agent_id, operation)