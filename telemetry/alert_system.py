"""
Alert System - Alert Engine for suspicious activity detection.

This module provides a rule-based alert engine for triggering
warnings on suspicious agent activity.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Self

import aiofiles


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status."""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class AlertError(Exception):
    """Base exception for alert errors."""
    pass


class RuleNotFoundError(AlertError):
    """Alert rule not found."""
    pass


@dataclass
class AlertRule:
    """Rule for triggering alerts."""
    name: str
    description: str
    condition: Callable[[str, dict[str, Any]], bool]
    severity: AlertSeverity = AlertSeverity.MEDIUM
    enabled: bool = True
    cooldown: float = 300.0  # Seconds between same alert
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (without condition)."""
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "enabled": self.enabled,
            "cooldown": self.cooldown,
            "tags": self.tags,
            "metadata": self.metadata,
        }


@dataclass
class Alert:
    """Triggered alert."""
    alert_id: str
    rule_name: str
    agent_id: str
    timestamp: float
    severity: AlertSeverity
    message: str
    status: AlertStatus = AlertStatus.ACTIVE
    event: dict[str, Any] = field(default_factory=dict)
    acknowledged_by: str | None = None
    acknowledged_at: float | None = None
    resolved_at: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "rule_name": self.rule_name,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "severity": self.severity.value,
            "message": self.message,
            "status": self.status.value,
            "event": self.event,
            "acknowledged_by": self.acknowledged_by,
            "acknowledged_at": self.acknowledged_at,
            "resolved_at": self.resolved_at,
            "metadata": self.metadata,
        }


@dataclass
class AgentActivity:
    """Tracks agent activity for analysis."""
    agent_id: str
    events: list[dict[str, Any]] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)
    file_accesses: list[str] = field(default_factory=list)
    privilege_changes: list[dict[str, Any]] = field(default_factory=list)
    network_connections: list[str] = field(default_factory=list)
    command_history: list[str] = field(default_factory=list)
    error_count: int = 0

    def add_event(self, event: dict[str, Any]) -> None:
        """Add an event to history."""
        self.events.append({"timestamp": time.time(), **event})
        self.last_seen = time.time()
        # Keep last 1000 events
        if len(self.events) > 1000:
            self.events = self.events[-1000:]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_id": self.agent_id,
            "events": self.events[-100:],
            "last_seen": self.last_seen,
            "file_accesses": self.file_accesses[-50:],
            "privilege_changes": self.privilege_changes,
            "network_connections": self.network_connections[-50:],
            "command_history": self.command_history[-50:],
            "error_count": self.error_count,
        }


class AlertEngine:
    """
    Rule-based alert engine for suspicious activity detection.

    Features:
    - Custom alert rules with conditions
    - Per-agent activity tracking
    - Alert lifecycle (active/acknowledged/resolved)
    - Cooldown periods to avoid spam
    - Persistence to file
    """

    # Pre-defined rule names
    RULE_PRIVILEGE_ESCALATION = "privilege_escalation"
    RULE_UNUSUAL_FILE_ACCESS = "unusual_file_access"
    RULE_SUSPICIOUS_NETWORK = "suspicious_network"
    RULE_RAPID_COMMANDS = "rapid_commands"
    RULE_HIGH_ERROR_RATE = "high_error_rate"
    RULE_UNUSUAL_TIMING = "unusual_timing"
    RULE_SWARM_DETECTED = "swarm_detected"
    RULE_LONG_RUNNING = "long_running"
    RULE_OFFLINE_AGENT = "offline_agent"
    RULE_SUSPICIOUS_METADATA = "suspicious_metadata"

    def __init__(
        self,
        storage_path: str | None = None,
        default_cooldown: float = 300.0,
    ):
        """
        Initialize alert engine.

        Args:
            storage_path: Path to store alerts
            default_cooldown: Default cooldown between same alerts
        """
        self._rules: dict[str, AlertRule] = {}
        self._alerts: dict[str, Alert] = {}
        self._agent_activities: dict[str, AgentActivity] = {}
        self._last_alert_time: dict[str, float] = {}  # rule:agent -> timestamp
        self._storage_path = storage_path
        self._default_cooldown = default_cooldown
        self._lock = asyncio.Lock()
        self._subscribers: list[Callable[[Alert], None]] = []

        # Initialize default rules
        self._init_default_rules()

    def _init_default_rules(self) -> None:
        """Initialize pre-defined alert rules."""

        # Privilege escalation
        self.add_rule(
            name=self.RULE_PRIVILEGE_ESCALATION,
            description="Agent gained elevated privileges",
            severity=AlertSeverity.HIGH,
            tags=["security", "privileges"],
            cooldown=60.0,
        )

        # Unusual file access
        self.add_rule(
            name=self.RULE_UNUSUAL_FILE_ACCESS,
            description="Agent accessed sensitive files",
            severity=AlertSeverity.MEDIUM,
            tags=["security", "files"],
            cooldown=120.0,
        )

        # Suspicious network activity
        self.add_rule(
            name=self.RULE_SUSPICIOUS_NETWORK,
            description="Agent made suspicious network connections",
            severity=AlertSeverity.HIGH,
            tags=["security", "network"],
            cooldown=60.0,
        )

        # Rapid commands
        self.add_rule(
            name=self.RULE_RAPID_COMMANDS,
            description="Agent executing commands at unusual rate",
            severity=AlertSeverity.MEDIUM,
            tags=["behavior", "commands"],
            cooldown=300.0,
        )

        # High error rate
        self.add_rule(
            name=self.RULE_HIGH_ERROR_RATE,
            description="Agent has high error rate",
            severity=AlertSeverity.LOW,
            tags=["health", "errors"],
            cooldown=600.0,
        )

        # Unusual timing
        self.add_rule(
            name=self.RULE_UNUSUAL_TIMING,
            description="Agent active at unusual times",
            severity=AlertSeverity.LOW,
            tags=["behavior", "timing"],
            cooldown=3600.0,
        )

        # Swarm detected
        self.add_rule(
            name=self.RULE_SWARM_DETECTED,
            description="Multiple agents acting as a swarm",
            severity=AlertSeverity.HIGH,
            tags=["security", "swarm"],
            cooldown=300.0,
        )

        # Long running
        self.add_rule(
            name=self.RULE_LONG_RUNNING,
            description="Agent running unusually long",
            severity=AlertSeverity.LOW,
            tags=["health", "performance"],
            cooldown=3600.0,
        )

        # Offline agent
        self.add_rule(
            name=self.RULE_OFFLINE_AGENT,
            description="Agent went offline unexpectedly",
            severity=AlertSeverity.MEDIUM,
            tags=["health", "availability"],
            cooldown=60.0,
        )

        # Suspicious metadata
        self.add_rule(
            name=self.RULE_SUSPICIOUS_METADATA,
            description="Agent has suspicious metadata",
            severity=AlertSeverity.MEDIUM,
            tags=["security", "metadata"],
            cooldown=300.0,
        )

    def add_rule(
        self,
        name: str,
        description: str = "",
        condition: Callable[[str, dict[str, Any]], bool] | None = None,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        enabled: bool = True,
        cooldown: float | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AlertRule:
        """
        Add an alert rule.

        Args:
            name: Rule name
            description: Rule description
            condition: Optional condition function (agent_id, event) -> bool
            severity: Alert severity
            enabled: Whether rule is enabled
            cooldown: Cooldown between same alerts
            tags: Tags for rule
            metadata: Additional metadata

        Returns:
            The created rule
        """
        rule = AlertRule(
            name=name,
            description=description,
            condition=condition or (lambda aid, evt: True),
            severity=severity,
            enabled=enabled,
            cooldown=cooldown or self._default_cooldown,
            tags=tags or [],
            metadata=metadata or {},
        )
        self._rules[name] = rule
        return rule

    def remove_rule(self, name: str) -> bool:
        """
        Remove an alert rule.

        Args:
            name: Rule name

        Returns:
            True if rule was removed
        """
        if name in self._rules:
            del self._rules[name]
            return True
        return False

    def get_rule(self, name: str) -> AlertRule:
        """
        Get an alert rule.

        Args:
            name: Rule name

        Returns:
            The rule

        Raises:
            RuleNotFoundError: If rule not found
        """
        if name not in self._rules:
            raise RuleNotFoundError(f"Rule not found: {name}")
        return self._rules[name]

    async def check(
        self,
        agent_id: str,
        event: dict[str, Any],
        event_type: str | None = None,
    ) -> list[Alert]:
        """
        Check an event against all rules.

        Args:
            agent_id: Agent identifier
            event: Event data
            event_type: Optional event type for filtering

        Returns:
            List of triggered alerts
        """
        alerts = []
        now = time.time()

        # Update activity tracking
        await self._track_activity(agent_id, event)

        async with self._lock:
            for rule_name, rule in self._rules.items():
                if not rule.enabled:
                    continue

                # Check cooldown
                cooldown_key = f"{rule_name}:{agent_id}"
                if cooldown_key in self._last_alert_time:
                    if now - self._last_alert_time[cooldown_key] < rule.cooldown:
                        continue

                # Check condition
                try:
                    should_alert = self._evaluate_rule(rule, agent_id, event)

                    if should_alert:
                        # Create alert
                        alert = await self._create_alert(
                            rule=rule,
                            agent_id=agent_id,
                            event=event,
                        )

                        # Update cooldown
                        self._last_alert_time[cooldown_key] = now

                        alerts.append(alert)

                except Exception as e:
                    # Log error but continue
                    print(f"Error evaluating rule {rule_name}: {e}")
                    continue

        # Notify subscribers
        for alert in alerts:
            await self._notify_subscribers(alert)

        return alerts

    def _evaluate_rule(
        self,
        rule: AlertRule,
        agent_id: str,
        event: dict[str, Any],
    ) -> bool:
        """Evaluate if a rule should trigger."""
        # Use custom condition if provided
        if rule.condition:
            try:
                return rule.condition(agent_id, event)
            except Exception:
                return False

        # Default evaluations based on rule name
        if rule.name == self.RULE_PRIVILEGE_ESCALATION:
            return self._check_privilege_escalation(agent_id, event)

        elif rule.name == self.RULE_UNUSUAL_FILE_ACCESS:
            return self._check_unusual_file_access(agent_id, event)

        elif rule.name == self.RULE_SUSPICIOUS_NETWORK:
            return self._check_suspicious_network(agent_id, event)

        elif rule.name == self.RULE_RAPID_COMMANDS:
            return self._check_rapid_commands(agent_id, event)

        elif rule.name == self.RULE_HIGH_ERROR_RATE:
            return self._check_high_error_rate(agent_id, event)

        elif rule.name == self.RULE_UNUSUAL_TIMING:
            return self._check_unusual_timing(agent_id, event)

        elif rule.name == self.RULE_SWARM_DETECTED:
            return self._check_swarm_detected(agent_id, event)

        elif rule.name == self.RULE_LONG_RUNNING:
            return self._check_long_running(agent_id, event)

        elif rule.name == self.RULE_OFFLINE_AGENT:
            return self._check_offline_agent(agent_id, event)

        elif rule.name == self.RULE_SUSPICIOUS_METADATA:
            return self._check_suspicious_metadata(agent_id, event)

        return False

    async def _track_activity(
        self,
        agent_id: str,
        event: dict[str, Any],
    ) -> None:
        """Track agent activity."""
        if agent_id not in self._agent_activities:
            self._agent_activities[agent_id] = AgentActivity(agent_id=agent_id)

        activity = self._agent_activities[agent_id]
        activity.add_event(event)

        # Track specific activity types
        event_type = event.get("type", "")
        if event_type == "file_access":
            path = event.get("path", "")
            if path:
                activity.file_accesses.append(path)
                if len(activity.file_accesses) > 50:
                    activity.file_accesses = activity.file_accesses[-50:]

        elif event_type == "privilege_change":
            activity.privilege_changes.append(event)

        elif event_type == "network":
            dest = event.get("destination", "")
            if dest:
                activity.network_connections.append(dest)
                if len(activity.network_connections) > 50:
                    activity.network_connections = activity.network_connections[-50:]

        elif event_type == "command":
            cmd = event.get("command", "")
            if cmd:
                activity.command_history.append(cmd)
                if len(activity.command_history) > 50:
                    activity.command_history = activity.command_history[-50:]

        elif event_type == "error":
            activity.error_count += 1

    async def _create_alert(
        self,
        rule: AlertRule,
        agent_id: str,
        event: dict[str, Any],
    ) -> Alert:
        """Create an alert from a rule match."""
        alert_id = self._generate_alert_id(rule.name, agent_id)

        message = f"Rule '{rule.name}' triggered for agent {agent_id}"
        if rule.description:
            message = rule.description

        alert = Alert(
            alert_id=alert_id,
            rule_name=rule.name,
            agent_id=agent_id,
            timestamp=time.time(),
            severity=rule.severity,
            message=message,
            event=event,
        )

        self._alerts[alert_id] = alert
        return alert

    def _generate_alert_id(self, rule_name: str, agent_id: str) -> str:
        """Generate a unique alert ID."""
        data = f"{rule_name}:{agent_id}:{time.time()}"
        return "alert_" + hashlib.md5(data.encode()).hexdigest()[:12]

    # Default rule implementations

    def _check_privilege_escalation(
        self,
        agent_id: str,
        event: dict[str, Any],
    ) -> bool:
        """Check for privilege escalation."""
        if event.get("type") != "privilege_change":
            return False

        old_level = event.get("old_level", 0)
        new_level = event.get("new_level", 0)

        # Privilege increased
        if new_level > old_level:
            # Check if increase is significant (e.g., 2+ levels)
            if new_level - old_level >= 2:
                return True
            # Root/admin level access
            if new_level >= 3:  # Assuming 3 is admin level
                return True

        return False

    def _check_unusual_file_access(
        self,
        agent_id: str,
        event: dict[str, Any],
    ) -> bool:
        """Check for unusual file access."""
        if event.get("type") not in ("file_access", "file_read", "file_write"):
            return False

        path = event.get("path", "").lower()

        # Sensitive paths
        sensitive_patterns = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/ssh/",
            ".ssh/",
            ".private",
            "credentials",
            "secrets",
            ".env",
            "private_key",
        ]

        for pattern in sensitive_patterns:
            if pattern in path:
                return True

        # Check activity history
        if agent_id in self._agent_activities:
            activity = self._agent_activities[agent_id]
            # Many different file accesses
            unique_files = len(set(activity.file_accesses))
            if unique_files > 50:
                return True

        return False

    def _check_suspicious_network(
        self,
        agent_id: str,
        event: dict[str, Any],
    ) -> bool:
        """Check for suspicious network activity."""
        if event.get("type") != "network":
            return False

        dest = event.get("destination", "")
        port = event.get("port", 0)

        # Suspicious destinations
        suspicious_domains = [
            ".onion",
            "pastebin.com",
            "webhook.site",
        ]

        for domain in suspicious_domains:
            if domain in dest:
                return True

        # Suspicious ports
        suspicious_ports = [
            (4444, 4444),  # Metasploit default
            (1337, 1338),  # Common backdoor ports
            (6667, 6669),  # IRC (often used by botnets)
        ]

        for start, end in suspicious_ports:
            if start <= port <= end:
                return True

        # Check activity history
        if agent_id in self._agent_activities:
            activity = self._agent_activities[agent_id]
            # Many different network connections
            if len(activity.network_connections) > 20:
                return True

        return False

    def _check_rapid_commands(
        self,
        agent_id: str,
        event: dict[str, Any],
    ) -> bool:
        """Check for rapid command execution."""
        if event.get("type") != "command":
            return False

        if agent_id not in self._agent_activities:
            return False

        activity = self._agent_activities[agent_id]
        commands = activity.command_history

        if len(commands) < 5:
            return False

        # Check commands in last minute
        now = time.time()
        recent_events = [
            e for e in activity.events
            if e.get("type") == "command" and now - e.get("timestamp", 0) < 60
        ]

        # More than 20 commands per minute is suspicious
        return len(recent_events) > 20

    def _check_high_error_rate(
        self,
        agent_id: str,
        event: dict[str, Any],
    ) -> bool:
        """Check for high error rate."""
        # Need to check total operations vs errors
        if agent_id not in self._agent_activities:
            return False

        activity = self._agent_activities[agent_id]
        error_count = activity.error_count
        total_events = len(activity.events)

        if total_events < 10:
            return False

        # More than 30% error rate
        error_rate = error_count / total_events
        return error_rate > 0.3

    def _check_unusual_timing(
        self,
        agent_id: str,
        event: dict[str, Any],
    ) -> bool:
        """Check for unusual timing patterns."""
        # Check if activity is at unusual hours (e.g., 2-5 AM)
        hour = datetime.now().hour
        return 2 <= hour <= 5

    def _check_swarm_detected(
        self,
        agent_id: str,
        event: dict[str, Any],
    ) -> bool:
        """Check if agent is part of a detected swarm."""
        return event.get("type") == "swarm_detected"

    def _check_long_running(
        self,
        agent_id: str,
        event: dict[str, Any],
    ) -> bool:
        """Check if agent has been running for unusually long."""
        # Agent running for more than 24 hours
        if agent_id not in self._agent_activities:
            return False

        activity = self._agent_activities[agent_id]
        first_event_time = activity.events[0].get("timestamp", time.time()) if activity.events else time.time()

        return (time.time() - first_event_time) > 86400  # 24 hours

    def _check_offline_agent(
        self,
        agent_id: str,
        event: dict[str, Any],
    ) -> bool:
        """Check if agent went offline unexpectedly."""
        return event.get("type") == "agent_offline" and event.get("unexpected", False)

    def _check_suspicious_metadata(
        self,
        agent_id: str,
        event: dict[str, Any],
    ) -> bool:
        """Check for suspicious metadata."""
        if event.get("type") != "metadata_update":
            return False

        metadata = event.get("metadata", {})

        # Suspicious patterns in metadata
        suspicious_keywords = [
            "malware",
            "backdoor",
            "exploit",
            "payload",
            "shell",
            "attack",
        ]

        metadata_str = json.dumps(metadata).lower()
        for keyword in suspicious_keywords:
            if keyword in metadata_str:
                return True

        return False

    def get_alert(self, alert_id: str) -> Alert | None:
        """Get an alert by ID."""
        return self._alerts.get(alert_id)

    def get_alerts(
        self,
        agent_id: str | None = None,
        severity: AlertSeverity | None = None,
        status: AlertStatus | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[Alert]:
        """
        Get alerts with optional filtering.

        Args:
            agent_id: Filter by agent
            severity: Filter by severity
            status: Filter by status
            since: Filter by timestamp
            limit: Maximum results

        Returns:
            List of matching alerts
        """
        alerts = list(self._alerts.values())

        if agent_id:
            alerts = [a for a in alerts if a.agent_id == agent_id]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if status:
            alerts = [a for a in alerts if a.status == status]
        if since:
            alerts = [a for a in alerts if a.timestamp >= since]

        # Sort by timestamp (newest first)
        alerts.sort(key=lambda a: a.timestamp, reverse=True)

        return alerts[:limit]

    def get_active_alerts(
        self,
        severity_threshold: AlertSeverity = AlertSeverity.HIGH,
    ) -> list[Alert]:
        """
        Get all active critical/high alerts.

        Args:
            severity_threshold: Minimum severity to include

        Returns:
            List of active alerts
        """
        severity_order = {
            AlertSeverity.INFO: 0,
            AlertSeverity.LOW: 1,
            AlertSeverity.MEDIUM: 2,
            AlertSeverity.HIGH: 3,
            AlertSeverity.CRITICAL: 4,
        }

        threshold = severity_order.get(severity_threshold, 2)

        return [
            alert for alert in self._alerts.values()
            if alert.status == AlertStatus.ACTIVE
            and severity_order.get(alert.severity, 0) >= threshold
        ]

    async def acknowledge_alert(
        self,
        alert_id: str,
        acknowledged_by: str,
    ) -> Alert:
        """
        Acknowledge an alert.

        Args:
            alert_id: Alert identifier
            acknowledged_by: Who acknowledged it

        Returns:
            Updated alert

        Raises:
            KeyError: If alert not found
        """
        async with self._lock:
            if alert_id not in self._alerts:
                raise KeyError(f"Alert not found: {alert_id}")

            alert = self._alerts[alert_id]
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_by = acknowledged_by
            alert.acknowledged_at = time.time()

            return alert

    async def resolve_alert(self, alert_id: str) -> Alert:
        """
        Resolve an alert.

        Args:
            alert_id: Alert identifier

        Returns:
            Updated alert

        Raises:
            KeyError: If alert not found
        """
        async with self._lock:
            if alert_id not in self._alerts:
                raise KeyError(f"Alert not found: {alert_id}")

            alert = self._alerts[alert_id]
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = time.time()

            return alert

    async def dismiss_alert(self, alert_id: str) -> Alert:
        """
        Dismiss an alert.

        Args:
            alert_id: Alert identifier

        Returns:
            Updated alert

        Raises:
            KeyError: If alert not found
        """
        async with self._lock:
            if alert_id not in self._alerts:
                raise KeyError(f"Alert not found: {alert_id}")

            alert = self._alerts[alert_id]
            alert.status = AlertStatus.DISMISSED
            return alert

    def subscribe(self, callback: Callable[[Alert], None]) -> None:
        """Subscribe to alert notifications."""
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[Alert], None]) -> None:
        """Unsubscribe from alert notifications."""
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    async def _notify_subscribers(self, alert: Alert) -> None:
        """Notify all subscribers of an alert."""
        for callback in self._subscribers:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert)
                else:
                    callback(alert)
            except Exception as e:
                print(f"Error notifying subscriber: {e}")

    def get_agent_activity(self, agent_id: str) -> AgentActivity | None:
        """Get activity data for an agent."""
        return self._agent_activities.get(agent_id)

    def get_statistics(self) -> dict[str, Any]:
        """Get alert statistics."""
        status_counts: dict[str, int] = defaultdict(int)
        severity_counts: dict[str, int] = defaultdict(int)
        rule_counts: dict[str, int] = defaultdict(int)

        for alert in self._alerts.values():
            status_counts[alert.status.value] += 1
            severity_counts[alert.severity.value] += 1
            rule_counts[alert.rule_name] += 1

        return {
            "total_alerts": len(self._alerts),
            "total_rules": len(self._rules),
            "enabled_rules": sum(1 for r in self._rules.values() if r.enabled),
            "by_status": dict(status_counts),
            "by_severity": dict(severity_counts),
            "by_rule": dict(rule_counts),
            "tracked_agents": len(self._agent_activities),
        }

    async def save_to_file(self, path: str | None = None) -> None:
        """Save alerts to file."""
        file_path = path or self._storage_path
        if not file_path:
            return

        data = {
            "alerts": [a.to_dict() for a in self._alerts.values()],
            "rules": [r.to_dict() for r in self._rules.values()],
            "timestamp": time.time(),
        }

        async with aiofiles.open(file_path, "w") as f:
            await f.write(json.dumps(data, indent=2))

    async def load_from_file(self, path: str | None = None) -> None:
        """Load alerts from file."""
        file_path = path or self._storage_path
        if not file_path:
            return

        try:
            async with aiofiles.open(file_path, "r") as f:
                content = await f.read()
                data = json.loads(content)

            for alert_data in data.get("alerts", []):
                alert = Alert(
                    alert_id=alert_data["alert_id"],
                    rule_name=alert_data["rule_name"],
                    agent_id=alert_data["agent_id"],
                    timestamp=alert_data["timestamp"],
                    severity=AlertSeverity(alert_data.get("severity", "medium")),
                    message=alert_data.get("message", ""),
                    status=AlertStatus(alert_data.get("status", "active")),
                    event=alert_data.get("event", {}),
                )
                self._alerts[alert.alert_id] = alert

        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            print(f"Error loading alerts: {e}")

    def prune_old_alerts(self, max_age: float = 86400.0) -> int:
        """
        Remove alerts older than max_age.

        Args:
            max_age: Maximum age in seconds

        Returns:
            Number of pruned alerts
        """
        now = time.time()
        to_remove = [
            alert_id
            for alert_id, alert in self._alerts.items()
            if (now - alert.timestamp) > max_age
            and alert.status in (AlertStatus.RESOLVED, AlertStatus.DISMISSED)
        ]

        for alert_id in to_remove:
            del self._alerts[alert_id]

        return len(to_remove)

    def prune_agent_activities(self, max_age: float = 3600.0) -> int:
        """
        Remove agent activities older than max_age.

        Args:
            max_age: Maximum age in seconds

        Returns:
            Number of pruned agents
        """
        now = time.time()
        to_remove = [
            agent_id
            for agent_id, activity in self._agent_activities.items()
            if (now - activity.last_seen) > max_age
        ]

        for agent_id in to_remove:
            del self._agent_activities[agent_id]

        return len(to_remove)