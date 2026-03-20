"""
Picoclaw Telemetry Module - Stage 4: Real-Time Telemetry

This module provides real-time monitoring capabilities for AI agents:

- Heartbeat tracking and agent health monitoring
- Agent registry with metadata and search
- FastAPI dashboard with WebSocket support
- Multi-agent swarm detection
- Rule-based alert system

Example usage:

    from telemetry import HeartbeatManager, AgentRegistry, AlertEngine

    # Create components
    heartbeat = HeartbeatManager(storage_path="heartbeats.jsonl")
    registry = AgentRegistry(storage_path="agents.json")
    alerts = AlertEngine(storage_path="alerts.json")

    # Start heartbeat manager
    await heartbeat.start()

    # Register an agent
    await registry.register(
        agent_id="agent-001",
        name="Clawdia",
        platform="openai",
        owner="user@example.com",
        capabilities=["file_read", "shell_exec"],
    )

    # Record heartbeat
    await heartbeat.heartbeat("agent-001", status="online")

    # Check for alerts
    await alerts.check("agent-001", {"type": "file_access", "path": "/etc/passwd"})

    # Get active alerts
    critical_alerts = alerts.get_active_alerts(AlertSeverity.HIGH)
"""

from .heartbeat import (
    HeartbeatManager,
    HeartbeatManagerContext,
    HeartbeatRecord,
    AgentInfo,
    AgentStatus,
    HeartbeatError,
    AgentNotFoundError,
)

from .registry import (
    AgentRegistry,
    AgentRegistryContext,
    AgentMetadata,
    RegisteredAgent,
    AgentCapability,
    AgentPlatform,
    RegistryError,
    AgentAlreadyExistsError,
    AgentNotFoundError as RegistryNotFoundError,
)

from .dashboard import (
    app as dashboard_app,
    create_app as create_dashboard,
    DashboardState,
    get_state,
    broadcast_event,
)

from .swarm_detector import (
    SwarmDetector,
    DetectedSwarm,
    SwarmMember,
    AgentObservation,
    SwarmType,
    DetectionMethod,
    SwarmError,
)

from .alert_system import (
    AlertEngine,
    Alert,
    AlertRule,
    AlertSeverity,
    AlertStatus,
    AgentActivity,
    AlertError,
    RuleNotFoundError,
)

__all__ = [
    # Heartbeat
    "HeartbeatManager",
    "HeartbeatManagerContext",
    "HeartbeatRecord",
    "AgentInfo",
    "AgentStatus",
    "HeartbeatError",
    "AgentNotFoundError",

    # Registry
    "AgentRegistry",
    "AgentRegistryContext",
    "AgentMetadata",
    "RegisteredAgent",
    "AgentCapability",
    "AgentPlatform",
    "RegistryError",
    "AgentAlreadyExistsError",
    "RegistryNotFoundError",

    # Dashboard
    "dashboard_app",
    "create_dashboard",
    "DashboardState",
    "get_state",
    "broadcast_event",

    # Swarm Detector
    "SwarmDetector",
    "DetectedSwarm",
    "SwarmMember",
    "AgentObservation",
    "SwarmType",
    "DetectionMethod",
    "SwarmError",

    # Alert System
    "AlertEngine",
    "Alert",
    "AlertRule",
    "AlertSeverity",
    "AlertStatus",
    "AgentActivity",
    "AlertError",
    "RuleNotFoundError",
]

__version__ = "1.0.0"
__stage__ = "Stage 4: Real-Time Telemetry"