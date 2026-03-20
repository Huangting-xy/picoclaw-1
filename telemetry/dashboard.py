"""
Dashboard API - Real-time dashboard endpoints.

This module provides a FastAPI-based dashboard for monitoring
agents in real-time, with WebSocket support for live updates.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field


# =============================================================================
# Models
# =============================================================================


class AgentStatusResponse(BaseModel):
    """Response model for agent status."""
    agent_id: str
    status: str
    last_heartbeat: float
    seconds_since_heartbeat: float
    metadata: dict[str, Any] = Field(default_factory=dict)
    heartbeat_count: int = 0
    consecutive_failures: int = 0


class AgentDetailResponse(BaseModel):
    """Response model for detailed agent info."""
    agent_id: str
    registered_at: float
    last_heartbeat: float
    status: str
    metadata: dict[str, Any]
    total_heartbeats: int
    consecutive_failures: int
    is_stale: bool
    seconds_since_heartbeat: float


class HeartbeatHistoryResponse(BaseModel):
    """Response model for heartbeat history."""
    agent_id: str
    history: list[dict[str, Any]]
    total: int


class GlobalStatsResponse(BaseModel):
    """Response model for global statistics."""
    total_agents: int
    active_agents: int
    stale_agents: int
    by_platform: dict[str, int]
    by_owner: dict[str, int]
    by_status: dict[str, int]
    uptime_seconds: float


class WebSocketMessage(BaseModel):
    """WebSocket message model."""
    type: str
    data: dict[str, Any] | None = None
    timestamp: float = Field(default_factory=time.time)


# =============================================================================
# Connection Manager
# =============================================================================


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast a message to all connections."""
        async with self._lock:
            dead_connections = []
            for connection in self._connections:
                try:
                    await connection.send_json(message)
                except Exception:
                    dead_connections.append(connection)

            for conn in dead_connections:
                self._connections.remove(conn)

    async def send_to(self, websocket: WebSocket, message: dict[str, Any]) -> None:
        """Send a message to a specific connection."""
        try:
            await websocket.send_json(message)
        except Exception:
            await self.disconnect(websocket)


# =============================================================================
# Dashboard Application
# =============================================================================


@dataclass
class DashboardState:
    """Shared dashboard state."""
    heartbeat_manager: Any = None  # HeartbeatManager
    registry: Any = None  # AgentRegistry
    alert_engine: Any = None  # AlertEngine
    swarm_detector: Any = None  # SwarmDetector
    connection_manager: ConnectionManager = field(default_factory=ConnectionManager)
    start_time: float = field(default_factory=time.time)


# Global state
_state = DashboardState()


def get_state() -> DashboardState:
    """Get the dashboard state."""
    return _state


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    # Startup
    if _state.heartbeat_manager:
        await _state.heartbeat_manager.start()
    if _state.registry:
        await _state.registry.initialize()
    yield
    # Shutdown
    if _state.heartbeat_manager:
        await _state.heartbeat_manager.stop()


# Create FastAPI app
app = FastAPI(
    title="Picoclaw Telemetry Dashboard",
    description="Real-time telemetry dashboard for AI agent monitoring",
    version="1.0.0",
    lifespan=lifespan,
)


# =============================================================================
# API Endpoints
# =============================================================================


@app.get("/api/agents", response_model=list[AgentStatusResponse])
async def list_agents(
    status: str | None = None,
    include_stale: bool = False,
    limit: int = 100,
) -> list[AgentStatusResponse]:
    """
    List active agents.

    Args:
        status: Filter by status
        include_stale: Include stale agents
        limit: Maximum results

    Returns:
        List of agent statuses
    """
    state = get_state()

    if not state.heartbeat_manager:
        raise HTTPException(status_code=503, detail="Heartbeat manager not initialized")

    # Parse status filter
    status_filter = None
    if status:
        from .heartbeat import AgentStatus
        try:
            status_filter = {AgentStatus(s) for s in status.split(",")}
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    agents = state.heartbeat_manager.get_active_agents(
        status_filter=status_filter,
        include_stale=include_stale,
    )

    return [
        AgentStatusResponse(
            agent_id=agent.agent_id,
            status=agent.status.value,
            last_heartbeat=agent.last_heartbeat,
            seconds_since_heartbeat=agent.seconds_since_heartbeat,
            metadata=agent.metadata,
            heartbeat_count=agent.total_heartbeats,
            consecutive_failures=agent.consecutive_failures,
        )
        for agent in agents[:limit]
    ]


@app.get("/api/agents/{agent_id}", response_model=AgentDetailResponse)
async def get_agent(agent_id: str) -> AgentDetailResponse:
    """
    Get detailed information for an agent.

    Args:
        agent_id: Agent identifier

    Returns:
        Agent details
    """
    state = get_state()

    if not state.heartbeat_manager:
        raise HTTPException(status_code=503, detail="Heartbeat manager not initialized")

    try:
        agent = state.heartbeat_manager.get_agent_status(agent_id)
        return AgentDetailResponse(
            agent_id=agent.agent_id,
            registered_at=agent.registered_at,
            last_heartbeat=agent.last_heartbeat,
            status=agent.status.value,
            metadata=agent.metadata,
            total_heartbeats=agent.total_heartbeats,
            consecutive_failures=agent.consecutive_failures,
            is_stale=agent.is_stale(),
            seconds_since_heartbeat=agent.seconds_since_heartbeat,
        )
    except Exception:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")


@app.get("/api/agents/{agent_id}/history", response_model=HeartbeatHistoryResponse)
async def get_agent_history(
    agent_id: str,
    since: float | None = None,
    limit: int = 100,
) -> HeartbeatHistoryResponse:
    """
    Get heartbeat history for an agent.

    Args:
        agent_id: Agent identifier
        since: Unix timestamp to get heartbeats after
        limit: Maximum number of records

    Returns:
        Heartbeat history
    """
    state = get_state()

    if not state.heartbeat_manager:
        raise HTTPException(status_code=503, detail="Heartbeat manager not initialized")

    try:
        history = state.heartbeat_manager.get_heartbeat_history(
            agent_id=agent_id,
            since=since,
            limit=limit,
        )
        return HeartbeatHistoryResponse(
            agent_id=agent_id,
            history=[h.to_dict() for h in history],
            total=len(history),
        )
    except Exception:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")


@app.get("/api/stats", response_model=GlobalStatsResponse)
async def get_stats() -> GlobalStatsResponse:
    """
    Get global statistics.

    Returns:
        Global statistics
    """
    state = get_state()

    if not state.heartbeat_manager:
        raise HTTPException(status_code=503, detail="Heartbeat manager not initialized")

    # Get heartbeat stats
    hb_stats = state.heartbeat_manager.get_statistics()

    # Get registry stats
    registry_stats = {}
    if state.registry:
        registry_stats = state.registry.get_statistics()

    # Get alert stats
    alert_stats = {}
    if state.alert_engine:
        alert_stats = state.alert_engine.get_statistics()

    return GlobalStatsResponse(
        total_agents=hb_stats.get("total_agents", 0),
        active_agents=hb_stats.get("active_agents", 0),
        stale_agents=hb_stats.get("stale_agents", 0),
        by_platform=registry_stats.get("platforms", {}),
        by_owner=registry_stats.get("owners", {}),
        by_status=hb_stats.get("status_distribution", {}),
        uptime_seconds=time.time() - state.start_time,
    )


# =============================================================================
# WebSocket Endpoint
# =============================================================================


@app.websocket("/ws/agents")
async def websocket_agents(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for real-time agent updates.

    Sends events:
    - agent_registered: New agent registered
    - heartbeat: Agent heartbeat received
    - agent_pruned: Agent pruned due to staleness
    - alert: Alert triggered
    """
    state = get_state()
    manager = state.connection_manager

    await manager.connect(websocket)

    try:
        # Send initial state
        if state.heartbeat_manager:
            agents = state.heartbeat_manager.get_active_agents(include_stale=True)
            await manager.send_to(websocket, {
                "type": "initial_state",
                "data": {
                    "agents": [a.to_dict() for a in agents],
                    "stats": state.heartbeat_manager.get_statistics(),
                },
            })

        # Handle incoming messages
        while True:
            try:
                # Wait for messages (mostly for keep-alive)
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)

                # Parse and handle commands
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await manager.send_to(websocket, {"type": "pong"})
                    elif msg.get("type") == "subscribe":
                        # Client wants specific events
                        await manager.send_to(websocket, {
                            "type": "subscribed",
                            "data": {"events": msg.get("events", ["all"])},
                        })
                except json.JSONDecodeError:
                    pass

            except asyncio.TimeoutError:
                # Send heartbeat
                await manager.send_to(websocket, {"type": "heartbeat"})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        await manager.disconnect(websocket)


async def broadcast_event(event_type: str, data: dict[str, Any]) -> None:
    """Broadcast an event to all WebSocket clients."""
    state = get_state()
    await state.connection_manager.broadcast({
        "type": event_type,
        "data": data,
        "timestamp": time.time(),
    })


# =============================================================================
# Dashboard HTML
# =============================================================================


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Picoclaw Telemetry Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0f1419;
            color: #e6e9ed;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid #2c3e50;
            margin-bottom: 20px;
        }
        h1 {
            font-size: 24px;
            color: #1da1f2;
        }
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 500;
        }
        .status-badge.connected {
            background: #1e3a29;
            color: #2ecc71;
        }
        .status-badge.disconnected {
            background: #3a1e1e;
            color: #e74c3c;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: #1c2128;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #2c3e50;
        }
        .stat-card h3 {
            font-size: 14px;
            color: #8b949e;
            margin-bottom: 8px;
            text-transform: uppercase;
        }
        .stat-card .value {
            font-size: 32px;
            font-weight: bold;
            color: #e6e9ed;
        }
        .stat-card .change {
            font-size: 12px;
            color: #2ecc71;
            margin-top: 5px;
        }
        .agents-section {
            background: #1c2128;
            border-radius: 12px;
            border: 1px solid #2c3e50;
            overflow: hidden;
        }
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            background: #21262d;
            border-bottom: 1px solid #2c3e50;
        }
        .section-header h2 {
            font-size: 16px;
        }
        .filters {
            display: flex;
            gap: 10px;
        }
        .filters select, .filters input {
            background: #0f1419;
            border: 1px solid #2c3e50;
            color: #e6e9ed;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 14px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px 20px;
            text-align: left;
            border-bottom: 1px solid #2c3e50;
        }
        th {
            font-size: 12px;
            color: #8b949e;
            text-transform: uppercase;
            font-weight: 500;
        }
        td {
            font-size: 14px;
        }
        .agent-status {
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        .status-dot.online { background: #2ecc71; }
        .status-dot.busy { background: #f1c40f; }
        .status-dot.idle { background: #3498db; }
        .status-dot.error { background: #e74c3c; }
        .status-dot.offline { background: #7f8c8d; }
        .status-dot.unknown { background: #95a5a6; }
        .time-ago {
            color: #8b949e;
            font-size: 12px;
        }
        .error {
            color: #e74c3c;
            padding: 20px;
            text-align: center;
        }
        .agent-row:hover {
            background: #21262d;
        }
        .agent-row {
            cursor: pointer;
            transition: background 0.2s;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.7);
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }
        .modal.active {
            display: flex;
        }
        .modal-content {
            background: #1c2128;
            border-radius: 12px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow: auto;
        }
        .modal-header {
            padding: 20px;
            border-bottom: 1px solid #2c3e50;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-body {
            padding: 20px;
        }
        .close-btn {
            background: none;
            border: none;
            color: #8b949e;
            font-size: 24px;
            cursor: pointer;
        }
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
        }
        .detail-item label {
            display: block;
            font-size: 12px;
            color: #8b949e;
            margin-bottom: 4px;
        }
        .detail-item .value {
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Picoclaw Telemetry</h1>
            <div id="connection-status" class="status-badge disconnected">
                <span class="dot"></span>
                <span>Disconnected</span>
            </div>
        </header>

        <div class="stats-grid" id="stats">
            <div class="stat-card">
                <h3>Total Agents</h3>
                <div class="value" id="total-agents">-</div>
            </div>
            <div class="stat-card">
                <h3>Active Agents</h3>
                <div class="value" id="active-agents">-</div>
            </div>
            <div class="stat-card">
                <h3>Stale Agents</h3>
                <div class="value" id="stale-agents">-</div>
            </div>
            <div class="stat-card">
                <h3>Uptime</h3>
                <div class="value" id="uptime">-</div>
            </div>
        </div>

        <div class="agents-section">
            <div class="section-header">
                <h2>Agents</h2>
                <div class="filters">
                    <select id="status-filter">
                        <option value="">All Status</option>
                        <option value="online">Online</option>
                        <option value="busy">Busy</option>
                        <option value="idle">Idle</option>
                        <option value="error">Error</option>
                        <option value="offline">Offline</option>
                    </select>
                    <input type="text" id="search" placeholder="Search agents...">
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Agent ID</th>
                        <th>Status</th>
                        <th>Last Heartbeat</th>
                        <th>Platform</th>
                        <th>Owner</th>
                    </tr>
                </thead>
                <tbody id="agents-table">
                    <tr><td colspan="5" class="error">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="modal" id="agent-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modal-agent-id">Agent Details</h2>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body" id="modal-body">
            </div>
        </div>
    </div>

    <script>
        let ws = null;
        let agents = [];

        function connect() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws/agents`);

            ws.onopen = () => {
                document.getElementById('connection-status').className = 'status-badge connected';
                document.getElementById('connection-status').querySelector('span:last-child').textContent = 'Connected';
            };

            ws.onclose = () => {
                document.getElementById('connection-status').className = 'status-badge disconnected';
                document.getElementById('connection-status').querySelector('span:last-child').textContent = 'Disconnected';
                setTimeout(connect, 5000);
            };

            ws.onmessage = (event) => {
                const msg = JSON.parse(event.data);
                handleMessage(msg);
            };
        }

        function handleMessage(msg) {
            switch (msg.type) {
                case 'initial_state':
                    agents = msg.data.agents;
                    updateStats(msg.data.stats);
                    renderAgents();
                    break;
                case 'heartbeat':
                    updateAgentHeartbeat(msg.data);
                    break;
                case 'agent_registered':
                    addAgent(msg.data);
                    break;
                case 'agent_pruned':
                    removeAgent(msg.data.agent_id);
                    break;
            }
        }

        function updateStats(stats) {
            document.getElementById('total-agents').textContent = stats.total_agents || 0;
            document.getElementById('active-agents').textContent = stats.active_agents || 0;
            document.getElementById('stale-agents').textContent = stats.stale_agents || 0;
            if (stats.uptime_seconds) {
                const mins = Math.floor(stats.uptime_seconds / 60);
                document.getElementById('uptime').textContent = mins > 60 ? 
                    `${Math.floor(mins/60)}h ${mins%60}m` : `${mins}m`;
            }
        }

        function renderAgents() {
            const tbody = document.getElementById('agents-table');
            const statusFilter = document.getElementById('status-filter').value;
            const search = document.getElementById('search').value.toLowerCase();

            let filtered = agents.filter(a => {
                if (statusFilter && a.status !== statusFilter) return false;
                if (search && !a.agent_id.toLowerCase().includes(search)) return false;
                return true;
            });

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="error">No agents found</td></tr>';
                return;
            }

            tbody.innerHTML = filtered.map(a => `
                <tr class="agent-row" onclick="showAgent('${a.agent_id}')">
                    <td><code>${a.agent_id.substring(0, 12)}...</code></td>
                    <td>
                        <span class="agent-status">
                            <span class="status-dot ${a.status}"></span>
                            ${a.status}
                        </span>
                    </td>
                    <td><span class="time-ago">${formatTime(a.last_heartbeat)}</span></td>
                    <td>${a.metadata?.platform || '-'}</td>
                    <td>${a.metadata?.owner || '-'}</td>
                </tr>
            `).join('');
        }

        function formatTime(timestamp) {
            const diff = Date.now() / 1000 - timestamp;
            if (diff < 60) return `${Math.floor(diff)}s ago`;
            if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
            return `${Math.floor(diff/3600)}h ago`;
        }

        function updateAgentHeartbeat(data) {
            const idx = agents.findIndex(a => a.agent_id === data.agent_id);
            if (idx >= 0) {
                agents[idx].last_heartbeat = data.timestamp;
                agents[idx].status = data.status;
            }
            renderAgents();
        }

        function addAgent(data) {
            agents.push(data);
            renderAgents();
        }

        function removeAgent(agentId) {
            agents = agents.filter(a => a.agent_id !== agentId);
            renderAgents();
        }

        async function showAgent(agentId) {
            try {
                const resp = await fetch(`/api/agents/${agentId}`);
                const data = await resp.json();
                document.getElementById('modal-agent-id').textContent = data.agent_id;
                document.getElementById('modal-body').innerHTML = `
                    <div class="detail-grid">
                        <div class="detail-item">
                            <label>Status</label>
                            <div class="value">${data.status}</div>
                        </div>
                        <div class="detail-item">
                            <label>Last Heartbeat</label>
                            <div class="value">${formatTime(data.last_heartbeat)}</div>
                        </div>
                        <div class="detail-item">
                            <label>Registered</label>
                            <div class="value">${new Date(data.registered_at * 1000).toLocaleString()}</div>
                        </div>
                        <div class="detail-item">
                            <label>Total Heartbeats</label>
                            <div class="value">${data.total_heartbeats}</div>
                        </div>
                        <div class="detail-item">
                            <label>Failures</label>
                            <div class="value">${data.consecutive_failures}</div>
                        </div>
                        <div class="detail-item">
                            <label>Is Stale</label>
                            <div class="value">${data.is_stale ? 'Yes' : 'No'}</div>
                        </div>
                    </div>
                    <h3 style="margin-top: 20px;">Metadata</h3>
                    <pre style="background: #0f1419; padding: 10px; border-radius: 6px; overflow: auto;">${JSON.stringify(data.metadata, null, 2)}</pre>
                `;
                document.getElementById('agent-modal').classList.add('active');
            } catch (e) {
                console.error('Failed to load agent:', e);
            }
        }

        function closeModal() {
            document.getElementById('agent-modal').classList.remove('active');
        }

        document.getElementById('status-filter').addEventListener('change', renderAgents);
        document.getElementById('search').addEventListener('input', renderAgents);
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
        });

        connect();
        setInterval(() => {
            fetch('/api/stats').then(r => r.json()).then(updateStats);
            fetch('/api/agents').then(r => r.json()).then(data => {
                agents = data;
                renderAgents();
            });
        }, 30000);
    </script>
</body>
</html>
"""


@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard() -> HTMLResponse:
    """Serve the dashboard HTML."""
    return HTMLResponse(content=DASHBOARD_HTML)


# =============================================================================
# Factory Function
# =============================================================================


def create_app(
    heartbeat_manager: Any = None,
    registry: Any = None,
    alert_engine: Any = None,
    swarm_detector: Any = None,
) -> FastAPI:
    """
    Create a FastAPI application with the dashboard.

    Args:
        heartbeat_manager: HeartbeatManager instance
        registry: AgentRegistry instance
        alert_engine: AlertEngine instance
        swarm_detector: SwarmDetector instance

    Returns:
        FastAPI application
    """
    _state.heartbeat_manager = heartbeat_manager
    _state.registry = registry
    _state.alert_engine = alert_engine
    _state.swarm_detector = swarm_detector
    _state.start_time = time.time()
    return app