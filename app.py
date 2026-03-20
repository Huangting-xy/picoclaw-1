#!/usr/bin/env python3
"""
Picoclaw - Minimal OpenClaw Gateway for CogniWatch Sentinel
Listens on port 18789 for WebSocket connections from CogniWatch

Security Hardening Stage 1.1:
- Token-based authentication for API endpoints
- Container isolation for tool execution
- Encrypted secret management
"""

from flask import Flask, jsonify, request, g
from flask_sock import Sock
import json
import sqlite3
import os
from datetime import datetime
import threading
import time
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import security modules
try:
    from security import (
        get_container_isolation,
        get_secret, set_secret, delete_secret,
        get_token_manager, require_auth, optional_auth
    )
    SECURITY_ENABLED = True
    logger.info("Security modules loaded successfully")
except ImportError as e:
    logger.warning(f"Security modules not available: {e}")
    SECURITY_ENABLED = False
    
    # Fallback: create dummy decorator
    def require_auth(f):
        return f
    def optional_auth(f):
        return f

app = Flask(__name__)
sock = Sock(app)

# Database path
DB_PATH = os.environ.get('PICOCLAW_DB', '/home/cogniwatch/data/picoclaw.db')

# Connected clients
clients = []

def init_db():
    """Initialize the Picoclaw database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source TEXT,
        event_type TEXT,
        data JSON
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT UNIQUE,
        name TEXT,
        registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        severity TEXT,
        source TEXT,
        message TEXT,
        data JSON
    )''')
    conn.commit()
    conn.close()
    
    # Initialize auth tokens table if security module is available
    if SECURITY_ENABLED:
        try:
            get_token_manager()
            logger.info("Auth tokens table initialized")
        except Exception as e:
            logger.error(f"Failed to initialize auth tokens table: {e}")

def log_event(source, event_type, data):
    """Log an event to the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('INSERT INTO events (source, event_type, data) VALUES (?, ?, ?)',
                  (source, event_type, json.dumps(data)))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error logging event: {e}")

def broadcast(message):
    """Broadcast a message to all connected clients"""
    for client in clients:
        try:
            client.send(json.dumps(message))
        except:
            clients.remove(client)

# Tool execution with container isolation
def execute_tool(command: str, files: dict = None, timeout: int = 120):
    """
    Execute a tool command in an isolated container.
    
    Args:
        command: The command to execute
        files: Optional dictionary of files to create in workspace
        timeout: Execution timeout in seconds
    
    Returns:
        Execution result dictionary
    """
    if not SECURITY_ENABLED:
        logger.warning("Container isolation not available, tool execution disabled")
        return {
            'success': False,
            'error': 'Container isolation not available'
        }
    
    try:
        container = get_container_isolation()
        result = container.execute(
            command=command,
            files=files,
            timeout=timeout
        )
        
        return {
            'success': result.success,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'exit_code': result.exit_code,
            'duration_ms': result.duration_ms,
            'container_id': result.container_id
        }
    except Exception as e:
        logger.error(f"Tool execution error: {e}")
        return {
            'success': False,
            'error': str(e)
        }

# REST API Endpoints
@app.route('/')
def index():
    return jsonify({
        "name": "Picoclaw Gateway",
        "version": "0.1.1",
        "status": "running",
        "connected_clients": len(clients),
        "security_enabled": SECURITY_ENABLED,
        "endpoints": ["/health", "/api/status", "/api/events", "/api/devices", 
                       "/api/alerts", "/api/tokens", "/api/tools/execute", "/ws"]
    })

@app.route('/health')
def health():
    """Health check endpoint - no auth required"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "security": {
            "enabled": SECURITY_ENABLED,
            "container_isolation": False,
            "token_auth": False
        }
    }
    
    if SECURITY_ENABLED:
        try:
            container = get_container_isolation()
            health_status["security"]["container_isolation"] = container.health_check().get('healthy', False)
        except Exception as e:
            logger.warning(f"Container isolation health check failed: {e}")
        
        try:
            get_token_manager()
            health_status["security"]["token_auth"] = True
        except Exception as e:
            logger.warning(f"Token auth health check failed: {e}")
    
    return jsonify(health_status)

# Token management endpoints
@app.route('/api/tokens', methods=['GET'])
@require_auth
def list_tokens():
    """List all authentication tokens"""
    if not SECURITY_ENABLED:
        return jsonify({"error": "Security module not available"}), 503
    
    include_inactive = request.args.get('include_inactive', 'false').lower() == 'true'
    tokens = get_token_manager().list_tokens(include_inactive=include_inactive)
    return jsonify({"tokens": tokens})

@app.route('/api/tokens', methods=['POST'])
def create_token():
    """Create a new authentication token"""
    if not SECURITY_ENABLED:
        return jsonify({"error": "Security module not available"}), 503
    
    data = request.json or {}
    name = data.get('name')
    expiry_hours = data.get('expiry_hours', 24 * 7)  # Default 7 days
    
    token = get_token_manager().create_token(name=name, expiry_hours=expiry_hours)
    return jsonify({
        "status": "created",
        "token": token,
        "name": name
    }), 201

@app.route('/api/tokens/<token>', methods=['DELETE'])
@require_auth
def revoke_token(token):
    """Revoke an authentication token"""
    if not SECURITY_ENABLED:
        return jsonify({"error": "Security module not available"}), 503
    
    if get_token_manager().revoke_token(token):
        return jsonify({"status": "revoked"})
    return jsonify({"error": "Token not found"}), 404

# Protected API endpoints
@app.route('/api/status')
@require_auth
def status():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM events')
    events = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM devices')
    devices = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM alerts')
    alerts = c.fetchone()[0]
    conn.close()
    
    return jsonify({
        "status": "running",
        "connected_clients": len(clients),
        "events_count": events,
        "devices_count": devices,
        "alerts_count": alerts,
        "uptime": "ok",
        "security_enabled": SECURITY_ENABLED
    })

@app.route('/api/events')
@require_auth
def get_events():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    limit = request.args.get('limit', 100)
    c.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?', (limit,))
    events = []
    for row in c.fetchall():
        events.append({
            "id": row[0],
            "timestamp": row[1],
            "source": row[2],
            "event_type": row[3],
            "data": json.loads(row[4]) if row[4] else {}
        })
    conn.close()
    return jsonify({"events": events})

@app.route('/api/devices')
@require_auth
def get_devices():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM devices ORDER BY last_seen DESC')
    devices = []
    for row in c.fetchall():
        devices.append({
            "id": row[0],
            "device_id": row[1],
            "name": row[2],
            "registered_at": row[3],
            "last_seen": row[4]
        })
    conn.close()
    return jsonify({"devices": devices})

@app.route('/api/alerts')
@require_auth
def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    limit = request.args.get('limit', 50)
    c.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
    alerts = []
    for row in c.fetchall():
        alerts.append({
            "id": row[0],
            "timestamp": row[1],
            "severity": row[2],
            "source": row[3],
            "message": row[4],
            "data": json.loads(row[5]) if row[5] else {}
        })
    conn.close()
    return jsonify({"alerts": alerts})

@app.route('/api/alert', methods=['POST'])
@require_auth
def create_alert():
    data = request.json
    severity = data.get('severity', 'info')
    source = data.get('source', 'unknown')
    message = data.get('message', '')
    alert_data = data.get('data', {})
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO alerts (severity, source, message, data) VALUES (?, ?, ?, ?)',
              (severity, source, message, json.dumps(alert_data)))
    conn.commit()
    conn.close()
    
    # Broadcast alert to connected clients
    broadcast({"type": "alert", "severity": severity, "message": message, "data": alert_data})
    
    return jsonify({"status": "created", "severity": severity})

# Tool execution endpoint with container isolation
@app.route('/api/tools/execute', methods=['POST'])
@require_auth
def api_execute_tool():
    """
    Execute a command in an isolated container.
    
    Request body:
        {
            "command": "ls -la",
            "files": {"script.sh": "#!/bin/bash\necho hello"},
            "timeout": 120
        }
    """
    if not SECURITY_ENABLED:
        return jsonify({"error": "Security module not available"}), 503
    
    data = request.json or {}
    command = data.get('command')
    files = data.get('files')
    timeout = data.get('timeout', 120)
    
    if not command:
        return jsonify({"error": "Command is required"}), 400
    
    result = execute_tool(command=command, files=files, timeout=timeout)
    return jsonify(result)

# Secrets management endpoints
@app.route('/api/secrets', methods=['GET'])
@require_auth
def list_secrets():
    """List secrets (names only, not values)"""
    if not SECURITY_ENABLED:
        return jsonify({"error": "Security module not available"}), 503
    
    secrets = get_secrets_manager().list_secrets()
    return jsonify({"secrets": secrets})

@app.route('/api/secrets/<name>', methods=['GET'])
@require_auth
def get_secret_endpoint(name):
    """Get a secret value"""
    if not SECURITY_ENABLED:
        return jsonify({"error": "Security module not available"}), 503
    
    try:
        value = get_secret(name)
        return jsonify({"name": name, "value": value})
    except Exception as e:
        return jsonify({"error": f"Secret not found: {name}"}), 404

@app.route('/api/secrets/<name>', methods=['PUT'])
@require_auth
def set_secret_endpoint(name):
    """Set a secret value"""
    if not SECURITY_ENABLED:
        return jsonify({"error": "Security module not available"}), 503
    
    data = request.json or {}
    value = data.get('value')
    
    if not value:
        return jsonify({"error": "Value is required"}), 400
    
    if set_secret(name, value):
        return jsonify({"status": "created", "name": name})
    return jsonify({"error": "Failed to set secret"}), 500

@app.route('/api/secrets/<name>', methods=['DELETE'])
@require_auth
def delete_secret_endpoint(name):
    """Delete a secret"""
    if not SECURITY_ENABLED:
        return jsonify({"error": "Security module not available"}), 503
    
    if delete_secret(name):
        return jsonify({"status": "deleted"})
    return jsonify({"error": "Secret not found"}), 404

# WebSocket endpoint
@sock.route('/ws')
def websocket(ws):
    clients.append(ws)
    try:
        while True:
            message = ws.receive()
            if message:
                try:
                    data = json.loads(message)
                    event_type = data.get('type', 'unknown')
                    source = data.get('source', 'cogniwatch')
                    
                    # Log the event
                    log_event(source, event_type, data)
                    
                    # Handle specific events
                    if event_type == 'device_registration':
                        # Register device
                        device_id = data.get('device_id')
                        name = data.get('name', 'Unknown')
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        c.execute('''INSERT OR REPLACE INTO devices (device_id, name, last_seen) 
                                    VALUES (?, ?, ?)''', (device_id, name, datetime.now().isoformat()))
                        conn.commit()
                        conn.close()
                    
                    elif event_type == 'scan_result':
                        # Forward scan results to all clients
                        broadcast({"type": "scan_result", "data": data})
                    
                    elif event_type == 'security_alert':
                        # Create alert
                        severity = data.get('severity', 'medium')
                        message = data.get('message', 'Security alert')
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        c.execute('INSERT INTO alerts (severity, source, message, data) VALUES (?, ?, ?, ?)',
                                  (severity, source, message, json.dumps(data)))
                        conn.commit()
                        conn.close()
                        broadcast({"type": "security_alert", "severity": severity, "message": message})
                    
                except json.JSONDecodeError:
                    pass
    except:
        pass
    finally:
        if ws in clients:
            clients.remove(ws)

if __name__ == '__main__':
    init_db()
    logger.info("🦈 Picoclaw Gateway starting on port 18789...")
    logger.info(f"Security hardening: {'ENABLED' if SECURITY_ENABLED else 'DISABLED'}")
    app.run(host='0.0.0.0', port=18789, debug=False)
