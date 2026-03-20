#!/usr/bin/env python3
"""
Picoclaw - Minimal OpenClaw Gateway for CogniWatch Sentinel
Listens on port 18789 for WebSocket connections from CogniWatch
"""

from flask import Flask, jsonify, request
from flask_sock import Sock
import json
import sqlite3
import os
from datetime import datetime
import threading
import time

# Import scanner modules
from scanner.manifest_detector import ManifestDetector, scan_url as scan_manifest_url
from scanner.fingerprint import FrameworkFingerprinter, fingerprint_url as fingerprint_url_func
from scanner.mcp_scanner import MCPScanner, scan_url as scan_mcp_url

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
    # Add scan results table
    c.execute('''CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        scan_type TEXT,
        target TEXT,
        result JSON
    )''')
    conn.commit()
    conn.close()

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
        print(f"Error logging event: {e}")

def log_scan_result(scan_type, target, result):
    """Log a scan result to the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('INSERT INTO scan_results (scan_type, target, result) VALUES (?, ?, ?)',
                  (scan_type, target, json.dumps(result)))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging scan result: {e}")

def broadcast(message):
    """Broadcast a message to all connected clients"""
    for client in clients:
        try:
            client.send(json.dumps(message))
        except:
            clients.remove(client)

# REST API Endpoints
@app.route('/')
def index():
    return jsonify({
        "name": "Picoclaw Gateway",
        "version": "0.1.0",
        "status": "running",
        "connected_clients": len(clients),
        "endpoints": [
            "/health", "/api/status", "/api/events", "/api/devices",
            "/api/scan/manifest", "/api/scan/fingerprint", "/api/scan/mcp"
        ]
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/api/status')
def status():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM events')
    events = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM devices')
    devices = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM alerts')
    alerts = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM scan_results')
    scans = c.fetchone()[0]
    conn.close()
    
    return jsonify({
        "status": "running",
        "connected_clients": len(clients),
        "events_count": events,
        "devices_count": devices,
        "alerts_count": alerts,
        "scans_count": scans,
        "uptime": "ok"
    })

@app.route('/api/events')
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

# Scanner API Endpoints

@app.route('/api/scan/manifest', methods=['POST'])
def scan_manifest():
    """
    Scan a URL for agent manifests.
    
    Request body:
    {
        "url": "https://example.com",
        "timeout": 10,
        "verify_ssl": true
    }
    
    Response:
    {
        "found": true,
        "manifests": [...]
    }
    """
    data = request.json
    
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400
    
    url = data.get('url')
    timeout = data.get('timeout', 10)
    verify_ssl = data.get('verify_ssl', True)
    
    try:
        detector = ManifestDetector(timeout=timeout, verify_ssl=verify_ssl)
        result = detector.scan(url)
        
        # Log the scan result
        log_scan_result('manifest', url, result)
        
        # Broadcast to connected clients
        broadcast({
            "type": "scan_result",
            "scan_type": "manifest",
            "target": url,
            "result": result
        })
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e), "found": False}), 500


@app.route('/api/scan/fingerprint', methods=['POST'])
def scan_fingerprint():
    """
    Fingerprint a URL to detect frameworks and vulnerabilities.
    
    Request body:
    {
        "url": "https://example.com",
        "timeout": 10,
        "verify_ssl": true
    }
    
    Response:
    {
        "framework": "openclaw",
        "version": "1.0.0",
        "vulnerable": false,
        "vulnerabilities": []
    }
    """
    data = request.json
    
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400
    
    url = data.get('url')
    timeout = data.get('timeout', 10)
    verify_ssl = data.get('verify_ssl', True)
    
    try:
        fingerprinter = FrameworkFingerprinter(timeout=timeout, verify_ssl=verify_ssl)
        result = fingerprinter.fingerprint(url)
        
        # Log the scan result
        log_scan_result('fingerprint', url, result)
        
        # Broadcast to connected clients
        broadcast({
            "type": "scan_result",
            "scan_type": "fingerprint",
            "target": url,
            "result": result
        })
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e), "framework": None, "vulnerable": False}), 500


@app.route('/api/scan/mcp', methods=['POST'])
def scan_mcp():
    """
    Scan a URL for MCP server endpoints.
    
    Request body:
    {
        "url": "https://example.com",
        "timeout": 10,
        "verify_ssl": true
    }
    
    Response:
    {
        "found": true,
        "mcp_endpoints": [...],
        "auth_required": false,
        "vulnerable": false
    }
    """
    data = request.json
    
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400
    
    url = data.get('url')
    timeout = data.get('timeout', 10)
    verify_ssl = data.get('verify_ssl', True)
    
    try:
        scanner = MCPScanner(timeout=timeout, verify_ssl=verify_ssl)
        result = scanner.scan(url)
        
        # Log the scan result
        log_scan_result('mcp', url, result)
        
        # Broadcast to connected clients
        broadcast({
            "type": "scan_result",
            "scan_type": "mcp",
            "target": url,
            "result": result
        })
        
        # Create alert if MCP found without auth (vulnerable)
        if result.get('found') and result.get('vulnerable'):
            log_event('scanner', 'security_alert', {
                'severity': 'high',
                'message': f'Vulnerable MCP endpoint found at {url}',
                'details': result
            })
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e), "found": False}), 500


@app.route('/api/scan/results')
def get_scan_results():
    """Get recent scan results"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    scan_type = request.args.get('type')
    limit = request.args.get('limit', 50)
    
    if scan_type:
        c.execute('SELECT * FROM scan_results WHERE scan_type = ? ORDER BY timestamp DESC LIMIT ?',
                  (scan_type, limit))
    else:
        c.execute('SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT ?', (limit,))
    
    results = []
    for row in c.fetchall():
        results.append({
            "id": row[0],
            "timestamp": row[1],
            "scan_type": row[2],
            "target": row[3],
            "result": json.loads(row[4]) if row[4] else {}
        })
    conn.close()
    
    return jsonify({"results": results})


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
                        message_str = data.get('message', 'Security alert')
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        c.execute('INSERT INTO alerts (severity, source, message, data) VALUES (?, ?, ?, ?)',
                                  (severity, source, message_str, json.dumps(data)))
                        conn.commit()
                        conn.close()
                        broadcast({"type": "security_alert", "severity": severity, "message": message_str})
                    
                except json.JSONDecodeError:
                    pass
    except:
        pass
    finally:
        if ws in clients:
            clients.remove(ws)

if __name__ == '__main__':
    init_db()
    print("Picoclaw Gateway starting on port 18789...")
    app.run(host='0.0.0.0', port=18789, debug=False)
