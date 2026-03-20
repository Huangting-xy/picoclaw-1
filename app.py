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

app = Flask(__name__)
sock = Sock(app)

# Database path
DB_PATH = os.environ.get("PICOCLAW_DB", "/home/cogniwatch/data/picoclaw.db")

# Connected clients
clients = []

def init_db():
    """Initialize the Picoclaw database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source TEXT,
        event_type TEXT,
        data JSON
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT UNIQUE,
        name TEXT,
        registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        severity TEXT,
        source TEXT,
        message TEXT,
        data JSON
    )""")
    conn.commit()
    conn.close()

def log_event(source, event_type, data):
    """Log an event to the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO events (source, event_type, data) VALUES (?, ?, ?)",
                  (source, event_type, json.dumps(data)))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging event: {e}")

def broadcast(message):
    """Broadcast a message to all connected clients"""
    for client in clients:
        try:
            client.send(json.dumps(message))
        except:
            clients.remove(client)

# REST API Endpoints
@app.route("/")
def index():
    return jsonify({
        "name": "Picoclaw Gateway",
        "version": "0.1.0",
        "status": "running",
        "connected_clients": len(clients),
        "endpoints": ["/health", "/api/status", "/api/events", "/api/devices", "/ws", "/api/vulns/*"]
    })

@app.route("/health")
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route("/api/status")
def status():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM events")
    events = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM devices")
    devices = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts")
    alerts = c.fetchone()[0]
    conn.close()
    
    return jsonify({
        "status": "running",
        "connected_clients": len(clients),
        "events_count": events,
        "devices_count": devices,
        "alerts_count": alerts,
        "uptime": "ok"
    })

@app.route("/api/events")
def get_events():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    limit = request.args.get("limit", 100)
    c.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
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

@app.route("/api/devices")
def get_devices():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM devices ORDER BY last_seen DESC")
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

@app.route("/api/alerts")
def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    limit = request.args.get("limit", 50)
    c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
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

@app.route("/api/alert", methods=["POST"])
def create_alert():
    data = request.json
    severity = data.get("severity", "info")
    source = data.get("source", "unknown")
    message = data.get("message", "")
    alert_data = data.get("data", {})
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO alerts (severity, source, message, data) VALUES (?, ?, ?, ?)",
              (severity, source, message, json.dumps(alert_data)))
    conn.commit()
    conn.close()
    
    # Broadcast alert to connected clients
    broadcast({"type": "alert", "severity": severity, "message": message, "data": alert_data})
    
    return jsonify({"status": "created", "severity": severity})

# ============================================
# Vulnerability API Endpoints
# ============================================

@app.route("/api/vulns/scan", methods=["POST"])
def vulns_scan():
    """
    Run a full vulnerability scan on a target.
    
    Request body:
    {
        "target": "http://localhost:18789",
        "checks": ["cve_2026_25253", "secrets", "mdns"],
        "timeout": 30
    }
    
    Returns:
        Comprehensive vulnerability scan results
    """
    try:
        from vulns import run_security_scan
        
        data = request.json or {}
        target = data.get("target", "http://localhost:18789")
        checks = data.get("checks", ["cve_2026_25253", "secrets", "mdns"])
        
        result = run_security_scan(target=target, checks=checks)
        return jsonify(result)
    
    except ImportError as e:
        return jsonify({
            "error": "Vulnerability modules not available",
            "details": str(e)
        }), 500
    except Exception as e:
        return jsonify({
            "error": "Scan failed",
            "details": str(e)
        }), 500

@app.route("/api/vulns/cve/<cve_id>")
def get_cve(cve_id):
    """
    Get CVE details by ID.
    
    Args:
        cve_id: CVE ID (e.g., CVE-2026-25253)
    
    Returns:
        CVE details from NVD database
    """
    try:
        from vulns import get_cve as fetch_cve
        
        cve = fetch_cve(cve_id.upper())
        if cve:
            return jsonify(cve)
        else:
            return jsonify({
                "error": "CVE not found",
                "cve_id": cve_id
            }), 404
    
    except ImportError as e:
        return jsonify({
            "error": "CVE database module not available",
            "details": str(e)
        }), 500
    except Exception as e:
        return jsonify({
            "error": "Failed to fetch CVE",
            "details": str(e)
        }), 500

@app.route("/api/vulns/cve/search")
def search_cves():
    """
    Search CVEs by keyword.
    
    Query params:
        q: Search keyword
        limit: Maximum results (default 20)
    
    Returns:
        List of matching CVEs
    """
    try:
        from vulns import search_cves
        
        keyword = request.args.get("q", "")
        limit = request.args.get("limit", 20)
        
        if not keyword:
            return jsonify({
                "error": "Search keyword required",
                "usage": "Provide q parameter"
            }), 400
        
        results = search_cves(keyword, limit=int(limit))
        return jsonify({
            "keyword": keyword,
            "count": len(results),
            "results": results
        })
    
    except ImportError as e:
        return jsonify({
            "error": "CVE database module not available",
            "details": str(e)
        }), 500
    except Exception as e:
        return jsonify({
            "error": "CVE search failed",
            "details": str(e)
        }), 500

@app.route("/api/vulns/openclaw", methods=["POST"])
def scan_openclaw():
    """
    Scan for OpenClaw-specific vulnerabilities.
    
    Request body:
    {
        "target": "http://localhost:18789",
        "checks": ["cve_2026_25253", "secrets", "mdns"]
    }
    
    Returns:
        OpenClaw vulnerability scan results
    """
    try:
        from vulns import (
            detect_cve_2026_25253,
            scan_secrets,
            detect_mdns
        )
        
        data = request.json or {}
        target = data.get("target", "http://localhost:18789")
        checks = data.get("checks", ["cve_2026_25253", "secrets", "mdns"])
        
        results = {
            "scan_time": datetime.now().isoformat(),
            "target": target,
            "vulnerabilities": [],
            "findings": {}
        }
        
        # Check for CVE-2026-25253
        if "cve_2026_25253" in checks:
            try:
                cve_result = detect_cve_2026_25253(target)
                results["findings"]["cve_2026_25253"] = cve_result
                if cve_result.get("vulnerable"):
                    for vuln in cve_result.get("details", {}).get("vulnerabilities_found", []):
                        results["vulnerabilities"].append({
                            "cve": "CVE-2026-25253",
                            "type": vuln["type"],
                            "severity": vuln["severity"],
                            "description": vuln["description"]
                        })
            except Exception as e:
                results["findings"]["cve_2026_25253"] = {"error": str(e)}
        
        # Check for exposed secrets
        if "secrets" in checks:
            try:
                secrets_result = scan_secrets()
                results["findings"]["secrets"] = secrets_result
                if secrets_result.get("found", 0) > 0:
                    results["vulnerabilities"].append({
                        "type": "exposed_secrets",
                        "severity": "critical" if secrets_result.get("severity_summary", {}).get("critical", 0) > 0 else "high",
                        "description": f"{secrets_result[found]} secrets found in configuration",
                        "count": secrets_result["found"]
                    })
            except Exception as e:
                results["findings"]["secrets"] = {"error": str(e)}
        
        # Check for mDNS broadcasting
        if "mdns" in checks:
            try:
                mdns_result = detect_mdns()
                results["findings"]["mdns"] = mdns_result
                if mdns_result.get("broadcasting"):
                    results["vulnerabilities"].append({
                        "type": "mdns_broadcast",
                        "severity": "high",
                        "description": "mDNS broadcasting detected - local discovery may expose services",
                        "services": mdns_result.get("services", [])
                    })
            except Exception as e:
                results["findings"]["mdns"] = {"error": str(e)}
        
        # Summary
        results["vulnerable"] = len(results["vulnerabilities"]) > 0
        results["vulnerability_count"] = len(results["vulnerabilities"])
        
        return jsonify(results)
    
    except ImportError as e:
        return jsonify({
            "error": "Vulnerability modules not available",
            "details": str(e)
        }), 500
    except Exception as e:
        return jsonify({
            "error": "OpenClaw vulnerability scan failed",
            "details": str(e)
        }), 500

@app.route("/api/vulns/cve/database/status")
def cve_database_status():
    """
    Get CVE database status and statistics.
    
    Returns:
        Database statistics including cached CVE count
    """
    try:
        from vulns import get_cve_database_status
        
        status = get_cve_database_status()
        return jsonify(status)
    
    except ImportError as e:
        return jsonify({
            "error": "CVE database module not available",
            "details": str(e)
        }), 500
    except Exception as e:
        return jsonify({
            "error": "Failed to get database status",
            "details": str(e)
        }), 500

# WebSocket endpoint
@sock.route("/ws")
def websocket(ws):
    clients.append(ws)
    try:
        while True:
            message = ws.receive()
            if message:
                try:
                    data = json.loads(message)
                    event_type = data.get("type", "unknown")
                    source = data.get("source", "cogniwatch")
                    
                    # Log the event
                    log_event(source, event_type, data)
                    
                    # Handle specific events
                    if event_type == "device_registration":
                        # Register device
                        device_id = data.get("device_id")
                        name = data.get("name", "Unknown")
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        c.execute("""INSERT OR REPLACE INTO devices (device_id, name, last_seen) 
                                    VALUES (?, ?, ?)""", (device_id, name, datetime.now().isoformat()))
                        conn.commit()
                        conn.close()
                    
                    elif event_type == "scan_result":
                        # Forward scan results to all clients
                        broadcast({"type": "scan_result", "data": data})
                    
                    elif event_type == "security_alert":
                        # Create alert
                        severity = data.get("severity", "medium")
                        message = data.get("message", "Security alert")
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        c.execute("INSERT INTO alerts (severity, source, message, data) VALUES (?, ?, ?, ?)",
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

if __name__ == "__main__":
    init_db()
    print("🦈 Picoclaw Gateway starting on port 18789...")
    app.run(host="0.0.0.0", port=18789, debug=False)
