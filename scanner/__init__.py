#!/usr/bin/env python3
"""
Picoclaw Scanner Package

Provides scanning and fingerprinting capabilities for AI agent detection:
- Manifest detection (ai-plugin.json, ai-agent, openclaw-config.json)
- Framework fingerprinting (OpenClaw, NanoClaw, MCP servers)
- MCP endpoint scanning
"""

from .manifest_detector import ManifestDetector, scan_url as scan_manifest
from .fingerprint import FrameworkFingerprinter, fingerprint_url as fingerprint_framework
from .mcp_scanner import MCPScanner, scan_url as scan_mcp

__all__ = [
    'ManifestDetector',
    'FrameworkFingerprinter',
    'MCPScanner',
    'scan_manifest',
    'fingerprint_framework',
    'scan_mcp',
]

__version__ = '1.0.0'
