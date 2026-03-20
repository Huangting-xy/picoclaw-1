#!/usr/bin/env python3
"""
Manifest Detector - Scans for AI agent manifests and configuration files

Detects:
- ai-plugin.json (OpenAI plugin format)
- .well-known/ai-agent (standardized agent discovery)
- openclaw-config.json (OpenClaw configuration)
"""

import requests
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, Optional, List
import json
import re


class ManifestDetector:
    """Detects agent manifests from URLs"""
    
    # Standard manifest paths to check
    MANIFEST_PATHS = {
        'ai-plugin': '/.well-known/ai-plugin.json',
        'ai-agent': '/.well-known/ai-agent',
        'openclaw-config': '/openclaw-config.json',
        'openai-plugin': '/ai-plugin.json',
    }
    
    # Alternative paths
    ALTERNATIVE_PATHS = [
        '/api/ai-plugin.json',
        '/api/.well-known/ai-agent',
        '/manifest.json',
        '/agent.json',
    ]
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize the manifest detector.
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Picoclaw-Scanner/1.0',
            'Accept': 'application/json, text/plain, */*'
        })
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _fetch_url(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Fetch URL and return JSON response if available.
        
        Args:
            url: URL to fetch
            
        Returns:
            Dict with response data or None on error
        """
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                
                # Try to parse as JSON
                if 'application/json' in content_type or response.text.strip().startswith('{'):
                    try:
                        return {
                            'status_code': response.status_code,
                            'content': response.json(),
                            'headers': dict(response.headers),
                            'url': response.url
                        }
                    except json.JSONDecodeError:
                        return {
                            'status_code': response.status_code,
                            'content': response.text,
                            'headers': dict(response.headers),
                            'url': response.url
                        }
                else:
                    return {
                        'status_code': response.status_code,
                        'content': response.text,
                        'headers': dict(response.headers),
                        'url': response.url
                    }
            else:
                return {
                    'status_code': response.status_code,
                    'error': f'HTTP {response.status_code}',
                    'headers': dict(response.headers)
                }
        except requests.exceptions.RequestException as e:
            return {
                'status_code': 0,
                'error': str(e)
            }
    
    def _parse_ai_plugin(self, content: Dict) -> Dict[str, Any]:
        """Parse OpenAI plugin manifest"""
        result = {
            'type': 'ai-plugin',
            'name': None,
            'description': None,
            'api_url': None,
            'auth': None,
            'config': {}
        }
        
        if isinstance(content, dict):
            # OpenAI plugin format
            result['name'] = content.get('name_for_human') or content.get('name')
            result['description'] = content.get('description_for_human') or content.get('description')
            
            # API configuration
            api = content.get('api', {})
            if isinstance(api, dict):
                result['api_url'] = api.get('url')
                result['config']['api_type'] = api.get('type', 'openapi')
            
            # Authentication
            auth = content.get('auth', {})
            if auth:
                result['auth'] = auth.get('type', 'none')
                result['config']['auth'] = auth
            
            # Logo/branding
            if content.get('logo_url'):
                result['config']['logo_url'] = content.get('logo_url')
            
            # Legal info
            if content.get('legal_info_url'):
                result['config']['legal_info_url'] = content.get('legal_info_url')
        
        return result
    
    def _parse_ai_agent(self, content: Any) -> Dict[str, Any]:
        """Parse .well-known/ai-agent manifest"""
        result = {
            'type': 'ai-agent',
            'name': None,
            'description': None,
            'capabilities': [],
            'endpoints': {},
            'config': {}
        }
        
        if isinstance(content, dict):
            result['name'] = content.get('name') or content.get('agent_name')
            result['description'] = content.get('description')
            
            # Capabilities
            caps = content.get('capabilities', [])
            if isinstance(caps, list):
                result['capabilities'] = caps
            
            # Endpoints
            endpoints = content.get('endpoints', {})
            if isinstance(endpoints, dict):
                result['endpoints'] = endpoints
            
            # Version
            if content.get('version'):
                result['config']['version'] = content.get('version')
            
            # Protocol info
            if content.get('protocol'):
                result['config']['protocol'] = content.get('protocol')
            
            # Auth requirements
            if content.get('requires_auth'):
                result['config']['requires_auth'] = content.get('requires_auth')
        
        return result
    
    def _parse_openclaw_config(self, content: Dict) -> Dict[str, Any]:
        """Parse openclaw-config.json"""
        result = {
            'type': 'openclaw-config',
            'name': None,
            'version': None,
            'capabilities': [],
            'mcp_servers': [],
            'config': {}
        }
        
        if isinstance(content, dict):
            result['name'] = content.get('name')
            result['version'] = content.get('version')
            
            # Capabilities
            caps = content.get('capabilities', [])
            if isinstance(caps, list):
                result['capabilities'] = caps
            
            # MCP servers
            mcp = content.get('mcp_servers', [])
            if isinstance(mcp, list):
                result['mcp_servers'] = mcp
            
            # Additional config
            for key in ['transport', 'auth', 'rate_limit', 'features']:
                if key in content:
                    result['config'][key] = content[key]
        
        return result
    
    def scan(self, target_url: str) -> Dict[str, Any]:
        """
        Scan a URL for agent manifests.
        
        Args:
            target_url: URL to scan
            
        Returns:
            Dict with scan results
        """
        base_url = self._normalize_url(target_url)
        results = {
            'found': False,
            'manifests': [],
            'errors': []
        }
        
        # Check all standard manifest paths
        for manifest_type, path in self.MANIFEST_PATHS.items():
            url = urljoin(base_url, path)
            response = self._fetch_url(url)
            
            if response and response.get('status_code') == 200:
                content = response.get('content')
                
                # Parse based on type
                if manifest_type == 'ai-plugin':
                    parsed = self._parse_ai_plugin(content)
                elif manifest_type == 'ai-agent':
                    parsed = self._parse_ai_agent(content)
                elif manifest_type == 'openclaw-config':
                    parsed = self._parse_openclaw_config(content)
                else:
                    parsed = {'type': manifest_type, 'raw': content}
                
                parsed['url'] = url
                results['manifests'].append(parsed)
                results['found'] = True
        
        # Check alternative paths
        for path in self.ALTERNATIVE_PATHS:
            url = urljoin(base_url, path)
            response = self._fetch_url(url)
            
            if response and response.get('status_code') == 200:
                content = response.get('content')
                
                # Try to identify the type
                if isinstance(content, dict):
                    if 'name_for_human' in content or 'api' in content:
                        parsed = self._parse_ai_plugin(content)
                    elif 'capabilities' in content:
                        parsed = self._parse_ai_agent(content)
                    elif 'mcp_servers' in content:
                        parsed = self._parse_openclaw_config(content)
                    else:
                        parsed = {'type': 'unknown', 'raw': content}
                    
                    parsed['url'] = url
                    parsed['path'] = path
                    results['manifests'].append(parsed)
                    results['found'] = True
        
        # Deduplicate manifests
        seen_urls = set()
        unique_manifests = []
        for m in results['manifests']:
            if m.get('url') not in seen_urls:
                seen_urls.add(m.get('url'))
                unique_manifests.append(m)
        results['manifests'] = unique_manifests
        
        return results
    
    def get_manifest_summary(self, scan_result: Dict) -> Dict[str, Any]:
        """
        Get a summary of detected manifests.
        
        Args:
            scan_result: Result from scan()
            
        Returns:
            Dict with summary info
        """
        summary = {
            'found': scan_result['found'],
            'types_detected': [],
            'has_auth': False,
            'has_mcp': False,
            'agent_name': None,
            'capabilities': []
        }
        
        for manifest in scan_result.get('manifests', []):
            mtype = manifest.get('type')
            if mtype not in summary['types_detected']:
                summary['types_detected'].append(mtype)
            
            if manifest.get('auth') and manifest['auth'] != 'none':
                summary['has_auth'] = True
            
            if manifest.get('mcp_servers'):
                summary['has_mcp'] = True
            
            name = manifest.get('name')
            if name and not summary['agent_name']:
                summary['agent_name'] = name
            
            caps = manifest.get('capabilities', [])
            for cap in caps:
                if cap not in summary['capabilities']:
                    summary['capabilities'].append(cap)
        
        return summary


def scan_url(url: str, timeout: int = 10, verify_ssl: bool = True) -> Dict[str, Any]:
    """
    Convenience function to scan a URL for manifests.
    
    Args:
        url: URL to scan
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        
    Returns:
        Dict with scan results
    """
    detector = ManifestDetector(timeout=timeout, verify_ssl=verify_ssl)
    return detector.scan(url)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python manifest_detector.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    print(f"Scanning {url} for manifests...")
    
    result = scan_url(url)
    print(json.dumps(result, indent=2))
    
    if result['found']:
        print(f"\nFound {len(result['manifests'])} manifest(s)")
        for m in result['manifests']:
            print(f"  - {m.get('type')}: {m.get('name', 'unnamed')}")
    else:
        print("\nNo manifests found")
