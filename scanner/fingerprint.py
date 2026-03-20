#!/usr/bin/env python3
"""
Framework Fingerprinter - Detects AI agent frameworks and versions

Detects:
- OpenClaw version from API response headers (X-OpenClaw-Version)
- NanoClaw from minimal signature
- MCP servers without auth
"""

import requests
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, Optional, List
import json
import re


class FrameworkFingerprinter:
    """Fingerprints AI agent frameworks from URLs"""
    
    # Known framework signatures
    FRAMEWORK_SIGNATURES = {
        'openclaw': {
            'headers': ['X-OpenClaw-Version', 'X-Picoclaw-Version'],
            'body_patterns': [
                r'"name":\s*"OpenClaw"',
                r'"name":\s*"Picoclaw"',
                r'openclaw',
                r'picoclaw',
            ],
            'endpoints': ['/api/status', '/health', '/'],
        },
        'nanoclaw': {
            'headers': ['X-NanoClaw-Version'],
            'body_patterns': [
                r'"name":\s*"NanoClaw"',
                r'nanoclaw',
                r'nano-claw',
            ],
            'endpoints': ['/health', '/status', '/'],
        },
        'mcp_server': {
            'headers': ['X-MCP-Version'],
            'body_patterns': [
                r'"protocol":\s*"mcp"',
                r'mcp-server',
                r'MCP Server',
            ],
            'endpoints': ['/mcp', '/mcp/sse', '/mcp/ws', '/'],
        },
        'langchain': {
            'headers': [],
            'body_patterns': [
                r'"framework":\s*"langchain"',
                r'langchain',
                r'LangChain',
            ],
            'endpoints': ['/health', '/'],
        },
        'autogpt': {
            'headers': [],
            'body_patterns': [
                r'"name":\s*"AutoGPT"',
                r'autogpt',
                r'AutoGPT',
            ],
            'endpoints': ['/health', '/'],
        },
        'crewai': {
            'headers': [],
            'body_patterns': [
                r'"framework":\s*"crewai"',
                r'crewai',
                r'CrewAI',
            ],
            'endpoints': ['/health', '/'],
        }
    }
    
    # Vulnerability patterns
    VULNERABILITY_PATTERNS = {
        'no_auth': {
            'description': 'No authentication required',
            'severity': 'high'
        },
        'default_credentials': {
            'description': 'Default credentials detected',
            'severity': 'critical'
        },
        'exposed_endpoints': {
            'description': 'Sensitive endpoints exposed without auth',
            'severity': 'high'
        },
        'version_disclosed': {
            'description': 'Version information disclosed in headers',
            'severity': 'low'
        },
        'cors_misconfigured': {
            'description': 'CORS misconfigured (allows all origins)',
            'severity': 'medium'
        }
    }
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize the fingerprinter.
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Picoclaw-Fingerprinter/1.0',
            'Accept': 'application/json, text/plain, */*'
        })
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _fetch_url(self, url: str, method: str = 'GET') -> Optional[Dict[str, Any]]:
        """
        Fetch URL and return response data.
        
        Args:
            url: URL to fetch
            method: HTTP method to use
            
        Returns:
            Dict with response data or None on error
        """
        try:
            if method == 'GET':
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )
            else:
                response = self.session.options(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:5000] if response.text else '',
                'url': response.url
            }
        except requests.exceptions.RequestException as e:
            return {
                'status_code': 0,
                'error': str(e)
            }
    
    def _extract_version(self, headers: Dict[str, str], body: str) -> Optional[str]:
        """Extract version from headers or body"""
        # Check headers first
        for header in ['X-OpenClaw-Version', 'X-Picoclaw-Version', 'X-NanoClaw-Version',
                        'X-MCP-Version', 'Server', 'X-Powered-By']:
            if header in headers:
                value = headers[header]
                # Try to extract version number
                version_match = re.search(r'(\d+\.\d+\.\d+|\d+\.\d+)', value)
                if version_match:
                    return version_match.group(1)
        
        # Check body for version
        version_patterns = [
            r'"version":\s*"([^"]+)"',
            r'version["\s:]+(\d+\.\d+\.\d+|\d+\.\d+)',
            r'v(\d+\.\d+\.\d+|\d+\.\d+)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, body)
            if match:
                return match.group(1)
        
        return None
    
    def _detect_framework_by_headers(self, headers: Dict[str, str]) -> List[str]:
        """Detect frameworks by examining response headers"""
        detected = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for framework, sig in self.FRAMEWORK_SIGNATURES.items():
            for header in sig.get('headers', []):
                if header.lower() in headers_lower:
                    detected.append(framework)
                    break
        
        return detected
    
    def _detect_framework_by_body(self, body: str) -> List[str]:
        """Detect frameworks by examining response body"""
        detected = []
        
        for framework, sig in self.FRAMEWORK_SIGNATURES.items():
            for pattern in sig.get('body_patterns', []):
                if re.search(pattern, body, re.IGNORECASE):
                    detected.append(framework)
                    break
        
        return detected
    
    def _check_authentication(self, url: str) -> Dict[str, Any]:
        """Check if endpoint requires authentication"""
        # Try various endpoints that might require auth
        auth_required_endpoints = [
            '/api/admin',
            '/api/config',
            '/api/users',
            '/api/secrets',
            '/admin',
            '/config',
        ]
        
        auth_status = {
            'requires_auth': False,
            'exposed_endpoints': [],
            'details': {}
        }
        
        for endpoint in auth_required_endpoints:
            test_url = urljoin(url, endpoint)
            response = self._fetch_url(test_url)
            
            if response and response.get('status_code') in [200, 201]:
                # Endpoint is accessible without auth - potential vulnerability
                auth_status['exposed_endpoints'].append({
                    'endpoint': endpoint,
                    'status': 'exposed',
                    'status_code': response['status_code']
                })
            elif response and response.get('status_code') in [401, 403]:
                auth_status['requires_auth'] = True
                auth_status['details'][endpoint] = 'protected'
        
        return auth_status
    
    def _check_cors(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check CORS configuration"""
        cors_status = {
            'misconfigured': False,
            'allowed_origins': [],
            'allows_credentials': False,
            'details': {}
        }
        
        # Check for wildcard CORS
        acao = headers.get('Access-Control-Allow-Origin', '')
        if acao == '*':
            cors_status['misconfigured'] = True
            cors_status['allowed_origins'] = ['*']
        
        # Check for credentials with wildcard
        acac = headers.get('Access-Control-Allow-Credentials', '')
        if acac.lower() == 'true' and acao == '*':
            cors_status['misconfigured'] = True
            cors_status['allows_credentials'] = True
        
        return cors_status
    
    def _analyze_vulnerabilities(self, fingerprint_result: Dict) -> List[Dict[str, Any]]:
        """Analyze detected issues for vulnerabilities"""
        vulnerabilities = []
        
        # Check for exposed endpoints
        if fingerprint_result.get('auth_status', {}).get('exposed_endpoints'):
            for endpoint in fingerprint_result['auth_status']['exposed_endpoints']:
                vulnerabilities.append({
                    'type': 'exposed_endpoints',
                    'description': f"Endpoint {endpoint['endpoint']} accessible without authentication",
                    'severity': 'high',
                    'endpoint': endpoint['endpoint']
                })
        
        # Check CORS misconfiguration
        cors_status = fingerprint_result.get('cors_status', {})
        if cors_status.get('misconfigured'):
            vulnerabilities.append({
                'type': 'cors_misconfigured',
                'description': 'CORS allows all origins',
                'severity': 'medium'
            })
            if cors_status.get('allows_credentials'):
                vulnerabilities.append({
                    'type': 'cors_misconfigured',
                    'description': 'CORS wildcard with credentials allowed - critical',
                    'severity': 'critical'
                })
        
        # Version disclosure
        if fingerprint_result.get('version'):
            vulnerabilities.append({
                'type': 'version_disclosed',
                'description': f"Version {fingerprint_result['version']} disclosed in response",
                'severity': 'low',
                'version': fingerprint_result['version']
            })
        
        return vulnerabilities
    
    def fingerprint(self, target_url: str) -> Dict[str, Any]:
        """
        Fingerprint a URL to detect frameworks and vulnerabilities.
        
        Args:
            target_url: URL to fingerprint
            
        Returns:
            Dict with fingerprint results
        """
        base_url = self._normalize_url(target_url)
        result = {
            'url': base_url,
            'framework': None,
            'version': None,
            'frameworks_detected': [],
            'vulnerable': False,
            'vulnerabilities': [],
            'auth_status': {},
            'cors_status': {},
            'headers': {},
            'details': {}
        }
        
        # Fetch main page
        main_response = self._fetch_url(base_url)
        
        if not main_response or main_response.get('status_code', 0) >= 400:
            result['error'] = main_response.get('error', f"HTTP {main_response.get('status_code', 'unknown')}")
            return result
        
        # Store headers
        result['headers'] = main_response.get('headers', {})
        
        # Detect frameworks from headers
        detected_from_headers = self._detect_framework_by_headers(result['headers'])
        
        # Detect frameworks from body
        detected_from_body = self._detect_framework_by_body(main_response.get('body', ''))
        
        # Combine detected frameworks
        all_detected = list(set(detected_from_headers + detected_from_body))
        result['frameworks_detected'] = all_detected
        
        # Set primary framework (first detected)
        if all_detected:
            result['framework'] = all_detected[0]
        
        # Extract version
        result['version'] = self._extract_version(result['headers'], main_response.get('body', ''))
        
        # Check authentication
        result['auth_status'] = self._check_authentication(base_url)
        
        # Check CORS
        result['cors_status'] = self._check_cors(result['headers'])
        
        # Analyze vulnerabilities
        result['vulnerabilities'] = self._analyze_vulnerabilities(result)
        
        # Set vulnerable flag
        result['vulnerable'] = len(result['vulnerabilities']) > 0
        
        # Try framework-specific endpoints
        for framework in all_detected:
            if framework in self.FRAMEWORK_SIGNATURES:
                for endpoint in self.FRAMEWORK_SIGNATURES[framework].get('endpoints', []):
                    test_url = urljoin(base_url, endpoint)
                    response = self._fetch_url(test_url)
                    if response and response.get('status_code') == 200:
                        if 'endpoints' not in result['details']:
                            result['details']['endpoints'] = []
                        result['details']['endpoints'].append({
                            'url': test_url,
                            'status': 'accessible',
                            'framework': framework
                        })
        
        return result
    
    def check_mcp_without_auth(self, target_url: str) -> Dict[str, Any]:
        """
        Check if MCP server endpoints are accessible without auth.
        
        Args:
            target_url: URL to check
            
        Returns:
            Dict with MCP auth check results
        """
        base_url = self._normalize_url(target_url)
        mcp_endpoints = [
            '/mcp',
            '/mcp/sse',
            '/mcp/ws',
            '/mcp/health',
            '/.mcp',
            '/api/mcp',
        ]
        
        results = {
            'found': False,
            'vulnerable': False,
            'endpoints': []
        }
        
        for endpoint in mcp_endpoints:
            test_url = urljoin(base_url, endpoint)
            response = self._fetch_url(test_url)
            
            if response and response.get('status_code') in [200, 101]:
                endpoint_info = {
                    'endpoint': endpoint,
                    'url': test_url,
                    'status_code': response['status_code'],
                    'accessible': True,
                    'requires_auth': False
                }
                
                # Check if it returns MCP-like response
                body = response.get('body', '')
                headers = response.get('headers', {})
                
                if 'mcp' in body.lower() or 'model-context-protocol' in body.lower():
                    endpoint_info['is_mcp'] = True
                    results['found'] = True
                
                # Check for auth headers
                www_auth = headers.get('WWW-Authenticate', '')
                if www_auth or response.get('status_code') == 401:
                    endpoint_info['requires_auth'] = True
                else:
                    results['vulnerable'] = True
                
                results['endpoints'].append(endpoint_info)
        
        return results


def fingerprint_url(url: str, timeout: int = 10, verify_ssl: bool = True) -> Dict[str, Any]:
    """
    Convenience function to fingerprint a URL.
    
    Args:
        url: URL to fingerprint
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        
    Returns:
        Dict with fingerprint results
    """
    fingerprinter = FrameworkFingerprinter(timeout=timeout, verify_ssl=verify_ssl)
    return fingerprinter.fingerprint(url)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python fingerprint.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    print(f"Fingerprinting {url}...")
    
    result = fingerprint_url(url)
    print(json.dumps(result, indent=2))
    
    if result.get('framework'):
        print(f"\nDetected framework: {result['framework']}")
        if result.get('version'):
            print(f"Version: {result['version']}")
    
    if result.get('vulnerable'):
        print(f"\n! Vulnerable: {len(result['vulnerabilities'])} issue(s) found")
        for v in result['vulnerabilities']:
            print(f"  - [{v['severity'].upper()}] {v['description']}")
