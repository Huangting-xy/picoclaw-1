#!/usr/bin/env python3
"""
MCP Scanner - Scans for MCP server endpoints and checks authentication

Scans for:
- MCP server endpoints (/mcp, /mcp/sse, /mcp/ws)
- Authentication requirements
- Sample tool calls
"""

import requests
import json
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, Optional, List
import websocket
import threading
import time


class MCPScanner:
    """Scanner for MCP server endpoints"""
    
    # Common MCP endpoint paths
    MCP_ENDPOINTS = [
        '/mcp',
        '/mcp/sse',
        '/mcp/ws',
        '/mcp/health',
        '/.mcp',
        '/api/mcp',
        '/api/v1/mcp',
        '/ws/mcp',
        '/sse/mcp',
    ]
    
    # Standard MCP methods to test
    MCP_METHODS = [
        'initialize',
        'list_tools',
        'list_resources',
        'list_prompts',
        'tools/call',
    ]
    
    # Sample tool call formats
    SAMPLE_TOOL_CALLS = {
        'initialize': {
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'initialize',
            'params': {
                'protocolVersion': '2024-11-05',
                'clientInfo': {
                    'name': 'Picoclaw-Scanner',
                    'version': '1.0.0'
                }
            }
        },
        'list_tools': {
            'jsonrpc': '2.0',
            'id': 2,
            'method': 'tools/list',
            'params': {}
        },
        'list_resources': {
            'jsonrpc': '2.0',
            'id': 3,
            'method': 'resources/list',
            'params': {}
        },
        'ping': {
            'jsonrpc': '2.0',
            'id': 4,
            'method': 'ping',
            'params': {}
        }
    }
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize the MCP scanner.
        
        Args:
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Picoclaw-MCP-Scanner/1.0',
            'Accept': 'application/json, text/event-stream, */*',
            'Content-Type': 'application/json'
        })
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format"""
        if not url.startswith(('http://', 'https://', 'ws://', 'wss://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _http_scan(self, url: str) -> Dict[str, Any]:
        """
        Scan an HTTP endpoint for MCP.
        
        Args:
            url: URL to scan
            
        Returns:
            Dict with scan results
        """
        result = {
            'url': url,
            'accessible': False,
            'is_mcp': False,
            'requires_auth': False,
            'auth_type': None,
            'response': None,
            'error': None
        }
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            result['response'] = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_type': response.headers.get('Content-Type', ''),
            }
            
            if response.status_code in [200, 201]:
                result['accessible'] = True
                
                # Check for MCP signatures
                content = response.text.lower()
                headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
                
                # Check content-type for SSE
                if 'text/event-stream' in response.headers.get('Content-Type', '').lower():
                    result['is_mcp'] = True
                
                # Check for MCP keywords in response
                mcp_keywords = ['mcp', 'model-context-protocol', 'jsonrpc', 'tools/list', 'resources/list']
                for keyword in mcp_keywords:
                    if keyword in content:
                        result['is_mcp'] = True
                        break
                
                # Check for MCP version header
                if 'x-mcp-version' in headers_lower:
                    result['is_mcp'] = True
                    result['mcp_version'] = headers_lower['x-mcp-version']
                
                # Check for authentication
                www_auth = response.headers.get('WWW-Authenticate', '')
                if www_auth:
                    result['requires_auth'] = True
                    result['auth_type'] = self._parse_auth_type(www_auth)
                
                # Parse SSE events if applicable
                if 'text/event-stream' in response.headers.get('Content-Type', '').lower():
                    result['sse_events'] = self._parse_sse(response.text)
            
            elif response.status_code == 401:
                result['requires_auth'] = True
                result['auth_type'] = self._parse_auth_type(
                    response.headers.get('WWW-Authenticate', 'unknown')
                )
            
            elif response.status_code == 403:
                result['accessible'] = False
                result['error'] = 'Forbidden'
            
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
        
        return result
    
    def _websocket_scan(self, url: str) -> Dict[str, Any]:
        """
        Scan a WebSocket endpoint for MCP.
        
        Args:
            url: WebSocket URL
            
        Returns:
            Dict with scan results
        """
        result = {
            'url': url,
            'accessible': False,
            'is_mcp': False,
            'requires_auth': False,
            'auth_type': None,
            'error': None,
            'tools': [],
            'resources': []
        }
        
        # Convert HTTP to WebSocket URL
        ws_url = url.replace('https://', 'wss://').replace('http://', 'ws://')
        
        try:
            ws = websocket.create_connection(
                ws_url,
                timeout=self.timeout
            )
            
            result['accessible'] = True
            
            # Try to initialize MCP connection
            init_msg = json.dumps(self.SAMPLE_TOOL_CALLS['initialize'])
            ws.send(init_msg)
            
            # Wait for response
            response = ws.recv()
            if response:
                try:
                    data = json.loads(response)
                    result['response'] = data
                    
                    # Check for MCP response structure
                    if 'jsonrpc' in data and 'result' in data:
                        result['is_mcp'] = True
                        
                        # Try to list tools
                        ws.send(json.dumps(self.SAMPLE_TOOL_CALLS['list_tools']))
                        tools_response = ws.recv()
                        if tools_response:
                            tools_data = json.loads(tools_response)
                            if 'result' in tools_data:
                                result['tools'] = tools_data['result'].get('tools', [])
                except json.JSONDecodeError:
                    pass
            
            ws.close()
            
        except websocket.WebSocketException as e:
            result['error'] = str(e)
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _parse_auth_type(self, www_authenticate: str) -> str:
        """Parse authentication type from WWW-Authenticate header"""
        www_auth_lower = www_authenticate.lower()
        
        if 'bearer' in www_auth_lower:
            return 'bearer'
        elif 'basic' in www_auth_lower:
            return 'basic'
        elif 'digest' in www_auth_lower:
            return 'digest'
        elif 'api-key' in www_auth_lower or 'apikey' in www_auth_lower:
            return 'api-key'
        elif 'oauth' in www_auth_lower:
            return 'oauth'
        else:
            return 'unknown'
    
    def _parse_sse(self, content: str) -> List[Dict[str, Any]]:
        """Parse Server-Sent Events content"""
        events = []
        
        for line in content.split('\n\n'):
            event = {}
            for part in line.split('\n'):
                if part.startswith('data:'):
                    event['data'] = part[5:].strip()
                elif part.startswith('event:'):
                    event['event'] = part[6:].strip()
                elif part.startswith('id:'):
                    event['id'] = part[3:].strip()
            
            if event:
                events.append(event)
        
        return events
    
    def _test_tool_call(self, url: str, endpoint: Dict) -> Dict[str, Any]:
        """
        Test a sample tool call on an MCP endpoint.
        
        Args:
            url: Base URL
            endpoint: Endpoint info dict
            
        Returns:
            Dict with tool call test results
        """
        result = {
            'success': False,
            'method': None,
            'response': None,
            'error': None
        }
        
        test_url = urljoin(url, endpoint['endpoint'])
        
        # Try POST with initialize
        try:
            response = self.session.post(
                test_url,
                json=self.SAMPLE_TOOL_CALLS['initialize'],
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result['success'] = True
                result['method'] = 'initialize'
                try:
                    result['response'] = response.json()
                except:
                    result['response'] = response.text[:500]
            elif response.status_code == 401:
                result['error'] = 'Authentication required'
            elif response.status_code == 404:
                result['error'] = 'Method not found'
            else:
                result['error'] = f'HTTP {response.status_code}'
                
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
        
        return result
    
    def scan(self, target_url: str) -> Dict[str, Any]:
        """
        Scan a URL for MCP server endpoints.
        
        Args:
            target_url: URL to scan
            
        Returns:
            Dict with scan results
        """
        base_url = self._normalize_url(target_url)
        
        result = {
            'url': base_url,
            'found': False,
            'mcp_endpoints': [],
            'auth_required': False,
            'auth_type': None,
            'vulnerable': False,
            'tools_found': [],
            'resources_found': [],
            'scan_details': []
        }
        
        # Scan each endpoint
        for endpoint in self.MCP_ENDPOINTS:
            test_url = urljoin(base_url, endpoint)
            
            # Check if WebSocket endpoint
            if endpoint.endswith('/ws') or '/ws/' in endpoint:
                scan_result = self._websocket_scan(test_url)
            else:
                scan_result = self._http_scan(test_url)
            
            scan_result['endpoint'] = endpoint
            result['scan_details'].append(scan_result)
            
            # Track MCP endpoints
            if scan_result.get('is_mcp'):
                result['found'] = True
                result['mcp_endpoints'].append({
                    'endpoint': endpoint,
                    'url': test_url,
                    'auth_required': scan_result.get('requires_auth', False),
                    'auth_type': scan_result.get('auth_type'),
                    'mcp_version': scan_result.get('mcp_version'),
                    'tools': scan_result.get('tools', []),
                })
            
            # Check overall auth requirements
            if scan_result.get('requires_auth'):
                result['auth_required'] = True
                if not result['auth_type']:
                    result['auth_type'] = scan_result.get('auth_type')
            
            # Track found tools
            if scan_result.get('tools'):
                for tool in scan_result['tools']:
                    if tool not in result['tools_found']:
                        result['tools_found'].append(tool)
            
            # Track found resources
            if scan_result.get('resources'):
                for resource in scan_result['resources']:
                    if resource not in result['resources_found']:
                        result['resources_found'].append(resource)
        
        # Check for vulnerabilities (MCP without auth)
        for endpoint_info in result['mcp_endpoints']:
            if not endpoint_info.get('auth_required'):
                result['vulnerable'] = True
                break
        
        return result
    
    def test_mcp_connection(self, target_url: str, endpoint: str = '/mcp') -> Dict[str, Any]:
        """
        Test MCP connection with sample tool calls.
        
        Args:
            target_url: URL to test
            endpoint: MCP endpoint to use
            
        Returns:
            Dict with connection test results
        """
        base_url = self._normalize_url(target_url)
        test_url = urljoin(base_url, endpoint)
        
        result = {
            'url': test_url,
            'connected': False,
            'methods_tested': [],
            'capabilities': {},
            'error': None
        }
        
        # Test HTTP endpoint
        http_result = self._http_scan(test_url)
        
        if http_result.get('accessible'):
            # Test tool call
            tool_result = self._test_tool_call(base_url, {'endpoint': endpoint})
            
            if tool_result.get('success'):
                result['connected'] = True
                result['methods_tested'].append('initialize')
                
                # Extract capabilities from response
                if tool_result.get('response'):
                    resp = tool_result['response']
                    if isinstance(resp, dict) and 'result' in resp:
                        result['capabilities'] = resp['result'].get('capabilities', {})
        
        # Test WebSocket if applicable
        if endpoint.endswith('/ws') or '/ws/' in endpoint:
            ws_result = self._websocket_scan(test_url)
            if ws_result.get('accessible'):
                result['connected'] = True
                result['methods_tested'].append('websocket')
                if ws_result.get('tools'):
                    result['capabilities']['tools'] = ws_result['tools']
        
        return result
    
    def get_mcp_summary(self, scan_result: Dict) -> Dict[str, Any]:
        """
        Get a summary of MCP scan results.
        
        Args:
            scan_result: Result from scan()
            
        Returns:
            Dict with summary info
        """
        return {
            'found': scan_result['found'],
            'endpoint_count': len(scan_result['mcp_endpoints']),
            'auth_required': scan_result['auth_required'],
            'auth_type': scan_result['auth_type'],
            'vulnerable': scan_result['vulnerable'],
            'tools_available': len(scan_result['tools_found']),
            'has_exposed_mcp': any(
                not ep.get('auth_required') for ep in scan_result['mcp_endpoints']
            )
        }


def scan_url(url: str, timeout: int = 10, verify_ssl: bool = True) -> Dict[str, Any]:
    """
    Convenience function to scan a URL for MCP endpoints.
    
    Args:
        url: URL to scan
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        
    Returns:
        Dict with scan results
    """
    scanner = MCPScanner(timeout=timeout, verify_ssl=verify_ssl)
    return scanner.scan(url)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python mcp_scanner.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    print(f"Scanning {url} for MCP endpoints...")
    
    result = scan_url(url)
    print(json.dumps(result, indent=2))
    
    if result['found']:
        print(f"\nFound {len(result['mcp_endpoints'])} MCP endpoint(s)")
        for ep in result['mcp_endpoints']:
            auth_str = " (requires auth)" if ep.get('auth_required') else " (no auth)"
            print(f"  - {ep['endpoint']}{auth_str}")
    else:
        print("\nNo MCP endpoints found")
