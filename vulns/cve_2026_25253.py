#!/usr/bin/env python3
"""
CVE-2026-25253 Detector for Picoclaw
Detects OpenClaw RCE vulnerability through unvalidated gateway URL and WebSocket origin.
"""

import json
import socket
import ssl
from typing import Dict, Any, Optional
import urllib.request
import urllib.error
import urllib.parse


CVE_ID = 'CVE-2026-25253'
CVE_DESCRIPTION = 'OpenClaw Remote Code Execution via Unvalidated Gateway URL'
CVE_SEVERITY = 'CRITICAL'


def check_url_parameter_validation(target: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Check if the target has proper URL parameter validation on /gateway endpoint.
    
    CVE-2026-25253 allows attackers to specify arbitrary gatewayUrl parameter
    which can be used for SSRF or to redirect traffic to malicious servers.
    
    Args:
        target: Target URL (e.g., 'http://localhost:18789')
        timeout: Request timeout in seconds
    
    Returns:
        Dictionary with validation check results
    """
    results = {
        'endpoint_exists': False,
        'accepts_relative_url': False,
        'accepts_external_url': False,
        'accepts_file_url': False,
        'accepts_javascript_url': False,
        'vulnerable_patterns': [],
        'safe_patterns': []
    }
    
    # Test payloads for gatewayUrl parameter
    test_payloads = {
        'relative': {
            'url': '../etc/passwd',
            'description': 'Relative path traversal',
            'severity': 'high'
        },
        'external_http': {
            'url': 'http://evil.com/malicious',
            'description': 'External HTTP URL',
            'severity': 'critical'
        },
        'external_https': {
            'url': 'https://evil.com/malicious',
            'description': 'External HTTPS URL',
            'severity': 'critical'
        },
        'file_scheme': {
            'url': 'file:///etc/passwd',
            'description': 'Local file scheme',
            'severity': 'critical'
        },
        'javascript': {
            'url': 'javascript:alert(1)',
            'description': 'JavaScript protocol',
            'severity': 'medium'
        },
        'data_url': {
            'url': 'data:text/html,<script>alert(1)</script>',
            'description': 'Data URL scheme',
            'severity': 'medium'
        }
    }
    
    try:
        # First check if /gateway endpoint exists
        base_url = target.rstrip('/')
        try:
            req = urllib.request.Request(f'{base_url}/gateway', method='GET')
            urllib.request.urlopen(req, timeout=timeout)
            results['endpoint_exists'] = True
        except urllib.error.HTTPError as e:
            # 404 means endpoint doesn't exist, other errors might mean it does
            results['endpoint_exists'] = e.code != 404
        except:
            pass
        
        if not results['endpoint_exists']:
            # Try POST endpoint
            try:
                req = urllib.request.Request(f'{base_url}/gateway', method='POST')
                req.add_header('Content-Type', 'application/json')
                urllib.request.urlopen(req, timeout=timeout)
                results['endpoint_exists'] = True
            except urllib.error.HTTPError as e:
                results['endpoint_exists'] = e.code not in [404, 405]
            except:
                pass
        
        # Test each payload type
        for payload_type, payload_info in test_payloads.items():
            test_url = f"{base_url}/gateway?gatewayUrl={urllib.parse.quote(payload_info['url'], safe='')}"
            try:
                req = urllib.request.Request(test_url, method='GET')
                req.add_header('User-Agent', 'Picoclaw-VulnScanner/1.0')
                response = urllib.request.urlopen(req, timeout=timeout)
                # If we get a successful response, the URL was accepted
                results[f'accepts_{payload_type}_url'] = True
                results['vulnerable_patterns'].append({
                    'type': payload_type,
                    'description': payload_info['description'],
                    'severity': payload_info['severity'],
                    'url': test_url
                })
            except urllib.error.HTTPError as e:
                if e.code in [400, 403, 422]:
                    # Request rejected - good validation
                    results[f'accepts_{payload_type}_url'] = False
                    results['safe_patterns'].append({
                        'type': payload_type,
                        'description': payload_info['description'],
                        'status_code': e.code
                    })
                else:
                    # Other error codes might indicate the URL was processed
                    results[f'accepts_{payload_type}_url'] = True
                    results['vulnerable_patterns'].append({
                        'type': payload_type,
                        'description': payload_info['description'],
                        'severity': payload_info['severity'],
                        'status_code': e.code
                    })
            except urllib.error.URLError:
                # Connection error - might be SSRF working
                results[f'accepts_{payload_type}_url'] = True
                results['vulnerable_patterns'].append({
                    'type': payload_type,
                    'description': f"{payload_info['description']} - Connection error suggests processing",
                    'severity': 'high'
                })
            except:
                pass
    
    except Exception as e:
        results['error'] = str(e)
    
    return results


def check_websocket_origin_validation(target: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Check if WebSocket connections validate Origin header.
    
    CVE-2026-25253 includes improper WebSocket origin validation allowing
    cross-site WebSocket hijacking (CSWSH).
    
    Args:
        target: Target WebSocket URL (e.g., 'ws://localhost:18789')
        timeout: Connection timeout in seconds
    
    Returns:
        Dictionary with WebSocket validation test results
    """
    results = {
        'websocket_enabled': False,
        'accepts_any_origin': False,
        'accepts_null_origin': False,
        'accepts_cross_origin': False,
        'validates_origin': False,
        'tested_origins': []
    }
    
    # Parse target to get host/port
    try:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        
        if parsed.scheme in ['ws', 'wss']:
            host = parsed.hostname or 'localhost'
            port = parsed.port or (443 if parsed.scheme == 'wss' else 80)
            use_ssl = parsed.scheme == 'wss'
        else:
            # Assume HTTP URL, convert to WS
            parsed = urlparse(target)
            host = parsed.hostname or 'localhost'
            port = parsed.port or (443 if parsed.scheme == 'https' else 18789)
            use_ssl = parsed.scheme == 'https'
            target = f"wss://{host}:{port}/ws" if use_ssl else f"ws://{host}:{port}/ws"
    except:
        return {'error': 'Invalid target URL', 'websocket_enabled': False}
    
    # Test origins
    test_origins = [
        {'origin': 'https://evil.com', 'description': 'External malicious origin', 'expected_block': True},
        {'origin': 'null', 'description': 'Null origin (file:// protocol)', 'expected_block': True},
        {'origin': 'http://localhost', 'description': 'Same-origin localhost', 'expected_block': False},
        {'origin': '', 'description': 'Missing origin header', 'expected_block': True},
        {'origin': 'https://attacker.example.org', 'description': 'Cross-origin HTTPS', 'expected_block': True},
    ]
    
    for test_origin in test_origins:
        origin_result = {
            'origin': test_origin['origin'],
            'description': test_origin['description'],
            'accepted': False,
            'error': None
        }
        
        try:
            # Create socket connection
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # WebSocket handshake with custom Origin
            ws_path = parsed.path or '/ws'
            request = f"GET {ws_path} HTTP/1.1\r\n"
            request += f"Host: {host}:{port}\r\n"
            request += "Upgrade: websocket\r\n"
            request += "Connection: Upgrade\r\n"
            request += "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            request += "Sec-WebSocket-Version: 13\r\n"
            if test_origin['origin']:
                request += f"Origin: {test_origin['origin']}\r\n"
            request += "\r\n"
            
            sock.sendall(request.encode())
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # Check if WebSocket upgrade was accepted
            if '101' in response and 'websocket' in response.lower():
                origin_result['accepted'] = True
                results['websocket_enabled'] = True
                if test_origin['expected_block']:
                    results['accepts_any_origin'] = True
                    if test_origin['origin'] == 'null':
                        results['accepts_null_origin'] = True
                    if 'evil' in test_origin['origin'] or 'attacker' in test_origin['origin']:
                        results['accepts_cross_origin'] = True
            else:
                origin_result['accepted'] = False
                # Check for 403 Forbidden or similar rejection
                if '403' in response:
                    origin_result['error'] = 'Forbidden'
                elif '400' in response:
                    origin_result['error'] = 'Bad Request'
                else:
                    origin_result['error'] = 'Rejected'
        
        except socket.timeout:
            origin_result['error'] = 'Connection timeout'
        except ConnectionRefusedError:
            origin_result['error'] = 'Connection refused'
            results['websocket_enabled'] = False
        except Exception as e:
            origin_result['error'] = str(e)
        
        results['tested_origins'].append(origin_result)
    
    # Determine if origin validation is properly implemented
    blocked_origins = [r for r in results['tested_origins'] if not r['accepted']]
    results['validates_origin'] = (len(blocked_origins) > 0 and 
                                    not results['accepts_cross_origin'] and
                                    not results['accepts_null_origin'])
    
    return results


def check_gateway_ssrf(target: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Check for Server-Side Request Forgery through gateway URL parameter.
    
    Args:
        target: Target URL
        timeout: Request timeout in seconds
    
    Returns:
        Dictionary with SSRF test results
    """
    results = {
        'ssrf_possible': False,
        'internal_access_possible': False,
        'cloud_metadata_accessible': False,
        'findings': []
    }
    
    # SSRF test targets
    ssrf_test_urls = [
        {'url': 'http://127.0.0.1:18789/health', 'description': 'Internal health endpoint', 'type': 'internal'},
        {'url': 'http://localhost:18789/api/status', 'description': 'Internal status endpoint', 'type': 'internal'},
        {'url': 'http://169.254.169.254/latest/meta-data/', 'description': 'AWS metadata', 'type': 'cloud'},
        {'url': 'http://metadata.google.internal/computeMetadata/v1/', 'description': 'GCP metadata', 'type': 'cloud'},
        {'url': 'http://169.254.169.254/metadata/v1/info', 'description': 'Azure metadata', 'type': 'cloud'},
    ]
    
    base_url = target.rstrip('/')
    
    for test in ssrf_test_urls:
        try:
            test_url = f"{base_url}/gateway?gatewayUrl={urllib.parse.quote(test['url'], safe='')}"
            req = urllib.request.Request(test_url)
            req.add_header('User-Agent', 'Picoclaw-VulnScanner/1.0')
            
            response = urllib.request.urlopen(req, timeout=timeout)
            content = response.read().decode('utf-8', errors='ignore')
            
            # If we got a response, SSRF might be possible
            results['ssrf_possible'] = True
            if test['type'] == 'internal':
                results['internal_access_possible'] = True
            elif test['type'] == 'cloud':
                results['cloud_metadata_accessible'] = True
            
            results['findings'].append({
                'url': test['url'],
                'description': test['description'],
                'type': test['type'],
                'status_code': response.status,
                'response_length': len(content),
                'vulnerable': True
            })
        
        except urllib.error.HTTPError as e:
            if e.code not in [400, 403, 422]:
                results['findings'].append({
                    'url': test['url'],
                    'description': test['description'],
                    'type': test['type'],
                    'status_code': e.code,
                    'vulnerable': e.code not in [404, 502, 503]
                })
        except:
            pass
    
    return results


def detect(target: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Main detection function for CVE-2026-25253.
    
    Performs comprehensive vulnerability check for OpenClaw RCE:
    - URL parameter validation on /gateway endpoint
    - WebSocket origin validation
    - Potential SSRF vectors
    
    Args:
        target: Target URL (e.g., 'http://localhost:18789')
        timeout: Request timeout in seconds
    
    Returns:
        Dictionary with vulnerability assessment:
        - vulnerable: bool
        - details: dict with specific vulnerability findings
    """
    result = {
        'cve_id': CVE_ID,
        'description': CVE_DESCRIPTION,
        'severity': CVE_SEVERITY,
        'vulnerable': False,
        'details': {
            'url_validation': None,
            'websocket_validation': None,
            'ssrf_check': None,
            'vulnerabilities_found': [],
            'recommendations': []
        }
    }
    
    # Run all checks
    url_validation = check_url_parameter_validation(target, timeout)
    ws_validation = check_websocket_origin_validation(target, timeout)
    ssrf_check = check_gateway_ssrf(target, timeout)
    
    result['details']['url_validation'] = url_validation
    result['details']['websocket_validation'] = ws_validation
    result['details']['ssrf_check'] = ssrf_check
    
    # Determine overall vulnerability
    vulnerabilities = []
    
    # Check for URL validation issues
    if url_validation.get('vulnerable_patterns'):
        for vuln in url_validation['vulnerable_patterns']:
            if vuln['severity'] in ['critical', 'high']:
                vulnerabilities.append({
                    'type': 'unvalidated_url_parameter',
                    'severity': vuln['severity'],
                    'description': f"Accepts {vuln['description']} without validation",
                    'pattern': vuln['type']
                })
    
    # Check for WebSocket validation issues
    if ws_validation.get('accepts_cross_origin'):
        vulnerabilities.append({
            'type': 'websocket_cswh',
            'severity': 'critical',
            'description': 'WebSocket accepts cross-origin connections without validation',
            'pattern': 'cross_origin_accepted'
        })
    
    if ws_validation.get('accepts_null_origin'):
        vulnerabilities.append({
            'type': 'websocket_null_origin',
            'severity': 'high',
            'description': 'WebSocket accepts null origin (allows file:// protocol attacks)',
            'pattern': 'null_origin_accepted'
        })
    
    # Check for SSRF
    if ssrf_check.get('internal_access_possible'):
        vulnerabilities.append({
            'type': 'ssrf_internal',
            'severity': 'critical',
            'description': 'SSRF allows access to internal services',
            'pattern': 'internal_access'
        })
    
    if ssrf_check.get('cloud_metadata_accessible'):
        vulnerabilities.append({
            'type': 'ssrf_cloud_metadata',
            'severity': 'critical',
            'description': 'SSRF allows access to cloud metadata services',
            'pattern': 'cloud_metadata'
        })
    
    result['details']['vulnerabilities_found'] = vulnerabilities
    result['vulnerable'] = len(vulnerabilities) > 0
    
    # Generate recommendations
    recommendations = []
    if vulnerabilities:
        if any(v['type'] == 'unvalidated_url_parameter' for v in vulnerabilities):
            recommendations.append('Implement strict URL whitelist validation for gatewayUrl parameter')
            recommendations.append('Reject URLs with non-HTTP(S) schemes (file://, javascript:, data:, etc.)')
            recommendations.append('Validate URL host against allowed list')
        
        if any(v['type'] in ['websocket_cswh', 'websocket_null_origin'] for v in vulnerabilities):
            recommendations.append('Implement WebSocket Origin header validation')
            recommendations.append('Reject connections with null or untrusted origins')
            recommendations.append('Use CSRF tokens for WebSocket connections')
        
        if any('ssrf' in v['type'] for v in vulnerabilities):
            recommendations.append('Implement URL scheme whitelist (only allow http/https)')
            recommendations.append('Block requests to private IP ranges')
            recommendations.append('Block requests to cloud metadata endpoints')
    
    result['details']['recommendations'] = recommendations
    
    return result


if __name__ == '__main__':
    import sys
    
    # Test with local gateway
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:18789'
    
    print(f"Scanning {target} for {CVE_ID}...")
    print()
    
    result = detect(target)
    
    print(f"Vulnerable: {result['vulnerable']}")
    print(f"Severity: {result['severity']}")
    print()
    
    if result['vulnerable']:
        print("Vulnerabilities found:") 
        for vuln in result['details']['vulnerabilities_found']:
            print(f"  - [{vuln['severity'].upper()}] {vuln['description']}")
        print()
        print("Recommendations:")
        for rec in result['details']['recommendations']:
            print(f"  - {rec}")
    else:
        print("No vulnerabilities detected.")
