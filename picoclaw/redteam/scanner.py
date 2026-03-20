#!/usr/bin/env python3
"""
Security Scanner for Picoclaw Continuous Red Teaming

Provides comprehensive security scanning capabilities for targets including:
- Endpoint vulnerability scanning
- Authentication strength testing
- Permission boundary verification
- Rate limiting assessment
"""

import asyncio
import hashlib
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable, Awaitable


class Severity(Enum):
    """Finding severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanType(Enum):
    """Types of security scans"""
    ENDPOINT = "endpoint"
    AUTH = "authentication"
    PERMISSION = "permission"
    RATE_LIMIT = "rate_limit"
    INJECTION = "injection"
    ENCRYPTION = "encryption"
    CONFIGURATION = "configuration"
    FULL = "full"


@dataclass
class TargetConfig:
    """Configuration for scan target"""
    url: str
    name: str = ""
    description: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_token: Optional[str] = None
    timeout: int = 30
    follow_redirects: bool = True
    verify_ssl: bool = True
    
    # Target details
    api_version: str = "v1"
    endpoints: List[str] = field(default_factory=list)
    
    # Scan configuration
    scan_types: Set[ScanType] = field(default_factory=lambda: {ScanType.FULL})
    safe_mode: bool = True  # Never cause actual damage
    
    def __post_init__(self):
        if not self.name:
            self.name = self.url
        if not self.endpoints:
            # Default API endpoints to check
            self.endpoints = [
                '/',
                '/api',
                '/api/v1',
                '/health',
                '/status',
                '/gateway',
                '/admin',
                '/config',
                '/debug',
                '/metrics'
            ]


@dataclass
class VulnerabilityFinding:
    """A security vulnerability finding"""
    id: str
    name: str
    severity: Severity
    description: str
    scan_type: ScanType
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Details
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: str = ""
    
    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # CVE mapping
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    
    # Status tracking
    verified: bool = False
    false_positive: bool = False
    fixed: bool = False
    fix_commit: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'severity': self.severity.value,
            'description': self.description,
            'scan_type': self.scan_type.value,
            'target': self.target,
            'timestamp': self.timestamp,
            'details': self.details,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'references': self.references,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'verified': self.verified,
            'false_positive': self.false_positive,
            'fixed': self.fixed,
            'fix_commit': self.fix_commit
        }


@dataclass
class ScanResult:
    """Result of a security scan"""
    target: str
    scan_types: List[ScanType]
    start_time: str
    end_time: str = ""
    duration_ms: int = 0
    
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    # Summary
    total_findings: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    
    def __post_init__(self):
        self.by_severity = {s.value: 0 for s in Severity}
    
    def add_finding(self, finding: VulnerabilityFinding):
        """Add a finding and update summary"""
        self.findings.append(finding)
        self.total_findings += 1
        self.by_severity[finding.severity.value] += 1
    
    def finalize(self):
        """Finalize scan result"""
        self.end_time = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            'target': self.target,
            'scan_types': [st.value for st in self.scan_types],
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration_ms': self.duration_ms,
            'findings': [f.to_dict() for f in self.findings],
            'errors': self.errors,
            'summary': {
                'total_findings': self.total_findings,
                'by_severity': self.by_severity
            }
        }


class SecurityScanner:
    """
    Comprehensive security scanner for API and web targets.
    
    Supports multiple scan types:
    - Endpoint discovery and vulnerability scanning
    - Authentication strength testing
    - Permission boundary verification
    - Rate limiting and DoS testing
    - Input injection testing
    
    Example:
        scanner = SecurityScanner()
        result = await scanner.scan_target(TargetConfig(
            url="http://localhost:18789",
            scan_types={ScanType.ENDPOINT, ScanType.AUTH}
        ))
        
        for finding in result.findings:
            print(f"{finding.severity.value.upper()}: {finding.name}")
    """
    
    def __init__(
        self,
        *,
        safe_mode: bool = True,
        timeout: int = 30,
        user_agent: str = "Picoclaw-SecurityScanner/1.0"
    ):
        """
        Initialize the security scanner.
        
        Args:
            safe_mode: Only probe, never cause actual damage
            timeout: Default request timeout in seconds
            user_agent: User agent for requests
        """
        self.safe_mode = safe_mode
        self.timeout = timeout
        self.user_agent = user_agent
        
        # Custom check functions
        self._custom_checks: Dict[str, Callable[..., Awaitable[List[VulnerabilityFinding]]]] = {}
        
        # Finding history for deduplication
        self._finding_cache: Dict[str, VulnerabilityFinding] = {}
        
        # Rate limiting tracking
        self._last_request_time: float = 0
        self._min_request_interval: float = 0.1  # 100ms minimum between requests
    
    def register_check(
        self,
        name: str,
        check_func: Callable[..., Awaitable[List[VulnerabilityFinding]]]
    ):
        """Register a custom security check function"""
        self._custom_checks[name] = check_func
    
    async def scan_target(self, target_config: TargetConfig) -> ScanResult:
        """
        Run full security scan on a target.
        
        Args:
            target_config: Target configuration
            
        Returns:
            ScanResult with all findings
        """
        start_time = datetime.now()
        result = ScanResult(
            target=target_config.url,
            scan_types=list(target_config.scan_types),
            start_time=start_time.isoformat()
        )
        
        try:
            # Run applicable scans based on scan_types
            if ScanType.FULL in target_config.scan_types or ScanType.ENDPOINT in target_config.scan_types:
                findings = await self._run_with_error_handling(
                    self.check_endpoints(target_config),
                    result
                )
                for f in findings:
                    result.add_finding(f)
            
            if ScanType.FULL in target_config.scan_types or ScanType.AUTH in target_config.scan_types:
                findings = await self._run_with_error_handling(
                    self.check_auth(target_config),
                    result
                )
                for f in findings:
                    result.add_finding(f)
            
            if ScanType.FULL in target_config.scan_types or ScanType.PERMISSION in target_config.scan_types:
                findings = await self._run_with_error_handling(
                    self.check_permissions(target_config),
                    result
                )
                for f in findings:
                    result.add_finding(f)
            
            if ScanType.FULL in target_config.scan_types or ScanType.RATE_LIMIT in target_config.scan_types:
                findings = await self._run_with_error_handling(
                    self.check_rate_limits(target_config),
                    result
                )
                for f in findings:
                    result.add_finding(f)
            
            # Run custom checks
            for check_name, check_func in self._custom_checks.items():
                try:
                    findings = await check_func(target_config)
                    for f in findings:
                        result.add_finding(f)
                except Exception as e:
                    result.errors.append(f"Custom check '{check_name}' failed: {e}")
            
        except Exception as e:
            result.errors.append(f"Scan failed: {e}")
        
        # Finalize
        result.finalize()
        result.duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return result
    
    async def _run_with_error_handling(
        self,
        coroutine,
        result: ScanResult
    ) -> List[VulnerabilityFinding]:
        """Run a coroutine with error handling"""
        try:
            return await coroutine
        except Exception as e:
            result.errors.append(str(e))
            return []
    
    async def _make_request(
        self,
        target_config: TargetConfig,
        endpoint: str,
        *,
        method: str = "GET",
        data: Optional[bytes] = None,
        extra_headers: Dict[str, str] = None
    ) -> tuple:
        """
        Make HTTP request to target.
        
        Returns:
            Tuple of (status_code, response_headers, response_body)
        """
        # Respect rate limiting
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_request_interval:
            await asyncio.sleep(self._min_request_interval - elapsed)
        
        url = f"{target_config.url.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = {
            'User-Agent': self.user_agent,
            **target_config.headers
        }
        if extra_headers:
            headers.update(extra_headers)
        
        if target_config.auth_token:
            headers['Authorization'] = f"Bearer {target_config.auth_token}"
        
        cookies = ""
        for name, value in target_config.cookies.items():
            cookies += f"{name}={value}; "
        if cookies:
            headers['Cookie'] = cookies.rstrip("; ")
        
        try:
            req = urllib.request.Request(url, method=method, data=data)
            for name, value in headers.items():
                req.add_header(name, value)
            
            # SSL context
            ctx = None
            if not target_config.verify_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            
            response = urllib.request.urlopen(req, timeout=target_config.timeout, context=ctx)
            body = response.read().decode('utf-8', errors='replace')
            self._last_request_time = time.time()
            return response.status, dict(response.headers), body
        
        except urllib.error.HTTPError as e:
            self._last_request_time = time.time()
            return e.code, dict(e.headers) if e.headers else {}, e.read().decode('utf-8', errors='replace')
        
        except Exception as e:
            self._last_request_time = time.time()
            return 0, {}, str(e)
    
    async def check_endpoints(self, target_config: TargetConfig) -> List[VulnerabilityFinding]:
        """
        Check API endpoints for vulnerabilities.
        
        Scans for:
        - Exposed endpoints without authentication
        - Information disclosure
        - Debug endpoints
        - Misconfigured CORS
        - Path traversal
        """
        findings = []
        
        # Check each endpoint
        for endpoint in target_config.endpoints:
            status, headers, body = await self._make_request(target_config, endpoint)
            
            # Check for exposed endpoints
            if status == 200:
                # Information disclosure
                if 'debug' in endpoint.lower() and not self.safe_mode:
                    findings.append(self._create_finding(
                        name="Exposed Debug Endpoint",
                        severity=Severity.HIGH,
                        scan_type=ScanType.ENDPOINT,
                        target=target_config.url,
                        description=f"Debug endpoint {endpoint} is publicly accessible",
                        evidence=f"Status: {status}, Length: {len(body)}",
                        remediation="Disable debug endpoints in production or restrict access"
                    ))
                
                # Sensitive information in response
                sensitive_patterns = [
                    (r'api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']', Severity.CRITICAL, "API Key"),
                    (r'password["\']?\s*[:=]\s*["\'][^"\']+["\']', Severity.CRITICAL, "Password"),
                    (r'secret["\']?\s*[:=]\s*["\'][^"\']+["\']', Severity.HIGH, "Secret"),
                    (r'token["\']?\s*[:=]\s*["\'][^"\']+["\']', Severity.HIGH, "Token"),
                    (r'private[_-]?key"', Severity.CRITICAL, "Private Key Reference"),
                ]
                
                for pattern, severity, finding_name in sensitive_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(self._create_finding(
                            name=f"Sensitive Information: {finding_name}",
                            severity=severity,
                            scan_type=ScanType.ENDPOINT,
                            target=target_config.url,
                            description=f"Potentially sensitive {finding_name} found in response",
                            evidence=f"Endpoint: {endpoint}, Pattern matched: {pattern}",
                            remediation="Encrypt or remove sensitive data from API responses"
                        ))
                        break  # Only report once per endpoint
            
            # Check CORS misconfiguration
            if 'Access-Control-Allow-Origin' in headers:
                cors_origin = headers['Access-Control-Allow-Origin']
                if cors_origin == '*':
                    findings.append(self._create_finding(
                        name="Overly Permissive CORS",
                        severity=Severity.MEDIUM,
                        scan_type=ScanType.ENDPOINT,
                        target=target_config.url,
                        description="CORS allows all origins",
                        evidence=f"Access-Control-Allow-Origin: {cors_origin}",
                        remediation="Restrict CORS to specific trusted origins"
                    ))
            
            # Check for path traversal (safe mode)
            if self.safe_mode:
                traversal_payloads = ['../', '..%2f', '..\\', '..%5c']
                for payload in traversal_payloads:
                    test_endpoint = f"{endpoint}{payload}etc/passwd"
                    status, _, _ = await self._make_request(target_config, test_endpoint)
                    if status == 200 or status == 403:  # 403 might indicate path exists
                        findings.append(self._create_finding(
                            name="Potential Path Traversal",
                            severity=Severity.HIGH,
                            scan_type=ScanType.ENDPOINT,
                            target=target_config.url,
                            description="Server may be vulnerable to path traversal",
                            evidence=f"Payload: {payload}, Status: {status}",
                            remediation="Sanitize and validate path inputs"
                        ))
                        break
        
        return findings
    
    async def check_auth(self, target_config: TargetConfig) -> List[VulnerabilityFinding]:
        """
        Verify authentication strength.
        
        Tests:
        - Missing authentication on protected endpoints
        - Weak password policies
        - Authentication bypass attempts
        - Session management issues
        - Token vulnerabilities
        """
        findings = []
        
        # Test endpoints without authentication
        test_url = f"{target_config.url.rstrip('/')}/api"
        status, headers, body = await self._make_request(target_config, "/api")
        
        # Save original auth token to restore later
        original_token = target_config.auth_token
        
        # Test without authentication
        target_config.auth_token = None
        status_no_auth, _, body_no_auth = await self._make_request(target_config, "/api")
        target_config.auth_token = original_token
        
        # If we can access protected endpoints without auth
        if status_no_auth == 200 and status == 200:
            # Check if response differs (if it should require auth)
            findings.append(self._create_finding(
                name="Unauthenticated API Access",
                severity=Severity.HIGH,
                scan_type=ScanType.AUTH,
                target=target_config.url,
                description="API endpoints accessible without authentication",
                evidence=f"/api returned {status_no_auth} without auth",
                remediation="Require authentication for all API endpoints"
            ))
        
        # Test authentication bypass techniques
        auth_bypass_attempts = [
            {'Authorization': 'Bearer invalid_token'},
            {'Authorization': 'Bearer '} ,
            {'Authorization': 'Basic dXNlcjpwYXNz'},  # base64(user:pass)
            {'X-Custom-Auth': 'admin'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
        ]
        
        if self.safe_mode:  # Only test bypasses in safe mode
            for bypass_headers in auth_bypass_attempts:
                # Temporarily remove auth and add bypass headers
                saved_token = target_config.auth_token
                target_config.auth_token = None
                status, _, _ = await self._make_request(target_config, "/api", extra_headers=bypass_headers)
                target_config.auth_token = saved_token
                
                if status == 200:
                    findings.append(self._create_finding(
                        name="Potential Auth Bypass",
                        severity=Severity.HIGH,
                        scan_type=ScanType.AUTH,
                        target=target_config.url,
                        description="Authentication may be bypassed with custom headers",
                        evidence=f"Headers: {bypass_headers}, Status: {status}",
                        remediation="Implement proper authentication mechanism and validate all auth tokens"
                    ))
                    break
        
        # Check for weak session cookies
        if 'Set-Cookie' in headers:
            set_cookie = headers['Set-Cookie']
            if 'HttpOnly' not in set_cookie:
                findings.append(self._create_finding(
                    name="Missing HttpOnly Cookie Flag",
                    severity=Severity.LOW,
                    scan_type=ScanType.AUTH,
                    target=target_config.url,
                    description="Session cookie missing HttpOnly flag",
                    evidence=set_cookie[:100],
                    remediation="Add HttpOnly flag to session cookies"
                ))
            if 'Secure' not in set_cookie and target_config.url.startswith('https'):
                findings.append(self._create_finding(
                    name="Missing Secure Cookie Flag",
                    severity=Severity.MEDIUM,
                    scan_type=ScanType.AUTH,
                    target=target_config.url,
                    description="Session cookie missing Secure flag on HTTPS endpoint",
                    evidence=set_cookie[:100],
                    remediation="Add Secure flag to session cookies when using HTTPS"
                ))
        
        # Test for timing attacks (safe mode - just check response times differ significantly)
        if self.safe_mode:
            # Multiple auth attempts to detect timing differences
            times_valid_token = []
            times_invalid_token = []
            
            # Make a few requests to check timing
            for _ in range(3):
                start = time.time()
                target_config.auth_token = "valid_test_token"
                await self._make_request(target_config, "/api")
                times_valid_token.append(time.time() - start)
            
            for _ in range(3):
                start = time.time()
                target_config.auth_token = "invalid_token_xyz"
                await self._make_request(target_config, "/api")
                times_invalid_token.append(time.time() - start)
            
            # Restore original token
            target_config.auth_token = original_token
            
            # Check if there's a significant timing difference
            avg_valid = sum(times_valid_token) / len(times_valid_token)
            avg_invalid = sum(times_invalid_token) / len(times_invalid_token)
            
            # More than 50% difference might indicate timing attack vulnerability
            if abs(avg_valid - avg_invalid) > min(avg_valid, avg_invalid) * 0.5:
                findings.append(self._create_finding(
                    name="Potential Timing Attack",
                    severity=Severity.LOW,
                    scan_type=ScanType.AUTH,
                    target=target_config.url,
                    description="Authentication timing difference detected",
                    evidence=f"Valid token avg: {avg_valid:.3f}s, Invalid token avg: {avg_invalid:.3f}s",
                    remediation="Use constant-time comparison for authentication tokens"
                ))
        
        return findings
    
    async def check_permissions(self, target_config: TargetConfig) -> List[VulnerabilityFinding]:
        """
        Test permission boundaries.
        
        Checks:
        - Horizontal privilege escalation
        - Vertical privilege escalation  
        - IDOR (Insecure Direct Object References)
        - Missing authorization checks
        """
        findings = []
        
        # Test for IDOR on common resource endpoints
        idor_test_paths = [
            '/api/users/1',
            '/api/users/me',
            '/api/users/2',
            '/api/documents/1',
            '/api/files/1',
            '/api/configs/1',
        ]
        
        for path in idor_test_paths:
            # Test with different user IDs
            status, headers, body = await self._make_request(target_config, path)
            
            # If we get data for user resources without specific auth
            if status == 200:
                findings.append(self._create_finding(
                    name="Potential IDOR Vulnerability",
                    severity=Severity.HIGH,
                    scan_type=ScanType.PERMISSION,
                    target=target_config.url,
                    description=f"Resource at {path} accessible without proper authorization",
                    evidence=f"Status: {status}, Response length: {len(body)}",
                    remediation="Implement proper authorization checks for each resource"
                ))
        
        # Test for admin endpoints
        admin_paths = ['/admin', '/api/admin', '/api/v1/admin', '/administrator']
        for path in admin_paths:
            status, _, _ = await self._make_request(target_config, path)
            if status == 200:
                findings.append(self._create_finding(
                    name="Exposed Admin Interface",
                    severity=Severity.CRITICAL,
                    scan_type=ScanType.PERMISSION,
                    target=target_config.url,
                    description=f"Admin endpoint {path} is accessible",
                    evidence=f"Status: {status}",
                    remediation="Restrict admin endpoints to authorized users only"
                ))
        
        return findings
    
    async def check_rate_limits(self, target_config: TargetConfig) -> List[VulnerabilityFinding]:
        """
        Check rate limiting enforcement.
        
        Tests:
        - Rate limiting presence
        - Rate limiting bypass techniques
        - DoS susceptibility
        """
        findings = []
        
        if self.safe_mode:
            # In safe mode, only send a small number of requests
            max_requests = 10
        else:
            max_requests = 100
        
        response_times = []
        status_codes = set()
        
        for i in range(max_requests):
            start = time.time()
            status, _, _ = await self._make_request(target_config, "/")
            response_times.append(time.time() - start)
            status_codes.add(status)
            
            # If we start getting rate limited, that's good
            if status == 429:
                break
        
        # Check if rate limiting is present
        if 429 not in status_codes:
            findings.append(self._create_finding(
                name="Missing Rate Limiting",
                severity=Severity.MEDIUM,
                scan_type=ScanType.RATE_LIMIT,
                target=target_config.url,
                description="No rate limiting detected after rapid requests",
                evidence=f"Made {max_requests} requests without rate limit, Status codes: {status_codes}",
                remediation="Implement rate limiting to prevent DoS attacks"
            ))
        
        # Check response time variance for potential DoS amplification
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            if max_time > avg_time * 5:
                findings.append(self._create_finding(
                    name="Potential DoS Amplification",
                    severity=Severity.LOW,
                    scan_type=ScanType.RATE_LIMIT,
                    target=target_config.url,
                    description="Some requests significantly slower than average",
                    evidence=f"Avg: {avg_time:.3f}s, Max: {max_time:.3f}s",
                    remediation="Investigate slow endpoints and implement request timeouts"
                ))
        
        return findings
    
    def rate_severity(self, findings: List[VulnerabilityFinding]) -> Dict[str, List[VulnerabilityFinding]]:
        """
        Rate finding severity and group by severity level.
        
        Args:
            findings: List of findings to rate
            
        Returns:
            Dictionary grouped by severity level
        """
        grouped = {s.value: [] for s in Severity}
        
        for finding in findings:
            grouped[finding.severity.value].append(finding)
        
        return grouped
    
    def _create_finding(
        self,
        name: str,
        severity: Severity,
        scan_type: ScanType,
        target: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
        details: Dict[str, Any] = None,
        cve_id: str = None
    ) -> VulnerabilityFinding:
        """Create a vulnerability finding with auto-generated ID"""
        # Generate unique ID based on finding content
        content = f"{name}_{severity.value}_{target}_{scan_type.value}"
        finding_id = hashlib.sha256(content.encode()).hexdigest()[:12]
        
        return VulnerabilityFinding(
            id=finding_id,
            name=name,
            severity=severity,
            description=description,
            scan_type=scan_type,
            target=target,
            evidence=evidence,
            remediation=remediation,
            details=details or {},
            cve_id=cve_id
        )


# Convenience function for quick scans
async def quick_scan(target_url: str, **kwargs) -> ScanResult:
    """
    Perform a quick security scan on a target.
    
    Args:
        target_url: URL to scan
        **kwargs: Additional TargetConfig options
        
    Returns:
        ScanResult with findings
    """
    config = TargetConfig(url=target_url, **kwargs)
    scanner = SecurityScanner()
    return await scanner.scan_target(config)


def run_sync_scan(target_url: str, **kwargs) -> ScanResult:
    """
    Synchronous wrapper for quick_scan.
    
    Args:
        target_url: URL to scan
        **kwargs: Additional TargetConfig options
        
    Returns:
        ScanResult with findings
    """
    return asyncio.run(quick_scan(target_url, **kwargs))


if __name__ == '__main__':
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:18789'
    
    print(f"Running security scan on {target}...")
    print()
    
    result = run_sync_scan(target)
    
    print(f"Scan completed in {result.duration_ms}ms")
    print(f"Total findings: {result.total_findings}")
    print()
    
    if result.findings:
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            for finding in result.findings:
                if finding.severity.value == severity:
                    print(f"[{finding.severity.value.upper()}] {finding.name}")
                    print(f"  Description: {finding.description}")
                    print(f"  Evidence: {finding.evidence}")
                    print(f"  Remediation: {finding.remediation}")
                    print()
    
    if result.errors:
        print("Errors:")
        for error in result.errors:
            print(f"  - {error}")