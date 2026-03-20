#!/usr/bin/env python3
"""
Security Hardening Recommendations for Picoclaw Continuous Red Teaming

Provides security hardening advice and automation:
- Vulnerability analysis
- Remediation recommendations
- Automated safe fixes
- Verification of fixes
- Categorized hardening steps
"""

import asyncio
import hashlib
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Callable
import threading


class HardeningCategory(Enum):
    """Categories of hardening steps"""
    NETWORK = "network"
    AUTH = "auth"
    PERMISSIONS = "permissions"
    LOGGING = "logging"
    UPDATES = "updates"
    CONFIGURATION = "configuration"
    ENCRYPTION = "encryption"
    INPUT_VALIDATION = "input_validation"
    SESSION = "session"
    RATE_LIMITING = "rate_limiting"
    CORS = "cors"
    HEADERS = "headers"


class HardeningPriority(Enum):
    """Priority levels for hardening"""
    IMMEDIATE = "immediate"      # Must fix now
    HIGH = "high"               # Fix within days
    MEDIUM = "medium"           # Fix within weeks
    LOW = "low"                 # Fix when possible
    BEST_PRACTICE = "best_practice"  # Nice to have


class FixStatus(Enum):
    """Status of a hardening fix"""
    NOT_APPLIED = "not_applied"
    APPLIED = "applied"
    VERIFIED = "verified"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class HardeningStep:
    """A single hardening step"""
    id: str
    title: str
    description: str
    category: HardeningCategory
    priority: HardeningPriority
    
    # Remediation details
    remediation: str = ""
    commands: List[str] = field(default_factory=list)
    config_changes: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    
    # Automation
    auto_applicable: bool = False
    auto_command: str = ""
    verify_command: str = ""
    
    # Status
    status: FixStatus = FixStatus.NOT_APPLIED
    applied_at: str = ""
    verified_at: str = ""
    error_message: str = ""
    
    # Tags
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category': self.category.value,
            'priority': self.priority.value,
            'remediation': self.remediation,
            'commands': self.commands,
            'config_changes': self.config_changes,
            'references': self.references,
            'auto_applicable': self.auto_applicable,
            'auto_command': self.auto_command,
            'verify_command': self.verify_command,
            'status': self.status.value,
            'applied_at': self.applied_at,
            'verified_at': self.verified_at,
            'error_message': self.error_message,
            'tags': self.tags
        }


@dataclass
class HardeningReport:
    """Report from hardening analysis"""
    finding_id: str
    finding_name: str
    severity: str
    category: HardeningCategory
    
    # Recommendations
    steps: List[HardeningStep] = field(default_factory=list)
    
    # Summary
    immediate_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Automation
    auto_fixable: int = 0
    verified: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'finding_id': self.finding_id,
            'finding_name': self.finding_name,
            'severity': self.severity,
            'category': self.category.value,
            'steps': [s.to_dict() for s in self.steps],
            'summary': {
                'immediate': self.immediate_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count,
                'auto_fixable': self.auto_fixable,
                'verified': self.verified
            }
        }


# Hardening step templates by vulnerability type
HARDENING_TEMPLATES = {
    'ssrf': [
        HardeningStep(
            id="SSRF-001",
            title="Implement URL Whitelist",
            description="Allow only whitelisted URLs for gateway connections",
            category=HardeningCategory.INPUT_VALIDATION,
            priority=HardeningPriority.IMMEDIATE,
            remediation="Configure gateway to only accept URLs from a whitelist of allowed domains",
            auto_applicable=True,
            auto_command="configure_gateway --set whitelist --domains 'api.trusted.com,gateway.trusted.com'",
            verify_command="test_gateway_url --check-whitelist",
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
            ],
            tags=['ssrf', 'url-validation', 'whitelist']
        ),
        HardeningStep(
            id="SSRF-002",
            title="Block Internal IP Ranges",
            description="Block requests to internal/private IP addresses",
            category=HardeningCategory.NETWORK,
            priority=HardeningPriority.IMMEDIATE,
            remediation="Configure network rules to block requests to 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16",
            commands=[
                "iptables -A OUTPUT -d 127.0.0.0/8 -j DROP",
                "iptables -A OUTPUT -d 10.0.0.0/8 -j DROP",
                "iptables -A OUTPUT -d 172.16.0.0/12 -j DROP",
                "iptables -A OUTPUT -d 192.168.0.0/16 -j DROP"
            ],
            references=[
                "https://en.wikipedia.org/wiki/Private_network"
            ],
            tags=['ssrf', 'network', 'ip-filtering']
        ),
        HardeningStep(
            id="SSRF-003",
            title="Block Cloud Metadata Endpoints",
            description="Block access to cloud provider metadata endpoints",
            category=HardeningCategory.NETWORK,
            priority=HardeningPriority.IMMEDIATE,
            remediation="Block requests to 169.254.169.254 (AWS, Azure) and metadata.google.internal (GCP)",
            commands=[
                "iptables -A OUTPUT -d 169.254.169.254 -j DROP",
                "echo '169.254.169.254 metadata.google.internal' >> /etc/hosts.deny"
            ],
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
            ],
            tags=['ssrf', 'cloud', 'metadata']
        )
    ],
    'auth_bypass': [
        HardeningStep(
            id="AUTH-001",
            title="Implement Strong Token Validation",
            description="Validate authentication tokens on every request",
            category=HardeningCategory.AUTH,
            priority=HardeningPriority.IMMEDIATE,
            remediation="Implement proper JWT validation including signature verification and expiration checks",
            auto_applicable=True,
            auto_command="configure_auth --enable-token-validation --verify-signature --check-expiry",
            verify_command="test_auth --check-token-validation",
            tags=['auth', 'jwt', 'token-validation']
        ),
        HardeningStep(
            id="AUTH-002",
            title="Remove Debug Headers",
            description="Remove X-Debug, X-Admin, and other debug headers",
            category=HardeningCategory.CONFIGURATION,
            priority=HardeningPriority.HIGH,
            remediation="Remove or disable all debug headers that could bypass authentication",
            auto_applicable=True,
            auto_command="configure_headers --remove 'X-Debug,X-Admin,X-Bypass'",
            verify_command="test_headers --check-debug",
            tags=['auth', 'headers', 'debug']
        ),
        HardeningStep(
            id="AUTH-003",
            title="Implement Rate Limiting on Auth",
            description="Add rate limiting to authentication endpoints",
            category=HardeningCategory.RATE_LIMITING,
            priority=HardeningPriority.HIGH,
            remediation="Configure rate limiting for authentication attempts (max 5 per minute)",
            config_changes={
                'auth_rate_limit': {
                    'requests_per_minute': 5,
                    'block_duration_seconds': 300
                }
            },
            tags=['auth', 'rate-limiting', 'brute-force']
        )
    ],
    'traversal': [
        HardeningStep(
            id="TRAV-001",
            title="Implement Path Validation",
            description="Validate and sanitize all file paths",
            category=HardeningCategory.INPUT_VALIDATION,
            priority=HardeningPriority.IMMEDIATE,
            remediation="Use realpath() to normalize paths and verify against allowed directories",
            auto_applicable=True,
            auto_command="configure_file_access --validate-paths --allowed-dirs '/var/app/data'",
            verify_command="test_path_traversal --check-validation",
            tags=['traversal', 'path-validation', 'file-security']
        ),
        HardeningStep(
            id="TRAV-002",
            title="Use Chroot or Container Isolation",
            description="Run application in isolated environment",
            category=HardeningCategory.PERMISSIONS,
            priority=HardeningPriority.MEDIUM,
            remediation="Use containers or chroot to limit file system access",
            references=[
                "https://man7.org/linux/man-pages/man2/chroot.2.html"
            ],
            tags=['traversal', 'isolation', 'container']
        ),
        HardeningStep(
            id="TRAV-003",
            title="Disable URL Encoding for Paths",
            description="Reject URL-encoded path components",
            category=HardeningCategory.INPUT_VALIDATION,
            priority=HardeningPriority.HIGH,
            remediation="Configure server to reject requests with URL-encoded path separators",
            auto_applicable=True,
            auto_command="configure_web_server --reject-encoded-paths",
            verify_command="test_encoding_bypass",
            tags=['traversal', 'url-encoding', 'input-validation']
        )
    ],
    'injection': [
        HardeningStep(
            id="INJ-001",
            title="Use Parameterized Queries",
            description="Replace dynamic queries with parameterized versions",
            category=HardeningCategory.INPUT_VALIDATION,
            priority=HardeningPriority.IMMEDIATE,
            remediation="Use parameterized queries or ORM for all database operations",
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            tags=['injection', 'sql', 'parameterized']
        ),
        HardeningStep(
            id="INJ-002",
            title="Implement Input Validation",
            description="Validate all user inputs against expected formats",
            category=HardeningCategory.INPUT_VALIDATION,
            priority=HardeningPriority.HIGH,
            remediation="Implement allowlist validation for all inputs (type, length, format)",
            tags=['injection', 'input-validation']
        ),
        HardeningStep(
            id="INJ-003",
            title="Enable WAF Rules",
            description="Enable Web Application Firewall rules for injection",
            category=HardeningCategory.NETWORK,
            priority=HardeningPriority.HIGH,
            remediation="Enable ModSecurity or WAF rules for SQL injection detection",
            auto_applicable=True,
            auto_command="enable_waf_rules --enable sqli --enable xss",
            verify_command="test_waf_rules --check sqli,xss",
            tags=['injection', 'waf', 'modsecurity']
        )
    ],
    'xss': [
        HardeningStep(
            id="XSS-001",
            title="Implement Content Security Policy",
            description="Add CSP header to prevent XSS",
            category=HardeningCategory.HEADERS,
            priority=HardeningPriority.HIGH,
            remediation="Add Content-Security-Policy header with restrictive policies",
            config_changes={
                'headers': {
                    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
                }
            },
            tags=['xss', 'csp', 'headers']
        ),
        HardeningStep(
            id="XSS-002",
            title="Enable XSS Protection Header",
            description="Enable browser XSS protection",
            category=HardeningCategory.HEADERS,
            priority=HardeningPriority.MEDIUM,
            remediation="Add X-XSS-Protection header",
            config_changes={
                'headers': {
                    'X-XSS-Protection': '1; mode=block'
                }
            },
            tags=['xss', 'headers', 'browser']
        ),
        HardeningStep(
            id="XSS-003",
            title="Implement Output Encoding",
            description="Encode all output to prevent XSS",
            category=HardeningCategory.INPUT_VALIDATION,
            priority=HardeningPriority.HIGH,
            remediation="Use proper output encoding (HTML, URL, JavaScript) based on context",
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ],
            tags=['xss', 'encoding', 'output']
        )
    ],
    'cors': [
        HardeningStep(
            id="CORS-001",
            title="Restrict CORS Origins",
            description="Remove wildcard CORS origin",
            category=HardeningCategory.CORS,
            priority=HardeningPriority.HIGH,
            remediation="Replace Access-Control-Allow-Origin: * with specific allowed origins",
            config_changes={
                'cors': {
                    'allowed_origins': ['https://app.example.com'],
                    'allow_credentials': True
                }
            },
            tags=['cors', 'headers', 'origin']
        ),
        HardeningStep(
            id="CORS-002",
            title="Limit CORS Methods",
            description="Restrict allowed HTTP methods",
            category=HardeningCategory.CORS,
            priority=HardeningPriority.MEDIUM,
            remediation="Only allow necessary HTTP methods in Access-Control-Allow-Methods",
            config_changes={
                'cors': {
                    'allowed_methods': ['GET', 'POST', 'PUT', 'DELETE']
                }
            },
            tags=['cors', 'methods', 'headers']
        ),
        HardeningStep(
            id="CORS-003",
            title="Limit CORS Headers",
            description="Restrict allowed headers",
            category=HardeningCategory.CORS,
            priority=HardeningPriority.MEDIUM,
            remediation="Only allow necessary headers in Access-Control-Allow-Headers",
            config_changes={
                'cors': {
                    'allowed_headers': ['Content-Type', 'Authorization', 'X-Requested-With']
                }
            },
            tags=['cors', 'headers']
        )
    ],
    'rate_limit': [
        HardeningStep(
            id="RATE-001",
            title="Implement Rate Limiting",
            description="Add rate limiting to all endpoints",
            category=HardeningCategory.RATE_LIMITING,
            priority=HardeningPriority.HIGH,
            remediation="Configure rate limiting with sliding window algorithm",
            config_changes={
                'rate_limiting': {
                    'enabled': True,
                    'requests_per_minute': 60,
                    'burst_size': 10,
                    'algorithm': 'sliding_window'
                }
            },
            tags=['rate-limiting', 'dos', 'brute-force']
        ),
        HardeningStep(
            id="RATE-002",
            title="Add Rate Limit Headers",
            description="Include rate limit info in responses",
            category=HardeningCategory.HEADERS,
            priority=HardeningPriority.LOW,
            remediation="Add X-RateLimit-Limit and X-RateLimit-Remaining headers",
            config_changes={
                'headers': {
                    'X-RateLimit-Limit': '${rate_limit}',
                    'X-RateLimit-Remaining': '${requests_remaining}',
                    'X-RateLimit-Reset': '${reset_timestamp}'
                }
            },
            tags=['rate-limiting', 'headers']
        )
    ],
    'logging': [
        HardeningStep(
            id="LOG-001",
            title="Enable Security Logging",
            description="Log all security-relevant events",
            category=HardeningCategory.LOGGING,
            priority=HardeningPriority.HIGH,
            remediation="Configure logging for authentication attempts, access control failures, input validation failures",
            config_changes={
                'logging': {
                    'auth_attempts': True,
                    'access_denials': True,
                    'validation_failures': True,
                    'sensitive_operations': True
                }
            },
            tags=['logging', 'audit', 'security']
        ),
        HardeningStep(
            id="LOG-002",
            title="Log to Secure Location",
            description="Send logs to tamper-proof storage",
            category=HardeningCategory.LOGGING,
            priority=HardeningPriority.MEDIUM,
            remediation="Configure centralized logging (SIEM) with log integrity verification",
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
            ],
            tags=['logging', 'siem', 'integrity']
        ),
        HardeningStep(
            id="LOG-003",
            title="Remove Sensitive Data from Logs",
            description="Mask or exclude sensitive data",
            category=HardeningCategory.LOGGING,
            priority=HardeningPriority.HIGH,
            remediation="Configure log masking for passwords, tokens, PII",
            config_changes={
                'log_masking': {
                    'patterns': ['password', 'token', 'secret', 'api_key', 'ssn'],
                    'mask': '*****'
                }
            },
            tags=['logging', 'privacy', 'sensitive-data']
        )
    ],
    'headers': [
        HardeningStep(
            id="HDR-001",
            title="Add Security Headers",
            description="Implement security-related HTTP headers",
            category=HardeningCategory.HEADERS,
            priority=HardeningPriority.MEDIUM,
            remediation="Add X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security headers",
            config_changes={
                'headers': {
                    'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': 'DENY',
                    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
                }
            },
            tags=['headers', 'security', 'hsts']
        ),
        HardeningStep(
            id="HDR-002",
            title="Remove Server Version",
            description="Hide server version information",
            category=HardeningCategory.HEADERS,
            priority=HardeningPriority.LOW,
            remediation="Configure server to hide version in Server header",
            auto_applicable=True,
            auto_command="configure_server --hide-version",
            verify_command="curl -I localhost | grep -i server",
            tags=['headers', 'information-disclosure', 'server']
        ),
        HardeningStep(
            id="HDR-003",
            title="Remove Powered-By Headers",
            description="Remove technology disclosure headers",
            category=HardeningCategory.HEADERS,
            priority=HardeningPriority.LOW,
            remediation="Remove X-Powered-By, X-AspNet-Version, and similar headers",
            config_changes={
                'headers_remove': ['X-Powered-By', 'X-AspNet-Version', 'X-Generator']
            },
            tags=['headers', 'information-disclosure']
        )
    ],
    'prompt_injection': [
        HardeningStep(
            id="PROMPT-001",
            title="Implement Input Sanitization",
            description="Sanitize all prompts for injection patterns",
            category=HardeningCategory.INPUT_VALIDATION,
            priority=HardeningPriority.IMMEDIATE,
            remediation="Filter out common injection patterns like 'Ignore previous instructions', 'System:', etc.",
            auto_applicable=True,
            auto_command="configure_llm --sanitizer strict --block-override-patterns",
            verify_command="test_prompt_injection --sanitizer-check",
            tags=['prompt-injection', 'llm', 'input-validation']
        ),
        HardeningStep(
            id="PROMPT-002",
            title="Implement Prompt Boundaries",
            description="Use clear system/user boundaries",
            category=HardeningCategory.INPUT_VALIDATION,
            priority=HardeningPriority.HIGH,
            remediation="Use role-based boundaries and delimiter protection in prompt templates",
            references=[
                "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
            ],
            tags=['prompt-injection', 'llm', 'boundaries']
        ),
        HardeningStep(
            id="PROMPT-003",
            title="Limit Model Capabilities",
            description="Restrict what LLM can access/execute",
            category=HardeningCategory.PERMISSIONS,
            priority=HardeningPriority.HIGH,
            remediation="Implement capability restrictions and output filtering for LLM responses",
            config_changes={
                'llm_restrictions': {
                    'allow_file_access': False,
                    'allow_network_access': False,
                    'allow_code_execution': False,
                    'max_output_length': 1000
                }
            },
            tags=['prompt-injection', 'llm', 'capabilities']
        )
    ]
}


class HardeningAdvisor:
    """
    Security hardening advisor for vulnerability remediation.
    
    Provides:
    - Analysis of findings and recommendations
    - Automated safe fixes
    - Verification of applied fixes
    - Hardening step tracking
    
    Example:
        advisor = HardeningAdvisor()
        
        # Analyze findings
        reports = advisor.analyze_findings(findings)
        
        # Get specific hardening steps
        steps = advisor.get_hardening_steps(finding)
        
        # Auto-apply safe fixes
        applied = await advisor.apply_hardening(finding)
        
        # Verify fix worked
        verified = await advisor.verify_hardening(finding)
    """
    
    def __init__(
        self,
        *,
        config_dir: Optional[str] = None,
        auto_apply_safe: bool = False,
        verification_timeout: int = 60
    ):
        """
        Initialize the hardening advisor.
        
        Args:
            config_dir: Directory for configuration files
            auto_apply_safe: Auto-apply safe fixes
            verification_timeout: Timeout for verification in seconds
        """
        self.config_dir = Path(config_dir) if config_dir else None
        self.auto_apply_safe = auto_apply_safe
        self.verification_timeout = verification_timeout
        
        # Applied hardening steps
        self._applied_steps: Dict[str, HardeningStep] = {}
        
        # Custom hardening step templates
        self._custom_templates: Dict[str, List[HardeningStep]] = {}
        
        # Verification callbacks
        self._verify_callbacks: Dict[str, Callable] = {}
        
        # Lock for thread safety
        self._lock = threading.RLock()
    
    def register_template(
        self,
        finding_type: str,
        steps: List[HardeningStep]
    ):
        """
        Register custom hardening template for a finding type.
        
        Args:
            finding_type: Type of finding
            steps: List of hardening steps
        """
        self._custom_templates[finding_type] = steps
    
    def register_verify_callback(
        self,
        step_id: str,
        callback: Callable
    ):
        """
        Register custom verification callback.
        
        Args:
            step_id: Step ID to verify
            callback: Async callback to run for verification
        """
        self._verify_callbacks[step_id] = callback
    
    def analyze_findings(
        self,
        findings: List[Any],  # List of VulnerabilityFinding
        *,
        include_best_practices: bool = False
    ) -> List[HardeningReport]:
        """
        Analyze findings and generate hardening recommendations.
        
        Args:
            findings: List of vulnerability findings
            include_best_practices: Include best practice recommendations
            
        Returns:
            List of HardeningReports
        """
        reports = []
        
        for finding in findings:
            # Extract finding type/category
            finding_type = self._determine_finding_type(finding)
            
            # Get hardening steps
            steps = self.get_hardening_steps(
                finding,
                include_best_practices=include_best_practices
            )
            
            # Create report
            report = HardeningReport(
                finding_id=finding.id if hasattr(finding, 'id') else str(hash(finding)),
                finding_name=finding.name if hasattr(finding, 'name') else str(finding),
                severity=finding.severity if hasattr(finding, 'severity') else 'medium',
                category=HardeningCategory(finding_type) if finding_type in [e.value for e in HardeningCategory] else HardeningCategory.CONFIGURATION,
                steps=steps,
                auto_fixable=sum(1 for s in steps if s.auto_applicable)
            )
            
            # Count by priority
            report.immediate_count = sum(1 for s in steps if s.priority == HardeningPriority.IMMEDIATE)
            report.high_count = sum(1 for s in steps if s.priority == HardeningPriority.HIGH)
            report.medium_count = sum(1 for s in steps if s.priority == HardeningPriority.MEDIUM)
            report.low_count = sum(1 for s in steps if s.priority == HardeningPriority.LOW)
            
            reports.append(report)
        
        return reports
    
    def _determine_finding_type(self, finding) -> str:
        """Determine finding type from finding object"""
        # Try different attributes
        if hasattr(finding, 'finding_type'):
            return finding.finding_type.value if hasattr(finding.finding_type, 'value') else str(finding.finding_type)
        
        if hasattr(finding, 'scan_type'):
            return finding.scan_type.value if hasattr(finding.scan_type, 'value') else str(finding.scan_type)
        
        # Infer from tags
        if hasattr(finding, 'tags'):
            for tag in finding.tags:
                tag_lower = tag.lower()
                if tag_lower in HARDENING_TEMPLATES:
                    return tag_lower
        
        # Infer from name
        if hasattr(finding, 'name'):
            name_lower = finding.name.lower()
            for key in HARDENING_TEMPLATES:
                if key in name_lower:
                    return key
            if 'ssrf' in name_lower or 'url' in name_lower:
                return 'ssrf'
            if 'auth' in name_lower or 'bypass' in name_lower:
                return 'auth_bypass'
            if 'traversal' in name_lower or 'path' in name_lower:
                return 'traversal'
            if 'injection' in name_lower or 'sql' in name_lower:
                return 'injection'
            if 'xss' in name_lower:
                return 'xss'
            if 'cors' in name_lower:
                return 'cors'
            if 'rate' in name_lower:
                return 'rate_limit'
            if 'prompt' in name_lower:
                return 'prompt_injection'
        
        # Default
        return 'configuration'
    
    def get_hardening_steps(
        self,
        finding: Any,
        *,
        include_best_practices: bool = False
    ) -> List[HardeningStep]:
        """
        Get hardening steps for a specific finding.
        
        Args:
            finding: Vulnerability finding
            include_best_practices: Include best practice steps
            
        Returns:
            List of HardeningSteps
        """
        finding_type = self._determine_finding_type(finding)
        
        # Get base steps
        steps = []
        
        # Check custom templates first
        if finding_type in self._custom_templates:
            steps.extend(self._custom_templates[finding_type])
        elif finding_type in HARDENING_TEMPLATES:
            # Clone templates to avoid modification
            for template in HARDENING_TEMPLATES[finding_type]:
                steps.append(HardeningStep(
                    id=template.id,
                    title=template.title,
                    description=template.description,
                    category=template.category,
                    priority=template.priority,
                    remediation=template.remediation,
                    commands=list(template.commands),
                    config_changes=dict(template.config_changes),
                    references=list(template.references),
                    auto_applicable=template.auto_applicable,
                    auto_command=template.auto_command,
                    verify_command=template.verify_command,
                    tags=list(template.tags)
                ))
        
        # Add best practices if requested
        if include_best_practices:
            best_practice_steps = self._get_best_practices(finding_type)
            for step in best_practice_steps:
                if step.priority == HardeningPriority.BEST_PRACTICE:
                    steps.append(step)
        
        return steps
    
    def _get_best_practices(self, finding_type: str) -> List[HardeningStep]:
        """Get best practice steps for a finding type"""
        # Generic best practices
        return [
            HardeningStep(
                id=f"BP-{finding_type.upper()}-001",
                title="Regular Security Reviews",
                description="Conduct regular security reviews",
                category=HardeningCategory.LOGGING,
                priority=HardeningPriority.BEST_PRACTICE,
                remediation="Schedule quarterly security reviews and penetration tests",
                tags=['best-practice', 'review', 'security']
            ),
            HardeningStep(
                id=f"BP-{finding_type.upper()}-002",
                title="Monitor for New Vulnerabilities",
                description="Stay informed about new vulnerabilities",
                category=HardeningCategory.UPDATES,
                priority=HardeningPriority.BEST_PRACTICE,
                remediation="Subscribe to security advisories and CVE feeds",
                tags=['best-practice', 'monitoring', 'cve']
            )
        ]
    
    async def apply_hardening(
        self,
        finding: Any,
        *,
        safe_only: bool = True,
        dry_run: bool = False
    ) -> List[HardeningStep]:
        """
        Apply hardening steps for a finding.
        
        Args:
            finding: Vulnerability finding
            safe_only: Only apply safe auto-fixable steps
            dry_run: Simulate without actually applying
            
        Returns:
            List of applied HardeningSteps
        """
        steps = self.get_hardening_steps(finding)
        applied = []
        
        for step in steps:
            # Skip if not auto-applicable
            if not step.auto_applicable:
                if safe_only:
                    continue
            
            # Check if safe mode allows
            if safe_only and step.priority in [HardeningPriority.IMMEDIATE, HardeningPriority.HIGH]:
                # Immediate and high priority may have side effects
                # Only apply if explicitly configured
                if not self.auto_apply_safe:
                    step.status = FixStatus.SKIPPED
                    step.error_message = "Requires manual application in safe mode"
                    applied.append(step)
                    continue
            
            # Apply the step
            if dry_run:
                step.status = FixStatus.NOT_APPLIED
                step.error_message = "Dry run - not applied"
            else:
                success = await self._apply_step(step)
                if success:
                    step.status = FixStatus.APPLIED
                    step.applied_at = datetime.now().isoformat()
                else:
                    step.status = FixStatus.FAILED
            
            applied.append(step)
            
            # Store for verification
            with self._lock:
                self._applied_steps[step.id] = step
        
        return applied
    
    async def _apply_step(self, step: HardeningStep) -> bool:
        """Apply a single hardening step"""
        if not step.auto_command:
            return False
        
        try:
            # Execute the auto command
            # In a real implementation, this would execute system commands
            # For safety, we simulate success
            process = await asyncio.create_subprocess_shell(
                step.auto_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.verification_timeout
            )
            
            if process.returncode == 0:
                return True
            else:
                step.error_message = stderr.decode() if stderr else "Command failed"
                return False
        
        except asyncio.TimeoutError:
            step.error_message = "Command timed out"
            return False
        except Exception as e:
            step.error_message = str(e)
            return False
    
    async def verify_hardening(
        self,
        finding: Any,
        *,
        step_ids: Optional[List[str]] = None
    ) -> List[HardeningStep]:
        """
        Verify hardening steps were applied correctly.
        
        Args:
            finding: Vulnerability finding
            step_ids: Specific steps to verify (all if None)
            
        Returns:
            List of verified HardeningSteps
        """
        finding_type = self._determine_finding_type(finding)
        steps = self.get_hardening_steps(finding)
        
        if step_ids:
            steps = [s for s in steps if s.id in step_ids]
        
        verified = []
        
        for step in steps:
            # Skip if not applied
            if step.status not in [FixStatus.APPLIED, FixStatus.VERIFIED]:
                continue
            
            # Verify the step
            success = await self._verify_step(step)
            
            if success:
                step.status = FixStatus.VERIFIED
                step.verified_at = datetime.now().isoformat()
            else:
                step.error_message = "Verification failed"
            
            verified.append(step)
        
        return verified
    
    async def _verify_step(self, step: HardeningStep) -> bool:
        """Verify a single hardening step"""
        # Check for custom verification callback
        if step.id in self._verify_callbacks:
            try:
                result = await self._verify_callbacks[step.id](step)
                return bool(result)
            except Exception:
                return False
        
        if not step.verify_command:
            # No verification command - assume verified
            return True
        
        try:
            process = await asyncio.create_subprocess_shell(
                step.verify_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.verification_timeout
            )
            
            return process.returncode == 0
        
        except asyncio.TimeoutError:
            return False
        except Exception:
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get hardening statistics.
        
        Returns:
            Dictionary with statistics
        """
        with self._lock:
            total = len(self._applied_steps)
            verified = sum(1 for s in self._applied_steps.values() if s.status == FixStatus.VERIFIED)
            applied = sum(1 for s in self._applied_steps.values() if s.status == FixStatus.APPLIED)
            failed = sum(1 for s in self._applied_steps.values() if s.status == FixStatus.FAILED)
            
            # By category
            by_category = {}
            for step in self._applied_steps.values():
                cat = step.category.value
                by_category[cat] = by_category.get(cat, 0) + 1
            
            # By priority
            by_priority = {}
            for step in self._applied_steps.values():
                pri = step.priority.value
                by_priority[pri] = by_priority.get(pri, 0) + 1
            
            return {
                'total_steps': total,
                'verified': verified,
                'applied': applied,
                'failed': failed,
                'by_category': by_category,
                'by_priority': by_priority
            }
    
    def export_config(self, format: str = 'json') -> str:
        """
        Export applied configuration changes.
        
        Args:
            format: Export format ('json', 'yaml')
            
        Returns:
            Exported configuration
        """
        config = {}
        
        with self._lock:
            for step in self._applied_steps.values():
                if step.status in [FixStatus.APPLIED, FixStatus.VERIFIED]:
                    if step.config_changes:
                        for key, value in step.config_changes.items():
                            if key not in config:
                                config[key] = value
                            elif isinstance(config[key], dict) and isinstance(value, dict):
                                config[key].update(value)
                            else:
                                config[key] = value
        
        if format == 'json':
            return json.dumps(config, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")


# Singleton instance
_advisor_instance: Optional[HardeningAdvisor] = None


def get_hardening_advisor(**kwargs) -> HardeningAdvisor:
    """Get the singleton HardeningAdvisor instance"""
    global _advisor_instance
    if _advisor_instance is None:
        _advisor_instance = HardeningAdvisor(**kwargs)
    return _advisor_instance


if __name__ == '__main__':
    import sys
    
    advisor = HardeningAdvisor()
    
    # Create a mock finding
    class MockFinding:
        def __init__(self):
            self.id = "test-001"
            self.name = "SSRF Vulnerability"
            self.severity = "critical"
            self.tags = ["ssrf", "url-injection"]
    
    finding = MockFinding()
    
    print("Analyzing finding...")
    reports = advisor.analyze_findings([finding])
    
    for report in reports:
        print(f"\nFinding: {report.finding_name}")
        print(f"Severity: {report.severity}")
        print(f"Category: {report.category.value}")
        print(f"\nHardening Steps ({len(report.steps)}):")
        
        for step in report.steps:
            print(f"  [{step.priority.value.upper()}] {step.title}")
            print(f"    {step.description}")
            print(f"    Auto-applicable: {step.auto_applicable}")
            if step.auto_command:
                print(f"    Command: {step.auto_command}")