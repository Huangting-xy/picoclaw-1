#!/usr/bin/env python3
"""
Context Contamination Detection Module for Picoclaw Observability
Detects and flags sensitive information entering shared memory/RAG.

Stage 3.2: Decision Capture
"""

import os
import re
import json
import math
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Contamination severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingType(Enum):
    """Types of sensitive information"""
    # Secrets and credentials
    API_KEY = "api_key"
    AWS_KEY = "aws_key"
    AWS_SECRET = "aws_secret"
    PRIVATE_KEY = "private_key"
    PASSWORD = "password"
    AUTH_TOKEN = "auth_token"
    DATABASE_URL = "database_url"
    SECRET_KEY = "secret_key"
    
    # PII
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    ADDRESS = "address"
    
    # Financial
    BANK_ACCOUNT = "bank_account"
    ROUTING_NUMBER = "routing_number"
    
    # Healthcare
    MEDICAL_ID = "medical_id"
    HEALTH_DATA = "health_data"
    
    # Other sensitive
    IP_INTERNAL = "internal_ip"
    DOMAIN_SENSITIVE = "sensitive_domain"
    CONNECTION_STRING = "connection_string"
    ENCRYPTION_KEY = "encryption_key"


@dataclass
class ContaminationFinding:
    """Represents a detected contamination"""
    finding_type: FindingType
    severity: Severity
    content_match: str  # The matched content (potentially redacted)
    context: str  # Surrounding context (limited chars)
    line_number: Optional[int]
    position: tuple[int, int]  # Start and end position
    pattern_name: str
    confidence: float  # Pattern match confidence
    recommendation: str
    redacted: bool = False
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            'finding_type': self.finding_type.value,
            'severity': self.severity.value,
            'content_match': self.content_match if self.redacted else '[REDACTED]',
            'context': self.context,
            'line_number': self.line_number,
            'position': self.position,
            'pattern_name': self.pattern_name,
            'confidence': self.confidence,
            'recommendation': self.recommendation,
            'redacted': self.redacted
        }


# Default patterns for secret detection
DEFAULT_SECRET_PATTERNS = {
    # API Keys
    'api_key_generic': {
        'pattern': r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        'type': FindingType.API_KEY,
        'severity': Severity.HIGH,
        'confidence': 0.8,
        'recommendation': 'Remove API key and use environment variables or secrets manager'
    },
    'api_key_header': {
        'pattern': r'(?i)x-api-key[:\s]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        'type': FindingType.API_KEY,
        'severity': Severity.HIGH,
        'confidence': 0.9,
        'recommendation': 'Remove API key from headers'
    },
    'bearer_token': {
        'pattern': r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})',
        'type': FindingType.AUTH_TOKEN,
        'severity': Severity.HIGH,
        'confidence': 0.9,
        'recommendation': 'Remove bearer token'
    },
    
    # AWS
    'aws_access_key': {
        'pattern': r'(?:A|A3|A4|A5|A8|AN|AS|AK|AG|AI|AN|AP|AR|AU|AV|AY|AZ)(?:I|K|M|N|P|R|S|X|Y)[A-Z0-9]{14,}',
        'type': FindingType.AWS_KEY,
        'severity': Severity.CRITICAL,
        'confidence': 0.95,
        'recommendation': 'Remove AWS access key and rotate credentials'
    },
    'aws_secret_key': {
        'pattern': r'(?i)aws[_-]?secret[_-]?(?:access)?[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?',
        'type': FindingType.AWS_SECRET,
        'severity': Severity.CRITICAL,
        'confidence': 0.95,
        'recommendation': 'Remove AWS secret key and rotate credentials'
    },
    
    # Private Keys
    'private_key_pem': {
        'pattern': r'-----BEGIN(?:\s+RSA|\s+DSA|\s+EC|\s+OPENSSH)?\s+PRIVATE KEY-----',
        'type': FindingType.PRIVATE_KEY,
        'severity': Severity.CRITICAL,
        'confidence': 0.99,
        'recommendation': 'Remove private key immediately'
    },
    'private_key_ssh': {
        'pattern': r'-----BEGIN\s+OPENSSH\s+PRIVATE KEY-----',
        'type': FindingType.PRIVATE_KEY,
        'severity': Severity.CRITICAL,
        'confidence': 0.99,
        'recommendation': 'Remove SSH private key immediately'
    },
    
    # Passwords
    'password_assignment': {
        'pattern': r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{4,})["\']?',
        'type': FindingType.PASSWORD,
        'severity': Severity.HIGH,
        'confidence': 0.7,
        'recommendation': 'Remove hardcoded password'
    },
    'password_in_url': {
        'pattern': r'(?i)[a-z][a-z0-9+\-.]*://[^:]+:([^@]+)@',
        'type': FindingType.PASSWORD,
        'severity': Severity.CRITICAL,
        'confidence': 0.95,
        'recommendation': 'Remove password from URL'
    },
    
    # Database URLs
    'database_url_postgres': {
        'pattern': r'postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^\s"\']+',
        'type': FindingType.DATABASE_URL,
        'severity': Severity.CRITICAL,
        'confidence': 0.95,
        'recommendation': 'Remove database connection string with credentials'
    },
    'database_url_mysql': {
        'pattern': r'mysql://[^:]+:[^@]+@[^/]+/[^\s"\']+',
        'type': FindingType.DATABASE_URL,
        'severity': Severity.CRITICAL,
        'confidence': 0.95,
        'recommendation': 'Remove database connection string with credentials'
    },
    'database_url_mongodb': {
        'pattern': r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+',
        'type': FindingType.DATABASE_URL,
        'severity': Severity.CRITICAL,
        'confidence': 0.95,
        'recommendation': 'Remove MongoDB connection string with credentials'
    },
    
    # Generic secrets
    'secret_key_assignment': {
        'pattern': r'(?i)(?:secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
        'type': FindingType.SECRET_KEY,
        'severity': Severity.HIGH,
        'confidence': 0.8,
        'recommendation': 'Remove secret key'
    },
    'generic_token': {
        'pattern': r'(?i)(?:token|auth)[_-]?(?:key)?\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
        'type': FindingType.AUTH_TOKEN,
        'severity': Severity.HIGH,
        'confidence': 0.75,
        'recommendation': 'Remove token'
    },
    
    # PII
    'email': {
        'pattern': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'type': FindingType.EMAIL,
        'severity': Severity.LOW,
        'confidence': 0.9,
        'recommendation': 'Consider redacting email address'
    },
    'phone_us': {
        'pattern': r'\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
        'type': FindingType.PHONE,
        'severity': Severity.LOW,
        'confidence': 0.75,
        'recommendation': 'Consider redacting phone number'
    },
    'ssn_us': {
        'pattern': r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b',
        'type': FindingType.SSN,
        'severity': Severity.CRITICAL,
        'confidence': 0.85,
        'recommendation': 'Remove SSN immediately - this is highly sensitive PII'
    },
    'credit_card': {
        'pattern': r'\b(?:\d{4}[-.\s]?){3}\d{4}\b',
        'type': FindingType.CREDIT_CARD,
        'severity': Severity.CRITICAL,
        'confidence': 0.8,
        'recommendation': 'Remove credit card number immediately'
    },
    'ipv4': {
        'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'type': FindingType.IP_ADDRESS,
        'severity': Severity.LOW,
        'confidence': 0.6,
        'recommendation': 'Review if IP address should be exposed'
    },
    'ipv4_private': {
        'pattern': r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
        'type': FindingType.IP_INTERNAL,
        'severity': Severity.MEDIUM,
        'confidence': 0.95,
        'recommendation': 'Remove private IP address - may reveal internal infrastructure'
    },
    
    # Banking
    'bank_account_us': {
        'pattern': r'\b\d{8,17}\b',
        'type': FindingType.BANK_ACCOUNT,
        'severity': Severity.HIGH,
        'confidence': 0.4,  # Low confidence - many false positives
        'recommendation': 'Review if this is a bank account number'
    },
}

# Entropy thresholds for secret detection
DEFAULT_ENTROPY_THRESHOLD = 4.5
DEFAULT_MIN_SECRET_LENGTH = 16


class ContaminationDetector:
    """
    Detects and flags sensitive information in content.
    
    Provides:
    - Detection of secrets via regex patterns
    - Entropy-based detection for high-randomness strings
    - Severity classification (LOW/MEDIUM/HIGH/CRITICAL)
    - Blocklist support for custom patterns
    - Safe write checking for memory/RAG
    
    Usage:
        detector = ContaminationDetector('/path/to/patterns.json')
        findings = detector.scan_content("api_key=sk-1234567890abcdef")
        if findings:
            print(f"Found {len(findings)} contaminants")
        
        # Check before writing to memory
        check = detector.check_memory_write(content, target="shared_memory")
        if not check['safe']:
            print(f"Blocked: {check['reason']}")
    """
    
    def __init__(self, patterns_file: str = None, custom_patterns: dict = None):
        """
        Initialize contamination detector.
        
        Args:
            patterns_file: Optional path to JSON file with custom patterns
            custom_patterns: Optional dict of additional patterns
        """
        self.patterns = dict(DEFAULT_SECRET_PATTERNS)
        self.compiled_patterns: dict[str, re.Pattern] = {}
        
        # Load custom patterns from file
        if patterns_file:
            self._load_patterns_file(patterns_file)
        
        # Add inline custom patterns
        if custom_patterns:
            self._add_patterns(custom_patterns)
        
        # Compile all patterns
        self._compile_patterns()
        
        # Blocklist for known-sensitive terms
        self.blocklist: set[str] = set()
        
        # Entropy settings
        self.entropy_threshold = DEFAULT_ENTROPY_THRESHOLD
        self.min_secret_length = DEFAULT_MIN_SECRET_LENGTH
        
        # Logging for detected contaminants
        self._detection_log: list[dict] = []
        self._log_retention = 1000  # Keep last N detections
    
    def _load_patterns_file(self, path: str):
        """Load patterns from JSON file"""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            if 'patterns' in data:
                self._add_patterns(data['patterns'])
            
            if 'blocklist' in data:
                self.blocklist.update(data['blocklist'])
            
            if 'entropy_threshold' in data:
                self.entropy_threshold = data['entropy_threshold']
            
            if 'min_secret_length' in data:
                self.min_secret_length = data['min_secret_length']
                
            logger.info(f"Loaded custom patterns from {path}")
        except FileNotFoundError:
            logger.warning(f"Patterns file not found: {path}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in patterns file: {e}")
        except Exception as e:
            logger.error(f"Error loading patterns file: {e}")
    
    def _add_patterns(self, patterns: dict):
        """Add patterns to the detector"""
        for name, config in patterns.items():
            if 'pattern' in config:
                self.patterns[name] = config
    
    def _compile_patterns(self):
        """Compile all regex patterns"""
        for name, config in self.patterns.items():
            try:
                pattern_str = config.get('pattern')
                if not pattern_str:
                    # Pattern is already compiled or invalid
                    continue
                
                # Support both pattern-only and config dict formats
                if isinstance(pattern_str, str):
                    flags = re.IGNORECASE if config.get('ignore_case', True) else 0
                    self.compiled_patterns[name] = re.compile(pattern_str, flags)
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{name}': {e}")
    
    def add_blocklist_term(self, term: str):
        """Add a term to the blocklist"""
        self.blocklist.add(term.lower())
    
    def add_blocklist_terms(self, terms: list[str]):
        """Add multiple terms to the blocklist"""
        for term in terms:
            self.blocklist.add(term.lower())
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not s:
            return 0.0
        
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        
        length = len(s)
        entropy = 0.0
        
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _extract_potential_secrets(self, content: str) -> list[tuple[str, int, int]]:
        """
        Extract potential secrets using entropy detection.
        Returns list of (string, start_pos, end_pos)
        """
        potentials = []
        
        # Look for high-entropy strings in quotes
        quoted_pattern = re.compile(r'["\']([a-zA-Z0-9_\-+/=]{16,})["\']')
        
        for match in quoted_pattern.finditer(content):
            s = match.group(1)
            entropy = self._calculate_entropy(s)
            
            if entropy >= self.entropy_threshold:
                potentials.append((s, match.start(1), match.end(1), entropy))
        
        # Look for base64-like strings
        base64_pattern = re.compile(r'\b([A-Za-z0-9+/]{20,}={0,2})\b')
        
        for match in base64_pattern.finditer(content):
            s = match.group(1)
            if len(s) >= self.min_secret_length:
                entropy = self._calculate_entropy(s)
                if entropy >= self.entropy_threshold:
                    potentials.append((s, match.start(1), match.end(1), entropy))
        
        return potentials
    
    def _get_severity(self, finding_type: FindingType, pattern_name: str) -> Severity:
        """Get severity for a finding type"""
        if pattern_name in self.patterns:
            sev = self.patterns[pattern_name].get('severity')
            if isinstance(sev, Severity):
                return sev
            if isinstance(sev, str):
                try:
                    return Severity[sev.upper()]
                except KeyError:
                    pass
        
        # Default severities by type
        defaults = {
            FindingType.API_KEY: Severity.HIGH,
            FindingType.AWS_KEY: Severity.CRITICAL,
            FindingType.AWS_SECRET: Severity.CRITICAL,
            FindingType.PRIVATE_KEY: Severity.CRITICAL,
            FindingType.PASSWORD: Severity.HIGH,
            FindingType.AUTH_TOKEN: Severity.HIGH,
            FindingType.DATABASE_URL: Severity.CRITICAL,
            FindingType.SECRET_KEY: Severity.HIGH,
            FindingType.EMAIL: Severity.LOW,
            FindingType.PHONE: Severity.LOW,
            FindingType.SSN: Severity.CRITICAL,
            FindingType.CREDIT_CARD: Severity.CRITICAL,
            FindingType.IP_ADDRESS: Severity.LOW,
            FindingType.IP_INTERNAL: Severity.MEDIUM,
            FindingType.BANK_ACCOUNT: Severity.HIGH,
        }
        
        return defaults.get(finding_type, Severity.MEDIUM)
    
    def _get_context(self, content: str, start: int, end: int, context_len: int = 50) -> str:
        """Get surrounding context for a match"""
        context_start = max(0, start - context_len)
        context_end = min(len(content), end + context_len)
        return content[context_start:context_end]
    
    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number for a position"""
        return content[:position].count('\n') + 1
    
    def _redact_content(self, content: str) -> str:
        """Redact sensitive content"""
        if len(content) <= 8:
            return '*' * len(content)
        return content[:2] + '*' * (len(content) - 4) + content[-2:]
    
    def scan_content(self, content: str) -> list[dict]:
        """
        Scan content for sensitive information.
        
        Args:
            content: The content to scan
        
        Returns:
            List of finding dictionaries with:
            - finding_type: Type of sensitive info found
            - severity: LOW/MEDIUM/HIGH/CRITICAL
            - content_match: The matched content (redacted)
            - context: Surrounding context
            - line_number: Line where found
            - position: (start, end) positions
            - pattern_name: Name of pattern that matched
            - confidence: Match confidence
            - recommendation: How to handle
        """
        findings = []
        
        # Scan with regex patterns
        for pattern_name, pattern in self.compiled_patterns.items():
            config = self.patterns.get(pattern_name, {})
            
            for match in pattern.finditer(content):
                finding_type = config.get('type', FindingType.SECRET_KEY)
                if isinstance(finding_type, str):
                    try:
                        finding_type = FindingType[finding_type.upper()]
                    except KeyError:
                        finding_type = FindingType.SECRET_KEY
                
                severity = self._get_severity(finding_type, pattern_name)
                confidence = config.get('confidence', 0.7)
                
                matched_content = match.group(0)
                start, end = match.span()
                
                # For patterns with capture groups, highlight the captured part
                if match.lastindex and match.lastindex >= 1:
                    captured = match.group(1)
                    matched_content = captured
                    start = match.start(1)
                    end = match.end(1)
                
                finding = ContaminationFinding(
                    finding_type=finding_type,
                    severity=severity,
                    content_match=matched_content,
                    context=self._get_context(content, start, end),
                    line_number=self._get_line_number(content, start),
                    position=(start, end),
                    pattern_name=pattern_name,
                    confidence=confidence,
                    recommendation=config.get('recommendation', 'Review and remove sensitive data'),
                    redacted=True
                )
                findings.append(finding)
        
        # Entropy-based detection for potential secrets
        potentials = self._extract_potential_secrets(content)
        
        for s, start, end, entropy in potentials:
            # Check if already found by a pattern
            already_found = any(
                f.position[0] <= start < f.position[1] or
                f.position[0] < end <= f.position[1]
                for f in findings
            )
            
            if not already_found:
                finding = ContaminationFinding(
                    finding_type=FindingType.SECRET_KEY,
                    severity=Severity.HIGH,
                    content_match=self._redact_content(s),
                    context=self._get_context(content, start, end),
                    line_number=self._get_line_number(content, start),
                    position=(start, end),
                    pattern_name='entropy_detection',
                    confidence=min(0.9, entropy / 6.0),  # Scale confidence with entropy
                    recommendation='Potential secret detected via entropy analysis - review manually',
                    redacted=True
                )
                findings.append(finding)
        
        # Check blocklist
        content_lower = content.lower()
        for term in self.blocklist:
            pos = content_lower.find(term)
            while pos != -1:
                end_pos = pos + len(term)
                
                finding = ContaminationFinding(
                    finding_type=FindingType.SECRET_KEY,
                    severity=Severity.HIGH,
                    content_match='*' * len(term),
                    context=self._get_context(content, pos, end_pos),
                    line_number=self._get_line_number(content, pos),
                    position=(pos, end_pos),
                    pattern_name='blocklist',
                    confidence=1.0,
                    recommendation=f'Blocklist term "{term}" found - remove immediately',
                    redacted=True
                )
                findings.append(finding)
                
                pos = content_lower.find(term, end_pos)
        
        # Log detections
        for finding in findings:
            self._log_detection(finding)
        
        return [f.to_dict() for f in findings]
    
    def _log_detection(self, finding: ContaminationFinding):
        """Log a detection for auditing"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'finding_type': finding.finding_type.value,
            'severity': finding.severity.value,
            'pattern_name': finding.pattern_name,
            'confidence': finding.confidence
        }
        
        self._detection_log.append(log_entry)
        
        # Trim log if needed
        if len(self._detection_log) > self._log_retention:
            self._detection_log = self._detection_log[-self._log_retention:]
        
        # Also log to standard logger
        log_msg = f"Contamination detected: {finding.finding_type.value} (severity: {finding.severity.value})"
        
        if finding.severity == Severity.CRITICAL:
            logger.critical(log_msg)
        elif finding.severity == Severity.HIGH:
            logger.warning(log_msg)
        elif finding.severity == Severity.MEDIUM:
            logger.info(log_msg)
        else:
            logger.debug(log_msg)
    
    def check_memory_write(self, content: str, target: str) -> dict:
        """
        Check if content is safe to write to memory/RAG.
        
        Args:
            content: Content to check
            target: Where content will be written (e.g., 'shared_memory', 'rag', 'cache')
        
        Returns:
            Dictionary with:
            - safe: bool - True if content is safe to write
            - findings: list - Any findings detected
            - severity: str - Highest severity found (or 'NONE')
            - reason: str - Reason if not safe
            - sanitized_content: str - Content with findings redacted (if applicable)
        """
        findings = self.scan_content(content)
        
        if not findings:
            return {
                'safe': True,
                'findings': [],
                'severity': 'NONE',
                'reason': None,
                'sanitized_content': content
            }
        
        # Determine if safe based on findings
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        max_severity = Severity.LOW
        
        for f in findings:
            sev = Severity[f['severity']]
            if severity_order.index(sev) > severity_order.index(max_severity):
                max_severity = sev
        
        # Create sanitized content
        sanitized = content
        # Sort by position descending to replace from end
        for f in sorted(findings, key=lambda x: x['position'][0], reverse=True):
            start, end = f['position']
            placeholder = f'[{f["finding_type"].upper()}_REDACTED]'
            sanitized = sanitized[:start] + placeholder + sanitized[end:]
        
        # Determine if safe
        safe = max_severity in (Severity.LOW,)
        reason = None
        
        if not safe:
            crit_count = sum(1 for f in findings if f['severity'] == 'CRITICAL')
            high_count = sum(1 for f in findings if f['severity'] == 'HIGH')
            med_count = sum(1 for f in findings if f['severity'] == 'MEDIUM')
            
            reasons = []
            if crit_count:
                reasons.append(f"{crit_count} CRITICAL severity findings")
            if high_count:
                reasons.append(f"{high_count} HIGH severity findings")
            if med_count:
                reasons.append(f"{med_count} MEDIUM severity findings")
            
            reason = f"Content contains sensitive information: {', '.join(reasons)}"
        
        return {
            'safe': safe,
            'findings': findings,
            'severity': max_severity.value,
            'reason': reason,
            'sanitized_content': sanitized
        }
    
    def get_statistics(self) -> dict:
        """
        Get detection statistics.
        
        Returns:
            Dictionary with aggregate statistics
        """
        if not self._detection_log:
            return {
                'total_detections': 0,
                'by_severity': {},
                'by_type': {},
                'recent_detections': []
            }
        
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        
        for entry in self._detection_log:
            by_severity[entry['severity']] += 1
            by_type[entry['finding_type']] += 1
        
        return {
            'total_detections': len(self._detection_log),
            'by_severity': dict(by_severity),
            'by_type': dict(by_type),
            'recent_detections': self._detection_log[-10:]
        }
    
    def clear_log(self):
        """Clear the detection log"""
        self._detection_log = []
    
    def export_patterns(self, path: str):
        """
        Export current patterns to a JSON file.
        
        Args:
            path: Path to write patterns file
        """
        patterns_data = {
            'patterns': {},
            'blocklist': list(self.blocklist),
            'entropy_threshold': self.entropy_threshold,
            'min_secret_length': self.min_secret_length
        }
        
        for name, config in self.patterns.items():
            patterns_data['patterns'][name] = {
                'pattern': config.get('pattern'),
                'type': config.get('type', {}).value if hasattr(config.get('type'), 'value') else str(config.get('type', '')),
                'severity': config.get('severity', {}).value if hasattr(config.get('severity'), 'value') else str(config.get('severity', '')),
                'confidence': config.get('confidence', 0.7),
                'recommendation': config.get('recommendation', '')
            }
        
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w') as f:
                json.dump(patterns_data, f, indent=2)
            logger.info(f"Exported patterns to {path}")
        except Exception as e:
            logger.error(f"Failed to export patterns: {e}")
            raise


# Singleton instance support
_detector: Optional[ContaminationDetector] = None


def get_detector(patterns_file: str = None) -> ContaminationDetector:
    """
    Get or create singleton ContaminationDetector instance.
    
    Args:
        patterns_file: Path to custom patterns file (only used on first call)
    
    Returns:
        ContaminationDetector instance
    """
    global _detector
    if _detector is None:
        patterns_path = patterns_file or os.environ.get(
            'PICOTCLAW_PATTERNS_FILE',
            '/etc/picoclaw/contamination_patterns.json'
        )
        _detector = ContaminationDetector(patterns_path)
    return _detector


def scan_content(content: str) -> list[dict]:
    """
    Convenience function to scan content using the default detector.
    
    Args:
        content: Content to scan
    
    Returns:
        List of finding dictionaries
    """
    return get_detector().scan_content(content)


def check_memory_write(content: str, target: str) -> dict:
    """
    Convenience function to check if content is safe for memory.
    
    Args:
        content: Content to check
        target: Target location
    
    Returns:
        Safety check result dictionary
    """
    return get_detector().check_memory_write(content, target)