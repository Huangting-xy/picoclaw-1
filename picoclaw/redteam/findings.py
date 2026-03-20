#!/usr/bin/env python3
"""
Vulnerability Findings Management for Picoclaw Continuous Red Teaming

Provides comprehensive vulnerability finding management:
- Finding reporting and storage
- Query and filtering
- False positive tracking
- Fix verification
- CVE mapping and CVSS scoring
"""

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import threading
from collections import defaultdict


class FindingStatus(Enum):
    """Status of a vulnerability finding"""
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    WONT_FIX = "wont_fix"
    REOPENED = "reopened"


class FindingType(Enum):
    """Type of vulnerability"""
    INJECTION = "injection"
    AUTH_BYPASS = "auth_bypass"
    TRAVERSAL = "traversal"
    XSS = "xss"
    SSRF = "ssrf"
    CONFIGURATION = "configuration"
    CRYPTO = "crypto"
    RATE_LIMIT = "rate_limit"
    PROMPT_INJECTION = "prompt_injection"
    LOGIC = "logic"
    INFORMATION_DISCLOSURE = "information_disclosure"
    PERMISSION = "permission"
    OTHER = "other"


@dataclass
class CVEInfo:
    """CVE vulnerability information"""
    cve_id: str
    description: str
    cvss_score: float
    cvss_vector: str = ""
    severity: str = ""
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'cve_id': self.cve_id,
            'description': self.description,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'severity': self.severity,
            'affected_products': self.affected_products,
            'references': self.references,
            'published_date': self.published_date,
            'modified_date': self.modified_date
        }


@dataclass
class VulnerabilityFinding:
    """A vulnerability finding"""
    id: str
    name: str
    description: str
    severity: str  # info, low, medium, high, critical
    finding_type: FindingType
    
    # Target info
    target: str
    endpoint: str = ""
    
    # Timestamps
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Evidence
    evidence: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    # CVE mapping
    cve_info: Optional[CVEInfo] = None
    
    # Status tracking
    status: FindingStatus = FindingStatus.NEW
    assigned_to: str = ""
    notes: List[Dict[str, str]] = field(default_factory=list)
    
    # Fix tracking
    fix_commit: str = ""
    fix_date: str = ""
    fix_verified: bool = False
    verification_attempts: int = 0
    
    # False positive tracking
    is_false_positive: bool = False
    false_positive_reason: str = ""
    false_positive_reported_by: str = ""
    
    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # Metadata
    scanner: str = "unknown"
    test_id: str = ""
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'finding_type': self.finding_type.value,
            'target': self.target,
            'endpoint': self.endpoint,
            'discovered_at': self.discovered_at,
            'updated_at': self.updated_at,
            'evidence': self.evidence,
            'details': self.details,
            'cve_info': self.cve_info.to_dict() if self.cve_info else None,
            'status': self.status.value,
            'assigned_to': self.assigned_to,
            'notes': self.notes,
            'fix_commit': self.fix_commit,
            'fix_date': self.fix_date,
            'fix_verified': self.fix_verified,
            'verification_attempts': self.verification_attempts,
            'is_false_positive': self.is_false_positive,
            'false_positive_reason': self.false_positive_reason,
            'false_positive_reported_by': self.false_positive_reported_by,
            'remediation': self.remediation,
            'references': self.references,
            'scanner': self.scanner,
            'test_id': self.test_id,
            'tags': self.tags
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VulnerabilityFinding':
        """Create from dictionary"""
        cve_info = None
        if data.get('cve_info'):
            cve_data = data['cve_info']
            cve_info = CVEInfo(**cve_data)
        
        return cls(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            severity=data['severity'],
            finding_type=FindingType(data['finding_type']),
            target=data['target'],
            endpoint=data.get('endpoint', ''),
            discovered_at=data.get('discovered_at', datetime.now().isoformat()),
            updated_at=data.get('updated_at', datetime.now().isoformat()),
            evidence=data.get('evidence', ''),
            details=data.get('details', {}),
            cve_info=cve_info,
            status=FindingStatus(data.get('status', 'new')),
            assigned_to=data.get('assigned_to', ''),
            notes=data.get('notes', []),
            fix_commit=data.get('fix_commit', ''),
            fix_date=data.get('fix_date', ''),
            fix_verified=data.get('fix_verified', False),
            verification_attempts=data.get('verification_attempts', 0),
            is_false_positive=data.get('is_false_positive', False),
            false_positive_reason=data.get('false_positive_reason', ''),
            false_positive_reported_by=data.get('false_positive_reported_by', ''),
            remediation=data.get('remediation', ''),
            references=data.get('references', []),
            scanner=data.get('scanner', 'unknown'),
            test_id=data.get('test_id', ''),
            tags=data.get('tags', [])
        )


@dataclass
class FindingStatistics:
    """Statistics about findings"""
    total_findings: int = 0
    new_findings: int = 0
    confirmed_findings: int = 0
    false_positives: int = 0
    fixed_findings: int = 0
    open_findings: int = 0
    
    # By severity
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # By type
    by_type: Dict[str, int] = field(default_factory=dict)
    
    # By target
    by_target: Dict[str, int] = field(default_factory=dict)
    
    # Trend
    findings_last_7_days: int = 0
    findings_last_30_days: int = 0
    avg_time_to_fix: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_findings': self.total_findings,
            'new_findings': self.new_findings,
            'confirmed_findings': self.confirmed_findings,
            'false_positives': self.false_positives,
            'fixed_findings': self.fixed_findings,
            'open_findings': self.open_findings,
            'by_severity': {
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count,
                'info': self.info_count
            },
            'by_type': self.by_type,
            'by_target': self.by_target,
            'trend': {
                'findings_last_7_days': self.findings_last_7_days,
                'findings_last_30_days': self.findings_last_30_days,
                'avg_time_to_fix_hours': self.avg_time_to_fix
            }
        }


# CVSS scoring helper functions
def get_severity_from_cvss(cvss_score: float) -> str:
    """Convert CVSS score to severity string"""
    if cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    elif cvss_score > 0:
        return "low"
    return "info"


def calculate_cvss_score(vector: str) -> float:
    """Calculate CVSS score from vector string (simplified)"""
    # This is a simplified calculation
    # In production, use the official CVSS calculator
    
    base_score = 0.0
    
    # Parse vector components
    components = {}
    for part in vector.split('/'):
        if ':' in part:
            key, value = part.split(':', 1)
            components[key] = value
    
    # Attack Vector (AV)
    av_scores = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}
    av = av_scores.get(components.get('AV', 'N'), 0.85)
    
    # Attack Complexity (AC)
    ac_scores = {'L': 0.77, 'H': 0.44}
    ac = ac_scores.get(components.get('AC', 'L'), 0.77)
    
    # Privileges Required (PR)
    pr_scores = {'N': 0.85, 'L': 0.62, 'H': 0.27}
    pr = pr_scores.get(components.get('PR', 'N'), 0.85)
    
    # User Interaction (UI)
    ui_scores = {'N': 0.85, 'R': 0.62}
    ui = ui_scores.get(components.get('UI', 'N'), 0.85)
    
    # Impact (C, I, A)
    impact_scores = {'H': 0.56, 'L': 0.22, 'N': 0}
    c = impact_scores.get(components.get('C', 'N'), 0)
    i = impact_scores.get(components.get('I', 'N'), 0)
    a = impact_scores.get(components.get('A', 'N'), 0)
    
    # Calculate exploitability
    exploitability = 8.22 * av * ac * pr * ui
    
    # Calculate impact
    impact = 1 - ((1 - c) * (1 - i) * (1 - a))
    
    # Calculate base score
    if impact <= 0:
        base_score = 0
    else:
        if components.get('S', 'U') == 'C':
            base_score = min(10, 1.08 * (impact + exploitability))
        else:
            base_score = min(10, impact + exploitability)
    
    return round(base_score, 1)


class FindingManager:
    """
    Manager for vulnerability findings.
    
    Provides:
    - Finding storage and retrieval
    - Status tracking
    - False positive management
    - Fix verification
    - CVE mapping
    - Statistics generation
    
    Example:
        manager = FindingManager()
        
        # Report a finding
        finding_id = manager.report_finding({
            'name': 'SQL Injection',
            'description': '...',
            'severity': 'critical',
            'target': 'http://example.com',
            ...
        })
        
        # Query findings
        critical_findings = manager.get_findings(severity='critical')
        
        # Mark as false positive
        manager.mark_false_positive(finding_id, reason='Not exploitable')
        
        # Mark as fixed
        manager.mark_fixed(finding_id, fix_commit='abc123')
        
        # Get statistics
        stats = manager.get_statistics()
    """
    
    def __init__(self, *, storage_dir: Optional[str] = None):
        """
        Initialize the finding manager.
        
        Args:
            storage_dir: Optional directory for persistent storage
        """
        self.storage_dir = Path(storage_dir) if storage_dir else None
        
        # In-memory storage
        self._findings: Dict[str, VulnerabilityFinding] = {}
        self._cve_index: Dict[str, Set[str]] = defaultdict(set)  # CVE -> finding IDs
        self._target_index: Dict[str, Set[str]] = defaultdict(set)  # Target -> finding IDs
        
        # Lock for thread safety
        self._lock = threading.RLock()
        
        # CVE database (simplified in-memory)
        self._cve_database: Dict[str, CVEInfo] = {}
        self._init_cve_database()
        
        # Load from storage if available
        if self.storage_dir:
            self._load_from_storage()
    
    def _init_cve_database(self):
        """Initialize with known CVEs"""
        known_cves = [
            CVEInfo(
                cve_id='CVE-2026-25253',
                description='OpenClaw Remote Code Execution via Unvalidated Gateway URL',
                cvss_score=9.8,
                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
                severity='critical',
                affected_products=['OpenClaw'],
                references=[
                    'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-25253'
                ]
            ),
            CVEInfo(
                cve_id='CVE-2024-23897',
                description='Jenkins CLI arbitrary file read vulnerability',
                cvss_score=9.8,
                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                severity='critical',
                affected_products=['Jenkins'],
                references=[
                    'https://www.jenkins.io/security/advisory/2024-01-24/'
                ]
            ),
            CVEInfo(
                cve_id='CVE-2023-44487',
                description='HTTP/2 Rapid Reset Attack',
                cvss_score=7.5,
                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                severity='high',
                affected_products=['HTTP/2 implementations'],
                references=[
                    'https://www.cve.org/CVERecord?id=CVE-2023-44487'
                ]
            ),
        ]
        
        for cve in known_cves:
            self._cve_database[cve.cve_id] = cve
    
    def _generate_finding_id(self, finding_data: Dict[str, Any]) -> str:
        """Generate unique finding ID"""
        content = f"{finding_data.get('name', '')}_{finding_data.get('target', '')}_{finding_data.get('endpoint', '')}"
        content += finding_data.get('description', '')[:100]
        content += finding_data.get('evidence', '')[:50]
        return hashlib.sha256(content.encode()).hexdigest()[:12]
    
    def report_finding(
        self,
        finding_data: Dict[str, Any],
        *,
        deduplicate: bool = True
    ) -> str:
        """
        Report a new vulnerability finding.
        
        Args:
            finding_data: Dictionary with finding details
            deduplicate: Check for duplicate findings
            
        Returns:
            Finding ID
        """
        with self._lock:
            finding_id = finding_data.get('id') or self._generate_finding_id(finding_data)
            
            # Check for duplicate
            if deduplicate and finding_id in self._findings:
                # Update existing finding
                existing = self._findings[finding_id]
                existing.updated_at = datetime.now().isoformat()
                existing.notes.append({
                    'timestamp': datetime.now().isoformat(),
                    'note': 'Finding re-discovered'
                })
                return finding_id
            
            # Get CVE info if applicable
            cve_info = None
            cve_id = finding_data.get('cve_id')
            if cve_id and cve_id in self._cve_database:
                cve_info = self._cve_database[cve_id]
            elif cve_id:
                # Create CVE info from data
                cve_info = CVEInfo(
                    cve_id=cve_id,
                    description=finding_data.get('description', ''),
                    cvss_score=finding_data.get('cvss_score', 0.0),
                    severity=finding_data.get('severity', 'medium')
                )
            
            # Determine finding type
            finding_type = FindingType(finding_data.get('finding_type', 'other'))
            
            # Determine severity
            severity = finding_data.get('severity', 'medium').lower()
            if cve_info and cve_info.cvss_score:
                severity = get_severity_from_cvss(cve_info.cvss_score)
            
            # Create finding
            finding = VulnerabilityFinding(
                id=finding_id,
                name=finding_data.get('name', 'Unknown Finding'),
                description=finding_data.get('description', ''),
                severity=severity,
                finding_type=finding_type,
                target=finding_data.get('target', ''),
                endpoint=finding_data.get('endpoint', ''),
                evidence=finding_data.get('evidence', ''),
                details=finding_data.get('details', {}),
                cve_info=cve_info,
                status=FindingStatus(finding_data.get('status', 'new')),
                remediation=finding_data.get('remediation', ''),
                references=finding_data.get('references', []),
                scanner=finding_data.get('scanner', 'unknown'),
                test_id=finding_data.get('test_id', ''),
                tags=finding_data.get('tags', [])
            )
            
            self._findings[finding_id] = finding
            
            # Update indexes
            if cve_id:
                self._cve_index[cve_id].add(finding_id)
            self._target_index[finding.target].add(finding_id)
            
            # Save to storage
            if self.storage_dir:
                self._save_finding(finding)
            
            return finding_id
    
    def get_finding(self, finding_id: str) -> Optional[VulnerabilityFinding]:
        """
        Get a finding by ID.
        
        Args:
            finding_id: Finding ID
            
        Returns:
            VulnerabilityFinding if found, None otherwise
        """
        return self._findings.get(finding_id)
    
    def get_findings(
        self,
        *,
        target: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[FindingStatus] = None,
        finding_type: Optional[FindingType] = None,
        cve_id: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[VulnerabilityFinding]:
        """
        Query findings with filters.
        
        Args:
            target: Filter by target
            severity: Filter by severity
            status: Filter by status
            finding_type: Filter by finding type
            cve_id: Filter by CVE ID
            since: Filter by discovery date
            limit: Maximum number of results
            offset: Offset for pagination
            
        Returns:
            List of matching VulnerabilityFindings
        """
        with self._lock:
            results = []
            
            # Use indexes for efficient filtering
            if cve_id and cve_id in self._cve_index:
                candidate_ids = self._cve_index[cve_id]
            elif target and target in self._target_index:
                candidate_ids = self._target_index[target]
            else:
                candidate_ids = set(self._findings.keys())
            
            for fid in candidate_ids:
                finding = self._findings.get(fid)
                if not finding:
                    continue
                
                # Apply filters
                if target and finding.target != target:
                    continue
                if severity and finding.severity != severity.lower():
                    continue
                if status and finding.status != status:
                    continue
                if finding_type and finding.finding_type != finding_type:
                    continue
                if cve_id and (not finding.cve_info or finding.cve_info.cve_id != cve_id):
                    continue
                if since:
                    discovered = datetime.fromisoformat(finding.discovered_at)
                    if discovered < since:
                        continue
                
                results.append(finding)
            
            # Sort by discovery date (newest first)
            results.sort(key=lambda f: f.discovered_at, reverse=True)
            
            return results[offset:offset + limit]
    
    def mark_false_positive(
        self,
        finding_id: str,
        *,
        reason: str = "",
        reported_by: str = ""
    ) -> bool:
        """
        Mark a finding as false positive.
        
        Args:
            finding_id: Finding ID
            reason: Reason for false positive
            reported_by: Who reported it
            
        Returns:
            True if successful
        """
        with self._lock:
            finding = self._findings.get(finding_id)
            if not finding:
                return False
            
            finding.status = FindingStatus.FALSE_POSITIVE
            finding.is_false_positive = True
            finding.false_positive_reason = reason
            finding.false_positive_reported_by = reported_by
            finding.updated_at = datetime.now().isoformat()
            
            if reason:
                finding.notes.append({
                    'timestamp': datetime.now().isoformat(),
                    'note': f'Marked as false positive: {reason}'
                })
            
            if self.storage_dir:
                self._save_finding(finding)
            
            return True
    
    def mark_fixed(
        self,
        finding_id: str,
        fix_commit: str = "",
        notes: str = ""
    ) -> bool:
        """
        Mark a finding as fixed.
        
        Args:
            finding_id: Finding ID
            fix_commit: Commit hash that fixed the issue
            notes: Additional notes
            
        Returns:
            True if successful
        """
        with self._lock:
            finding = self._findings.get(finding_id)
            if not finding:
                return False
            
            finding.status = FindingStatus.FIXED
            finding.fix_commit = fix_commit
            finding.fix_date = datetime.now().isoformat()
            finding.updated_at = datetime.now().isoformat()
            
            if notes:
                finding.notes.append({
                    'timestamp': datetime.now().isoformat(),
                    'note': f'Fixed: {notes}'
                })
            
            if self.storage_dir:
                self._save_finding(finding)
            
            return True
    
    def acknowledge_finding(
        self,
        finding_id: str,
        assigned_to: str = ""
    ) -> bool:
        """
        Acknowledge a finding.
        
        Args:
            finding_id: Finding ID
            assigned_to: Who is assigned to handle it
            
        Returns:
            True if successful
        """
        with self._lock:
            finding = self._findings.get(finding_id)
            if not finding:
                return False
            
            finding.status = FindingStatus.ACKNOWLEDGED
            finding.assigned_to = assigned_to
            finding.updated_at = datetime.now().isoformat()
            
            if assigned_to:
                finding.notes.append({
                    'timestamp': datetime.now().isoformat(),
                    'note': f'Assigned to: {assigned_to}'
                })
            
            if self.storage_dir:
                self._save_finding(finding)
            
            return True
    
    def reopen_finding(
        self,
        finding_id: str,
        reason: str = ""
    ) -> bool:
        """
        Reopen a fixed finding.
        
        Args:
            finding_id: Finding ID
            reason: Reason for reopening
            
        Returns:
            True if successful
        """
        with self._lock:
            finding = self._findings.get(finding_id)
            if not finding:
                return False
            
            finding.status = FindingStatus.REOPENED
            finding.fix_verified = False
            finding.updated_at = datetime.now().isoformat()
            
            finding.notes.append({
                'timestamp': datetime.now().isoformat(),
                'note': f'Reopened: {reason}' if reason else 'Reopened'
            })
            
            if self.storage_dir:
                self._save_finding(finding)
            
            return True
    
    def add_note(
        self,
        finding_id: str,
        note: str,
        author: str = ""
    ) -> bool:
        """
        Add a note to a finding.
        
        Args:
            finding_id: Finding ID
            note: Note content
            author: Note author
            
        Returns:
            True if successful
        """
        with self._lock:
            finding = self._findings.get(finding_id)
            if not finding:
                return False
            
            finding.notes.append({
                'timestamp': datetime.now().isoformat(),
                'author': author,
                'note': note
            })
            finding.updated_at = datetime.now().isoformat()
            
            if self.storage_dir:
                self._save_finding(finding)
            
            return True
    
    def get_statistics(self) -> FindingStatistics:
        """
        Get finding statistics.
        
        Returns:
            FindingStatistics with current statistics
        """
        with self._lock:
            stats = FindingStatistics()
            now = datetime.now()
            week_ago = now - timedelta(days=7)
            month_ago = now - timedelta(days=30)
            
            fix_times = []
            
            for finding in self._findings.values():
                # Total
                stats.total_findings += 1
                
                # By status
                if finding.status == FindingStatus.NEW:
                    stats.new_findings += 1
                elif finding.status == FindingStatus.CONFIRMED:
                    stats.confirmed_findings += 1
                elif finding.status == FindingStatus.FALSE_POSITIVE:
                    stats.false_positives += 1
                elif finding.status == FindingStatus.FIXED:
                    stats.fixed_findings += 1
                    
                    # Calculate time to fix
                    if finding.fix_date:
                        try:
                            fix_date = datetime.fromisoformat(finding.fix_date)
                            discovered = datetime.fromisoformat(finding.discovered_at)
                            fix_times.append((fix_date - discovered).total_seconds() / 3600)
                        except:
                            pass
                
                # Open findings (not fixed or false positive)
                if finding.status not in [FindingStatus.FIXED, FindingStatus.FALSE_POSITIVE]:
                    stats.open_findings += 1
                
                # By severity
                severity = finding.severity.lower()
                if severity == 'critical':
                    stats.critical_count += 1
                elif severity == 'high':
                    stats.high_count += 1
                elif severity == 'medium':
                    stats.medium_count += 1
                elif severity == 'low':
                    stats.low_count += 1
                else:
                    stats.info_count += 1
                
                # By type
                type_str = finding.finding_type.value
                stats.by_type[type_str] = stats.by_type.get(type_str, 0) + 1
                
                # By target
                stats.by_target[finding.target] = stats.by_target.get(finding.target, 0) + 1
                
                # Trend
                try:
                    discovered = datetime.fromisoformat(finding.discovered_at)
                    if discovered >= week_ago:
                        stats.findings_last_7_days += 1
                    if discovered >= month_ago:
                        stats.findings_last_30_days += 1
                except:
                    pass
            
            # Average time to fix
            if fix_times:
                stats.avg_time_to_fix = sum(fix_times) / len(fix_times)
            
            return stats
    
    def get_cve_mapping(self, cve_id: str) -> List[VulnerabilityFinding]:
        """
        Get all findings for a CVE.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            List of findings for the CVE
        """
        finding_ids = self._cve_index.get(cve_id, set())
        return [self._findings[fid] for fid in finding_ids if fid in self._findings]
    
    def register_cve(self, cve_info: CVEInfo) -> None:
        """
        Register CVE information.
        
        Args:
            cve_info: CVE information
        """
        with self._lock:
            self._cve_database[cve_info.cve_id] = cve_info
    
    def get_cve_info(self, cve_id: str) -> Optional[CVEInfo]:
        """
        Get CVE information.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            CVEInfo if found, None otherwise
        """
        return self._cve_database.get(cve_id)
    
    def export_findings(
        self,
        format: str = 'json',
        filters: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Export findings to a format.
        
        Args:
            format: Export format ('json', 'csv')
            filters: Optional filters
            
        Returns:
            Exported data as string
        """
        findings = self.get_findings(**(filters or {}))
        
        if format == 'json':
            return json.dumps([f.to_dict() for f in findings], indent=2)
        
        elif format == 'csv':
            lines = ['id,name,severity,status,target,cve_id,discovered_at']
            for f in findings:
                cve_id = f.cve_info.cve_id if f.cve_info else ''
                lines.append(f'{f.id},{f.name},{f.severity},{f.status.value},{f.target},{cve_id},{f.discovered_at}')
            return '\n'.join(lines)
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def import_findings(self, data: str, format: str = 'json') -> int:
        """
        Import findings from a format.
        
        Args:
            data: Data to import
            format: Import format ('json')
            
        Returns:
            Number of findings imported
        """
        count = 0
        
        if format == 'json':
            items = json.loads(data)
            for item in items:
                self.report_finding(item, deduplicate=True)
                count += 1
        
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        return count
    
    def _save_finding(self, finding: VulnerabilityFinding):
        """Save finding to storage"""
        if not self.storage_dir:
            return
        
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        filepath = self.storage_dir / f"{finding.id}.json"
        with open(filepath, 'w') as f:
            json.dump(finding.to_dict(), f, indent=2)
    
    def _load_from_storage(self):
        """Load findings from storage"""
        if not self.storage_dir or not self.storage_dir.exists():
            return
        
        for filepath in self.storage_dir.glob('*.json'):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                finding = VulnerabilityFinding.from_dict(data)
                self._findings[finding.id] = finding
                
                # Update indexes
                if finding.cve_info:
                    self._cve_index[finding.cve_info.cve_id].add(finding.id)
                self._target_index[finding.target].add(finding.id)
            except Exception:
                pass  # Skip invalid files
    
    def delete_finding(self, finding_id: str) -> bool:
        """
        Delete a finding.
        
        Args:
            finding_id: Finding ID
            
        Returns:
            True if deleted, False if not found
        """
        with self._lock:
            finding = self._findings.pop(finding_id, None)
            if not finding:
                return False
            
            # Update indexes
            if finding.cve_info:
                self._cve_index[finding.cve_info.cve_id].discard(finding_id)
            self._target_index[finding.target].discard(finding_id)
            
            # Remove from storage
            if self.storage_dir:
                filepath = self.storage_dir / f"{finding_id}.json"
                if filepath.exists():
                    filepath.unlink()
            
            return True


# Singleton instance
_manager_instance: Optional[FindingManager] = None


def get_finding_manager(storage_dir: Optional[str] = None) -> FindingManager:
    """Get the singleton FindingManager instance"""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = FindingManager(storage_dir=storage_dir)
    return _manager_instance


if __name__ == '__main__':
    import sys
    
    manager = FindingManager()
    
    # Create a sample finding
    finding_id = manager.report_finding({
        'name': 'SQL Injection',
        'description': 'SQL injection vulnerability in login endpoint',
        'severity': 'critical',
        'finding_type': 'injection',
        'target': 'http://example.com',
        'endpoint': '/api/login',
        'evidence': 'Error message reveals SQL syntax',
        'cve_id': 'CVE-2024-12345'
    })
    
    print(f"Created finding: {finding_id}")
    
    # Get statistics
    stats = manager.get_statistics()
    print(f"Statistics: {json.dumps(stats.to_dict(), indent=2)}")
    
    # Export findings
    export = manager.export_findings()
    print(f"\nExported findings:\n{export[:500]}...")