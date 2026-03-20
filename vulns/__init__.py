#!/usr/bin/env python3
"""
Vulnerability Detection Modules for Picoclaw

This package contains vulnerability detection modules for CogniWatch Picoclaw:
- cve_database: CVE database integration with NVD API
- cve_2026_25253: CVE-2026-25253 OpenClaw RCE detector
- secret_scanner: Scanner for exposed API keys and secrets
- mdns_detector: mDNS broadcast detector for insecure discovery
"""

from .cve_database import (
    init_cve_db,
    get_cve,
    search_cves,
    get_openclaw_cves,
    get_cve_statistics,
    CVE_DB_PATH
)

from .cve_2026_25253 import (
    detect as detect_cve_2026_25253,
    check_url_parameter_validation,
    check_websocket_origin_validation,
    check_gateway_ssrf,
    CVE_ID as CVE_2026_25253_ID
)

from .secret_scanner import (
    run_full_scan as scan_secrets,
    quick_scan as quick_secret_scan,
    scan_file as scan_file_secrets,
    scan_directory as scan_directory_secrets,
    scan_openclaw_directory,
    SECRET_PATTERNS
)

from .mdns_detector import (
    detect as detect_mdns,
    check_mdns_broadcast,
    check_mdns_vulnerability,
    MDNS_PORT,
    OPENCLAW_SERVICE_TYPES
)


__all__ = [
    # CVE Database
    'init_cve_db',
    'get_cve',
    'search_cves',
    'get_openclaw_cves',
    'get_cve_statistics',
    'CVE_DB_PATH',
    
    # CVE-2026-25253 Detector
    'detect_cve_2026_25253',
    'check_url_parameter_validation',
    'check_websocket_origin_validation',
    'check_gateway_ssrf',
    'CVE_2026_25253_ID',
    
    # Secret Scanner
    'scan_secrets',
    'quick_secret_scan',
    'scan_file_secrets',
    'scan_directory_secrets',
    'scan_openclaw_directory',
    'SECRET_PATTERNS',
    
    # mDNS Detector
    'detect_mdns',
    'check_mdns_broadcast',
    'check_mdns_vulnerability',
    'MDNS_PORT',
    'OPENCLAW_SERVICE_TYPES'
]


def get_cve_database_status():
    """Get status of CVE database"""
    try:
        stats = get_cve_statistics()
        return {
            'initialized': True,
            'stats': stats
        }
    except Exception as e:
        return {
            'initialized': False,
            'error': str(e)
        }


def run_security_scan(target: str = None, checks: list = None):
    """
    Run comprehensive security scan.
    
    Args:
        target: Target URL for vulnerability checks
        checks: List of checks to run. Default: all
                Options: ['cve_2026_25253', 'secrets', 'mdns']
    
    Returns:
        Dictionary with scan results
    """
    if checks is None:
        checks = ['cve_2026_25253', 'secrets', 'mdns']
    
    results = {
        'scan_time': None,
        'target': target,
        'checks_requested': checks,
        'results': {}
    }
    
    from datetime import datetime
    results['scan_time'] = datetime.now().isoformat()
    
    # CVE-2026-25253 check
    if 'cve_2026_25253' in checks:
        try:
            if target:
                results['results']['cve_2026_25253'] = detect_cve_2026_25253(target)
            else:
                results['results']['cve_2026_25253'] = {
                    'error': 'No target specified for CVE-2026-25253 check'
                }
        except Exception as e:
            results['results']['cve_2026_25253'] = {'error': str(e)}
    
    # Secret scan
    if 'secrets' in checks:
        try:
            results['results']['secrets'] = scan_secrets()
        except Exception as e:
            results['results']['secrets'] = {'error': str(e)}
    
    # mDNS check
    if 'mdns' in checks:
        try:
            results['results']['mdns'] = detect_mdns()
        except Exception as e:
            results['results']['mdns'] = {'error': str(e)}
    
    # Calculate summary
    vulnerable_count = 0
    critical_count = 0
    high_count = 0
    
    if 'cve_2026_25253' in results['results']:
        if results['results']['cve_2026_25253'].get('vulnerable'):
            vulnerable_count += 1
    
    if 'secrets' in results['results']:
        secrets_found = results['results']['secrets'].get('found', 0)
        if secrets_found > 0:
            vulnerable_count += 1
            sev_summary = results['results']['secrets'].get('severity_summary', {})
            critical_count += sev_summary.get('critical', 0)
            high_count += sev_summary.get('high', 0)
    
    if 'mdns' in results['results']:
        if results['results']['mdns'].get('broadcasting'):
            vulnerable_count += 1
    
    results['summary'] = {
        'vulnerable_checks': vulnerable_count,
        'critical_secrets': critical_count,
        'high_severity_secrets': high_count,
        'total_issues': vulnerable_count + critical_count + high_count
    }
    
    return results
