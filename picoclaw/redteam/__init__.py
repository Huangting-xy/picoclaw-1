#!/usr/bin/env python3
"""
Picoclaw Continuous Red Teaming Module

This module provides comprehensive security testing and vulnerability management
for the Picoclaw security framework.

Components:
- SecurityScanner: Comprehensive security scanner for targets
- ExploitLibrary: Library of exploit definitions for testing
- RedTeamRunner: Penetration test runner with scheduling
- FindingManager: Vulnerability finding management and tracking
- HardeningAdvisor: Security hardening recommendations

Usage:
    from picoclaw.redteam import (
        SecurityScanner,
        ExploitLibrary,
        RedTeamRunner,
        FindingManager,
        HardeningAdvisor,
        get_exploit_library,
        get_runner,
        get_finding_manager,
        get_hardening_advisor
    )
    
    # Initialize scanner
    scanner = SecurityScanner(safe_mode=True)
    result = await scanner.scan_target(TargetConfig(
        url="http://localhost:18789",
        scan_types={ScanType.FULL}
    ))
    
    # Run exploit tests
    library = get_exploit_library()
    result = await library.run_exploit_test(
        "CVE-2026-25253",
        "http://localhost:18789"
    )
    
    # Run test suite
    runner = get_runner()
    result = await runner.run_suite("quick", "http://localhost:18789")
    
    # Report findings
    manager = get_finding_manager()
    finding_id = manager.report_finding({
        'name': 'SSRF Vulnerability',
        'severity': 'critical',
        'target': 'http://localhost:18789'
    })
    
    # Get hardening recommendations
    advisor = get_hardening_advisor()
    reports = advisor.analyze_findings(findings)
"""

from .scanner import (
    SecurityScanner,
    TargetConfig,
    ScanResult,
    VulnerabilityFinding,
    ScanType,
    Severity,
    quick_scan,
    run_sync_scan
)

from .exploits import (
    ExploitLibrary,
    ExploitDefinition,
    ExploitResult,
    ExploitCategory,
    ExploitRisk,
    CVE_2026_25253,
    FILE_PATH_TRAVERSAL_TEST,
    AUTH_BYPASS_TEST,
    RATE_LIMIT_BYPASS_TEST,
    PROMPT_INJECTION_TEST,
    get_exploit_library,
    run_exploit
)

from .runner import (
    RedTeamRunner,
    TestConfig,
    TestResult,
    TestSuite,
    TestStatus,
    TestType,
    DEFAULT_SUITES,
    get_runner,
    quick_test,
    quick_test_sync
)

from .findings import (
    FindingManager,
    VulnerabilityFinding as ManagedFinding,
    FindingStatus,
    FindingType,
    FindingStatistics,
    CVEInfo,
    get_finding_manager,
    get_severity_from_cvss,
    calculate_cvss_score
)

from .hardening import (
    HardeningAdvisor,
    HardeningStep,
    HardeningReport,
    HardeningCategory,
    HardeningPriority,
    FixStatus,
    HARDENING_TEMPLATES,
    get_hardening_advisor
)


__all__ = [
    # Scanner
    'SecurityScanner',
    'TargetConfig',
    'ScanResult',
    'VulnerabilityFinding',
    'ScanType',
    'Severity',
    'quick_scan',
    'run_sync_scan',
    
    # Exploits
    'ExploitLibrary',
    'ExploitDefinition',
    'ExploitResult',
    'ExploitCategory',
    'ExploitRisk',
    'CVE_2026_25253',
    'FILE_PATH_TRAVERSAL_TEST',
    'AUTH_BYPASS_TEST',
    'RATE_LIMIT_BYPASS_TEST',
    'PROMPT_INJECTION_TEST',
    'get_exploit_library',
    'run_exploit',
    
    # Runner
    'RedTeamRunner',
    'TestConfig',
    'TestResult',
    'TestSuite',
    'TestStatus',
    'TestType',
    'DEFAULT_SUITES',
    'get_runner',
    'quick_test',
    'quick_test_sync',
    
    # Findings
    'FindingManager',
    'ManagedFinding',
    'FindingStatus',
    'FindingType',
    'FindingStatistics',
    'CVEInfo',
    'get_finding_manager',
    'get_severity_from_cvss',
    'calculate_cvss_score',
    
    # Hardening
    'HardeningAdvisor',
    'HardeningStep',
    'HardeningReport',
    'HardeningCategory',
    'HardeningPriority',
    'FixStatus',
    'HARDENING_TEMPLATES',
    'get_hardening_advisor'
]

__version__ = '1.0.0'


async def run_full_security_test(
    target: str,
    *,
    safe_mode: bool = True,
    scan_types: set = None
) -> dict:
    """
    Convenience function to run a complete security test.
    
    Runs all components:
    - Full security scan
    - All exploit tests
    - Generates findings
    - Produces hardening recommendations
    
    Args:
        target: Target URL to test
        safe_mode: Run in safe mode (no damage)
        scan_types: Types of scans to run (default: all)
        
    Returns:
        Dictionary with complete test results
    """
    from .scanner import ScanType
    
    if scan_types is None:
        scan_types = {ScanType.FULL}
    
    # Initialize components
    scanner = SecurityScanner(safe_mode=safe_mode)
    exploit_library = get_exploit_library()
    runner = get_runner(safe_mode=safe_mode)
    finding_manager = get_finding_manager()
    hardening_advisor = get_hardening_advisor()
    
    results = {
        'target': target,
        'safe_mode': safe_mode,
        'scan_result': None,
        'exploit_results': [],
        'findings': [],
        'hardening_reports': [],
        'summary': {}
    }
    
    # Run security scan
    target_config = TargetConfig(
        url=target,
        scan_types=scan_types,
        safe_mode=safe_mode
    )
    scan_result = await scanner.scan_target(target_config)
    results['scan_result'] = scan_result.to_dict()
    
    # Report scan findings
    for finding in scan_result.findings:
        finding_id = finding_manager.report_finding({
            'name': finding.name,
            'description': finding.description,
            'severity': finding.severity.value,
            'target': finding.target,
            'evidence': finding.evidence,
            'scanner': 'SecurityScanner'
        })
        results['findings'].append(finding_id)
    
    # Run all exploits
    for exploit in exploit_library.get_all_exploits():
        try:
            exploit_result = await exploit_library.run_exploit_test(
                exploit.identifier,
                target,
                safe_mode=safe_mode
            )
            results['exploit_results'].append(exploit_result.to_dict())
            
            # Report if vulnerable
            if exploit_result.vulnerable:
                finding_manager.report_finding({
                    'name': f"Vulnerable to {exploit.name}",
                    'description': exploit.description,
                    'severity': exploit.severity or 'high',
                    'cve_id': exploit.cve_id,
                    'target': target,
                    'evidence': exploit_result.evidence,
                    'tags': exploit.tags,
                    'scanner': 'ExploitLibrary'
                })
        except Exception as e:
            results['exploit_results'].append({
                'exploit': exploit.identifier,
                'error': str(e)
            })
    
    # Get all findings
    all_findings = finding_manager.get_findings(limit=1000)
    
    # Generate hardening recommendations
    hardening_reports = hardening_advisor.analyze_findings(all_findings)
    results['hardening_reports'] = [r.to_dict() for r in hardening_reports]
    
    # Generate summary
    stats = finding_manager.get_statistics()
    results['summary'] = {
        'total_findings': stats.total_findings,
        'critical': stats.critical_count,
        'high': stats.high_count,
        'medium': stats.medium_count,
        'low': stats.low_count,
        'by_type': stats.by_type,
        'hardening_steps_available': sum(r.auto_fixable for r in hardening_reports)
    }
    
    return results


def run_full_security_test_sync(
    target: str,
    *,
    safe_mode: bool = True
) -> dict:
    """Synchronous wrapper for run_full_security_test"""
    import asyncio
    return asyncio.run(run_full_security_test(target, safe_mode=safe_mode))


if __name__ == '__main__':
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:18789'
    
    print(f"Picoclaw Red Team Module v{__version__}")
    print(f"Running full security test against {target}...")
    print()
    
    result = run_full_security_test_sync(target)
    
    print("=== Scan Results ===")
    if result['scan_result']:
        sr = result['scan_result']
        print(f"Duration: {sr['duration_ms']}ms")
        print(f"Findings: {sr['summary']['total_findings']}")
        for sev, count in sr['summary']['by_severity'].items():
            if count > 0:
                print(f"  {sev}: {count}")
    
    print("\n=== Exploit Results ===")
    for er in result['exploit_results']:
        status = "VULNERABLE" if er.get('vulnerable') else "SAFE"
        print(f"  {er.get('exploit_name', er.get('exploit', 'unknown'))}: {status}")
    
    print("\n=== Summary ===")
    summary = result['summary']
    print(f"Total Findings: {summary['total_findings']}")
    print(f"  Critical: {summary['critical']}")
    print(f"  High: {summary['high']}")
    print(f"  Medium: {summary['medium']}")
    print(f"  Low: {summary['low']}")
    print(f"Auto-fixable Hardening Steps: {summary['hardening_steps_available']}")