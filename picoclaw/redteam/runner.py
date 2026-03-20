#!/usr/bin/env python3
"""
Penetration Test Runner for Picoclaw Continuous Red Teaming

Provides test execution and orchestration for security testing:
- Single exploit tests
- Test suites
- Scheduled tests
- Result collection and reporting
"""

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Callable, Awaitable
import threading
import queue


from .exploits import (
    ExploitLibrary,
    ExploitDefinition,
    ExploitResult,
    get_exploit_library,
    ExploitCategory,
    ExploitRisk
)
from .scanner import (
    SecurityScanner,
    ScanResult,
    VulnerabilityFinding,
    TargetConfig,
    Severity,
    ScanType
)


class TestStatus(Enum):
    """Status of a test"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SCHEDULED = "scheduled"


class TestType(Enum):
    """Type of test"""
    SINGLE = "single"          # Single exploit test
    SUITE = "suite"           # Test suite
    FULL_SCAN = "full_scan"   # Full security scan
    CUSTOM = "custom"         # Custom test


@dataclass
class TestConfig:
    """Configuration for a test run"""
    name: str
    test_type: TestType
    target: str
    
    # Test-specific options
    exploit_name: Optional[str] = None
    suite_name: Optional[str] = None
    scan_types: Set[ScanType] = field(default_factory=lambda: {ScanType.FULL})
    
    # Execution options
    safe_mode: bool = True
    timeout: int = 300  # 5 minutes default
    retries: int = 0
    
    # Scheduling
    scheduled_time: Optional[datetime] = None
    recurring: bool = False
    recurring_interval: Optional[timedelta] = None
    
    # Notifications
    notify_on_complete: bool = False
    notify_on_vuln: bool = False
    notification_channels: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'test_type': self.test_type.value,
            'target': self.target,
            'exploit_name': self.exploit_name,
            'suite_name': self.suite_name,
            'scan_types': [st.value for st in self.scan_types],
            'safe_mode': self.safe_mode,
            'timeout': self.timeout,
            'retries': self.retries,
            'scheduled_time': self.scheduled_time.isoformat() if self.scheduled_time else None,
            'recurring': self.recurring
        }


@dataclass
class TestResult:
    """Result of a test execution"""
    test_id: str
    config: TestConfig
    status: TestStatus
    start_time: str
    end_time: str = ""
    duration_ms: int = 0
    
    # Results
    exploit_results: List[ExploitResult] = field(default_factory=list)
    scan_results: List[ScanResult] = field(default_factory=list)
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    
    # Summary
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    vulnerability_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    
    # Error info
    error_message: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'test_id': self.test_id,
            'status': self.status.value,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration_ms': self.duration_ms,
            'config': self.config.to_dict(),
            'summary': {
                'total_tests': self.total_tests,
                'passed_tests': self.passed_tests,
                'failed_tests': self.failed_tests,
                'vulnerability_count': self.vulnerability_count,
                'critical_count': self.critical_count,
                'high_count': self.high_count
            },
            'exploit_results': [r.to_dict() for r in self.exploit_results],
            'error_message': self.error_message
        }


@dataclass
class TestSuite:
    """Definition of a test suite"""
    name: str
    description: str
    exploits: List[str]
    scan_types: List[ScanType] = field(default_factory=list)
    
    # Suite options
    stop_on_first_vuln: bool = False
    parallel: bool = True
    max_parallel: int = 3
    
    # Tags for categorization
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'description': self.description,
            'exploits': self.exploits,
            'scan_types': [st.value for st in self.scan_types],
            'stop_on_first_vuln': self.stop_on_first_vuln,
            'parallel': self.parallel,
            'max_parallel': self.max_parallel,
            'tags': self.tags
        }


# Pre-defined test suites
DEFAULT_SUITES = {
    'quick': TestSuite(
        name='quick',
        description='Quick security check - critical vulnerabilities only',
        exploits=['CVE-2026-25253', 'EXP-AUTH-001'],
        scan_types=[ScanType.AUTH, ScanType.ENDPOINT],
        stop_on_first_vuln=False,
        parallel=True,
        max_parallel=5,
        tags=['quick', 'critical', 'auth']
    ),
    'comprehensive': TestSuite(
        name='comprehensive',
        description='Comprehensive security scan - all test types',
        exploits=['CVE-2026-25253', 'EXP-TRAVERSAL-001', 'EXP-AUTH-001', 'EXP-RATE-001', 'EXP-PROMPT-001'],
        scan_types=[ScanType.ENDPOINT, ScanType.AUTH, ScanType.PERMISSION, ScanType.RATE_LIMIT],
        stop_on_first_vuln=False,
        parallel=True,
        max_parallel=3,
        tags=['comprehensive', 'full', 'all']
    ),
    'injection': TestSuite(
        name='injection',
        description='Injection vulnerability tests',
        exploits=['EXP-TRAVERSAL-001', 'EXP-PROMPT-001'],
        scan_types=[ScanType.ENDPOINT],
        stop_on_first_vuln=False,
        parallel=True,
        max_parallel=5,
        tags=['injection', 'traversal', 'prompt']
    ),
    'auth': TestSuite(
        name='auth',
        description='Authentication and authorization tests',
        exploits=['EXP-AUTH-001'],
        scan_types=[ScanType.AUTH, ScanType.PERMISSION],
        stop_on_first_vuln=False,
        parallel=True,
        max_parallel=3,
        tags=['auth', 'authorization', 'session']
    ),
    'ssrf': TestSuite(
        name='ssrf',
        description='SSRF and URL injection tests',
        exploits=['CVE-2026-25253'],
        scan_types=[ScanType.ENDPOINT],
        stop_on_first_vuln=False,
        parallel=True,
        max_parallel=3,
        tags=['ssrf', 'url', 'injection']
    )
}


class TestScheduler:
    """Background scheduler for periodic tests"""
    
    def __init__(self, runner: 'RedTeamRunner'):
        self.runner = runner
        self._scheduled_tests: Dict[str, Dict] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._queue: queue.Queue = queue.Queue()
    
    def schedule_test(
        self,
        config: TestConfig,
        interval: timedelta,
        test_id: Optional[str] = None
    ) -> str:
        """Schedule a recurring test"""
        if test_id is None:
            test_id = self._generate_test_id(config)
        
        self._scheduled_tests[test_id] = {
            'config': config,
            'interval': interval,
            'next_run': datetime.now() + interval,
            'last_run': None,
            'run_count': 0
        }
        
        return test_id
    
    def unschedule_test(self, test_id: str) -> bool:
        """Remove a scheduled test"""
        if test_id in self._scheduled_tests:
            del self._scheduled_tests[test_id]
            return True
        return False
    
    def start(self):
        """Start the scheduler"""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop the scheduler"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self._running:
            now = datetime.now()
            
            for test_id, schedule in list(self._scheduled_tests.items()):
                if schedule['next_run'] <= now:
                    # Queue the test for execution
                    self._queue.put((test_id, schedule['config']))
                    
                    # Update schedule
                    schedule['last_run'] = now
                    schedule['next_run'] = now + schedule['interval']
                    schedule['run_count'] += 1
            
            # Sleep for a bit before checking again
            time.sleep(1)
    
    def _generate_test_id(self, config: TestConfig) -> str:
        """Generate unique test ID"""
        content = f"{config.name}_{config.target}_{datetime.now().isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]


class RedTeamRunner:
    """
    Penetration test runner for continuous red teaming.
    
    Supports:
    - Single exploit tests
    - Test suites (pre-defined and custom)
    - Scheduled/periodic tests
    - Result collection and analysis
    - Safe mode execution (never causes damage)
    
    Example:
        runner = RedTeamRunner()
        
        # Run single exploit test
        result = await runner.run_test('CVE-2026-25253', 'http://localhost:18789')
        
        # Run a test suite
        result = await runner.run_suite('comprehensive', 'http://localhost:18789')
        
        # Schedule periodic tests
        test_id = runner.schedule_test(
            TestConfig(name='daily-check', ...),
            interval=timedelta(hours=24)
        )
        
        # Get results
        result = runner.get_results(test_id)
    """
    
    def __init__(
        self,
        *,
        safe_mode: bool = True,
        results_dir: Optional[str] = None,
        max_concurrent: int = 5
    ):
        """
        Initialize the test runner.
        
        Args:
            safe_mode: Run all tests in safe mode (no damage)
            results_dir: Directory to store results (optional)
            max_concurrent: Maximum concurrent tests
        """
        self.safe_mode = safe_mode
        self.results_dir = Path(results_dir) if results_dir else None
        self.max_concurrent = max_concurrent
        
        # Components
        self._exploit_library = get_exploit_library()
        self._scanner = SecurityScanner(safe_mode=safe_mode)
        self._scheduler = TestScheduler(self)
        
        # Test tracking
        self._results: Dict[str, TestResult] = {}
        self._running_tests: Dict[str, asyncio.Task] = {}
        self._test_queue: asyncio.Queue = asyncio.Queue()
        self._suites: Dict[str, TestSuite] = dict(DEFAULT_SUITES)
        
        # Callbacks
        self._on_complete_callbacks: List[Callable[[TestResult], Awaitable[None]]] = []
        self._on_vuln_callbacks: List[Callable[[VulnerabilityFinding], Awaitable[None]]] = []
    
    def register_suite(self, suite: TestSuite):
        """Register a custom test suite"""
        self._suites[suite.name] = suite
    
    def get_suite(self, name: str) -> Optional[TestSuite]:
        """Get a test suite by name"""
        return self._suites.get(name)
    
    def list_suites(self) -> List[TestSuite]:
        """List all available test suites"""
        return list(self._suites.values())
    
    def on_complete(self, callback: Callable[[TestResult], Awaitable[None]]):
        """Register callback for test completion"""
        self._on_complete_callbacks.append(callback)
    
    def on_vulnerability_found(self, callback: Callable[[VulnerabilityFinding], Awaitable[None]]):
        """Register callback for vulnerability found"""
        self._on_vuln_callbacks.append(callback)
    
    async def run_test(
        self,
        exploit_name: str,
        target: str,
        *,
        config: Optional[TestConfig] = None,
        safe_mode: Optional[bool] = None
    ) -> TestResult:
        """
        Execute a single exploit test.
        
        Args:
            exploit_name: Name or identifier of exploit to run
            target: Target URL
            config: Optional test configuration
            safe_mode: Override safe mode setting
            
        Returns:
            TestResult with outcome
        """
        if config is None:
            config = TestConfig(
                name=f"test_{exploit_name}",
                test_type=TestType.SINGLE,
                target=target,
                exploit_name=exploit_name,
                safe_mode=safe_mode if safe_mode is not None else self.safe_mode
            )
        
        test_id = self._generate_test_id(config)
        result = TestResult(
            test_id=test_id,
            config=config,
            status=TestStatus.RUNNING,
            start_time=datetime.now().isoformat()
        )
        
        self._results[test_id] = result
        
        try:
            # Run the exploit test
            exploit_result = await self._exploit_library.run_exploit_test(
                exploit_name,
                target,
                safe_mode=config.safe_mode
            )
            
            result.exploit_results.append(exploit_result)
            result.total_tests = 1
            
            if exploit_result.vulnerable:
                result.failed_tests = 1
                result.vulnerability_count = 1
                result.critical_count = 1 if exploit_result.details.get('severity') == 'CRITICAL' else 0
            else:
                result.passed_tests = 1
            
            result.status = TestStatus.COMPLETED
            
        except asyncio.TimeoutError:
            result.status = TestStatus.FAILED
            result.error_message = "Test timed out"
            
        except Exception as e:
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        
        finally:
            result.end_time = datetime.now().isoformat()
            start = datetime.fromisoformat(result.start_time)
            end = datetime.fromisoformat(result.end_time)
            result.duration_ms = int((end - start).total_seconds() * 1000)
            
            # Save result
            if self.results_dir:
                self._save_result(result)
            
            # Call callbacks
            await self._call_completion_callbacks(result)
        
        return result
    
    async def run_suite(
        self,
        suite_name: str,
        target: str,
        *,
        config: Optional[TestConfig] = None,
        safe_mode: Optional[bool] = None
    ) -> TestResult:
        """
        Execute a test suite.
        
        Args:
            suite_name: Name of test suite
            target: Target URL
            config: Optional test configuration
            safe_mode: Override safe mode setting
            
        Returns:
            TestResult with combined outcome
        """
        suite = self._suites.get(suite_name)
        if suite is None:
            return TestResult(
                test_id="error",
                config=config or TestConfig(name="error", test_type=TestType.SUITE, target=target),
                status=TestStatus.FAILED,
                start_time=datetime.now().isoformat(),
                error_message=f"Suite '{suite_name}' not found"
            )
        
        if config is None:
            config = TestConfig(
                name=f"suite_{suite_name}",
                test_type=TestType.SUITE,
                target=target,
                suite_name=suite_name,
                safe_mode=safe_mode if safe_mode is not None else self.safe_mode
            )
        
        test_id = self._generate_test_id(config)
        result = TestResult(
            test_id=test_id,
            config=config,
            status=TestStatus.RUNNING,
            start_time=datetime.now().isoformat()
        )
        
        self._results[test_id] = result
        
        try:
            # Run scanner if scan types specified
            if suite.scan_types:
                target_config = TargetConfig(
                    url=target,
                    scan_types=set(suite.scan_types),
                    safe_mode=config.safe_mode
                )
                scan_result = await self._scanner.scan_target(target_config)
                result.scan_results.append(scan_result)
                
                # Add findings
                for finding in scan_result.findings:
                    result.findings.append(finding)
                    await self._call_vuln_callbacks(finding)
            
            # Run exploit tests
            if suite.parallel:
                # Run in parallel with semaphore
                sem = asyncio.Semaphore(suite.max_parallel)
                
                async def run_with_semaphore(exploit_name: str):
                    async with sem:
                        return await self._exploit_library.run_exploit_test(
                            exploit_name,
                            target,
                            config.safe_mode
                        )
                
                tasks = [run_with_semaphore(exp) for exp in suite.exploits]
                exploit_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for exp_result in exploit_results:
                    if isinstance(exp_result, Exception):
                        result.failed_tests += 1
                        continue
                    
                    result.exploit_results.append(exp_result)
                    result.total_tests += 1
                    
                    if exp_result.vulnerable:
                        result.failed_tests += 1
                        result.vulnerability_count += 1
                        
                        if suite.stop_on_first_vuln:
                            break
                    else:
                        result.passed_tests += 1
            
            else:
                # Run sequentially
                for exploit_name in suite.exploits:
                    if suite.stop_on_first_vuln and result.vulnerability_count > 0:
                        break
                    
                    exp_result = await self._exploit_library.run_exploit_test(
                        exploit_name,
                        target,
                        config.safe_mode
                    )
                    
                    result.exploit_results.append(exp_result)
                    result.total_tests += 1
                    
                    if exp_result.vulnerable:
                        result.failed_tests += 1
                        result.vulnerability_count += 1
            else:
                result.passed_tests += 1
            
            # Update counts
            result.critical_count = sum(
                1 for f in result.findings if f.severity == Severity.CRITICAL
            )
            result.high_count = sum(
                1 for f in result.findings if f.severity == Severity.HIGH
            )
            
            result.status = TestStatus.COMPLETED
            
        except asyncio.TimeoutError:
            result.status = TestStatus.FAILED
            result.error_message = "Suite timed out"
            
        except Exception as e:
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        
        finally:
            result.end_time = datetime.now().isoformat()
            start = datetime.fromisoformat(result.start_time)
            end = datetime.fromisoformat(result.end_time)
            result.duration_ms = int((end - start).total_seconds() * 1000)
            
            if self.results_dir:
                self._save_result(result)
            
            await self._call_completion_callbacks(result)
        
        return result
    
    async def run_full_scan(
        self,
        target: str,
        *,
        config: Optional[TestConfig] = None,
        scan_types: Optional[Set[ScanType]] = None,
        safe_mode: Optional[bool] = None
    ) -> TestResult:
        """
        Run a full security scan.
        
        Args:
            target: Target URL
            config: Optional test configuration
            scan_types: Types of scans to run
            safe_mode: Override safe mode setting
            
        Returns:
            TestResult with scan results
        """
        if config is None:
            config = TestConfig(
                name="full_scan",
                test_type=TestType.FULL_SCAN,
                target=target,
                safe_mode=safe_mode if safe_mode is not None else self.safe_mode
            )
        
        test_id = self._generate_test_id(config)
        result = TestResult(
            test_id=test_id,
            config=config,
            status=TestStatus.RUNNING,
            start_time=datetime.now().isoformat()
        )
        
        self._results[test_id] = result
        
        try:
            # Run scanner
            target_config = TargetConfig(
                url=target,
                scan_types=scan_types or {ScanType.FULL},
                safe_mode=config.safe_mode
            )
            
            scan_result = await self._scanner.scan_target(target_config)
            result.scan_results.append(scan_result)
            
            # Add findings
            for finding in scan_result.findings:
                result.findings.append(finding)
                await self._call_vuln_callbacks(finding)
            
            result.total_tests = 1
            result.passed_tests = 0 if scan_result.total_findings > 0 else 1
            result.vulnerability_count = scan_result.total_findings
            
            # Count by severity
            severity_grouped = self._scanner.rate_severity(scan_result.findings)
            result.critical_count = len(severity_grouped.get('critical', []))
            result.high_count = len(severity_grouped.get('high', []))
            
            result.status = TestStatus.COMPLETED
            
        except asyncio.TimeoutError:
            result.status = TestStatus.FAILED
            result.error_message = "Scan timed out"
            
        except Exception as e:
            result.status = TestStatus.FAILED
            result.error_message = str(e)
        
        finally:
            result.end_time = datetime.now().isoformat()
            start = datetime.fromisoformat(result.start_time)
            end = datetime.fromisoformat(result.end_time)
            result.duration_ms = int((end - start).total_seconds() * 1000)
            
            if self.results_dir:
                self._save_result(result)
            
            await self._call_completion_callbacks(result)
        
        return result
    
    def schedule_test(
        self,
        config: TestConfig,
        interval: timedelta
    ) -> str:
        """
        Schedule a periodic test.
        
        Args:
            config: Test configuration
            interval: Time between runs
            
        Returns:
            Scheduled test ID
        """
        if not self._scheduler._running:
            self._scheduler.start()
        
        return self._scheduler.schedule_test(config, interval)
    
    def unschedule_test(self, test_id: str) -> bool:
        """Remove a scheduled test"""
        return self._scheduler.unschedule_test(test_id)
    
    def get_results(self, test_id: str) -> Optional[TestResult]:
        """
        Get results for a test.
        
        Args:
            test_id: Test ID to look up
            
        Returns:
            TestResult if found, None otherwise
        """
        return self._results.get(test_id)
    
    def get_recent_results(
        self,
        limit: int = 10,
        status: Optional[TestStatus] = None
    ) -> List[TestResult]:
        """
        Get recent test results.
        
        Args:
            limit: Maximum number of results
            status: Filter by status
            
        Returns:
            List of recent TestResults
        """
        results = list(self._results.values())
        
        if status:
            results = [r for r in results if r.status == status]
        
        # Sort by start time (most recent first)
        results.sort(key=lambda r: r.start_time, reverse=True)
        
        return results[:limit]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get test statistics.
        
        Returns:
            Dictionary with statistics
        """
        results = list(self._results.values())
        
        total = len(results)
        completed = len([r for r in results if r.status == TestStatus.COMPLETED])
        failed = len([r for r in results if r.status == TestStatus.FAILED])
        
        total_vulns = sum(r.vulnerability_count for r in results)
        total_critical = sum(r.critical_count for r in results)
        total_high = sum(r.high_count for r in results)
        
        avg_duration = 0
        if completed > 0:
            durations = [r.duration_ms for r in results if r.status == TestStatus.COMPLETED]
            avg_duration = sum(durations) / len(durations) if durations else 0
        
        return {
            'total_tests': total,
            'completed_tests': completed,
            'failed_tests': failed,
            'running_tests': len(self._running_tests),
            'scheduled_tests': len(self._scheduler._scheduled_tests),
            'total_vulnerabilities': total_vulns,
            'critical_vulnerabilities': total_critical,
            'high_vulnerabilities': total_high,
            'average_duration_ms': int(avg_duration)
        }
    
    def _generate_test_id(self, config: TestConfig) -> str:
        """Generate unique test ID"""
        content = f"{config.name}_{config.target}_{datetime.now().isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]
    
    def _save_result(self, result: TestResult):
        """Save result to file"""
        if not self.results_dir:
            return
        
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        filename = f"result_{result.test_id}_{result.start_time.replace(':', '-').replace('.', '-')}.json"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
    
    async def _call_completion_callbacks(self, result: TestResult):
        """Call all completion callbacks"""
        for callback in self._on_complete_callbacks:
            try:
                await callback(result)
            except Exception as e:
                pass  # Don't fail on callback errors
    
    async def _call_vuln_callbacks(self, finding: VulnerabilityFinding):
        """Call all vulnerability callbacks"""
        for callback in self._on_vuln_callbacks:
            try:
                await callback(finding)
            except Exception as e:
                pass  # Don't fail on callback errors


# Singleton instance
_runner_instance: Optional[RedTeamRunner] = None


def get_runner(
    safe_mode: bool = True,
    results_dir: Optional[str] = None
) -> RedTeamRunner:
    """Get the singleton RedTeamRunner instance"""
    global _runner_instance
    if _runner_instance is None:
        _runner_instance = RedTeamRunner(
            safe_mode=safe_mode,
            results_dir=results_dir
        )
    return _runner_instance


async def quick_test(target: str, safe_mode: bool = True) -> TestResult:
    """
    Run a quick security test against a target.
    
    Args:
        target: Target URL
        safe_mode: Run in safe mode
        
    Returns:
        TestResult
    """
    runner = get_runner(safe_mode=safe_mode)
    return await runner.run_suite('quick', target, safe_mode=safe_mode)


def quick_test_sync(target: str, safe_mode: bool = True) -> TestResult:
    """Synchronous wrapper for quick_test"""
    return asyncio.run(quick_test(target, safe_mode))


if __name__ == '__main__':
    import sys
    
    target = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:18789'
    suite = sys.argv[2] if len(sys.argv) > 2 else 'quick'
    
    print(f"Running '{suite}' test suite against {target}...")
    print()
    
    runner = get_runner()
    
    result = asyncio.run(runner.run_suite(suite, target))
    
    print(f"Test ID: {result.test_id}")
    print(f"Status: {result.status.value}")
    print(f"Duration: {result.duration_ms}ms")
    print()
    
    print(f"Summary:")
    print(f"  Total tests: {result.total_tests}")
    print(f"  Passed: {result.passed_tests}")
    print(f"  Failed: {result.failed_tests}")
    print(f"  Vulnerabilities: {result.vulnerability_count}")
    print(f"    Critical: {result.critical_count}")
    print(f"    High: {result.high_count}")
    
    if result.error_message:
        print(f"\nError: {result.error_message}")
    
    if result.findings:
        print("\nFindings:")
        for finding in result.findings:
            print(f"  [{finding.severity.value.upper()}] {finding.name}")
            print(f"    {finding.description}")