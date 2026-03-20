#!/usr/bin/env python3
"""
Picoclaw Observability Module

This module provides behavior baseline learning and anomaly detection
for monitoring agent activities and detecting suspicious behavior.

Components:
- BehaviorBaseline: Learns normal agent behavior patterns over time
- AnomalyDetector: Compares current behavior against learned baseline

Usage:
    from observability import (
        BehaviorBaseline,
        AnomalyDetector,
        get_behavior_baseline,
        get_anomaly_detector,
        check_for_anomalies
    )
    
    # Initialize
    baseline = get_behavior_baseline()
    detector = get_anomaly_detector(baseline)
    
    # Record operations for baseline learning
    await baseline.record_operation('agent_1', {
        'tool': 'exec',
        'duration_ms': 150,
        'memory_mb': 128,
        'cpu_percent': 15
    })
    
    # Check for anomalies (after training complete)
    if baseline.is_trained('agent_1'):
        anomalies = detector.check_operation('agent_1', {
            'tool': 'some_tool',
            ...
        })
        
        for anomaly in anomalies:
            print(f"Anomaly: {anomaly['anomaly_type']} - {anomaly['description']}")
    
    # Get baseline statistics
    stats = baseline.get_baseline('agent_1')
    print(f"Tools used: {list(stats['tool_calls'].keys())}")
"""

from .baseline import (
    BehaviorBaseline,
    ToolCallStats,
    SequenceStats,
    TimingStats,
    ResourceStats,
    AgentBaseline,
    SENSITIVE_TOOLS,
    get_behavior_baseline
)

from .anomaly import (
    AnomalyDetector,
    Anomaly,
    AnomalyType,
    AnomalySeverity,
    get_anomaly_detector,
    check_for_anomalies
)

__all__ = [
    # Baseline
    'BehaviorBaseline',
    'ToolCallStats',
    'SequenceStats',
    'TimingStats',
    'ResourceStats',
    'AgentBaseline',
    'SENSITIVE_TOOLS',
    'get_behavior_baseline',
    
    # Anomaly Detection
    'AnomalyDetector',
    'Anomaly',
    'AnomalyType',
    'AnomalySeverity',
    'get_anomaly_detector',
    'check_for_anomalies'
]

__version__ = '1.0.0'