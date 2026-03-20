"""
Picoclaw Observability Module
Decision capture and contamination detection for agent transparency.

Stage 3.2: Decision Capture
"""

from .decisions import (
    DecisionCapture,
    DecisionNode,
    get_decision_capture,
    record_decision,
)

from .contamination import (
    ContaminationDetector,
    ContaminationFinding,
    Severity,
    FindingType,
    get_detector,
    scan_content,
    check_memory_write,
)

__all__ = [
    # Decisions
    'DecisionCapture',
    'DecisionNode',
    'get_decision_capture',
    'record_decision',
    
    # Contamination
    'ContaminationDetector',
    'ContaminationFinding',
    'Severity',
    'FindingType',
    'get_detector',
    'scan_content',
    'check_memory_write',
]