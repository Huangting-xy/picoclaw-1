#!/usr/bin/env python3
"""
Decision Tree Capture Module for Picoclaw Observability
Records and traces why each decision was made with full provenance.

Stage 3.2: Decision Capture
"""

import os
import json
import uuid
import asyncio
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from asyncio import Lock

logger = logging.getLogger(__name__)


@dataclass
class DecisionNode:
    """Represents a single decision point in the decision tree"""
    decision_id: str
    agent_id: str
    session_id: str
    parent_id: Optional[str]
    trigger: str
    options_considered: list[str]
    chosen_option: str
    reasoning: str
    confidence: float
    result_id: Optional[str]  # Links to final result if applicable
    children: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            'decision_id': self.decision_id,
            'agent_id': self.agent_id,
            'session_id': self.session_id,
            'parent_id': self.parent_id,
            'trigger': self.trigger,
            'options_considered': self.options_considered,
            'chosen_option': self.chosen_option,
            'reasoning': self.reasoning,
            'confidence': self.confidence,
            'result_id': self.result_id,
            'children': self.children,
            'timestamp': self.timestamp
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'DecisionNode':
        """Create from dictionary"""
        return cls(
            decision_id=data['decision_id'],
            agent_id=data['agent_id'],
            session_id=data['session_id'],
            parent_id=data.get('parent_id'),
            trigger=data['trigger'],
            options_considered=data['options_considered'],
            chosen_option=data['chosen_option'],
            reasoning=data['reasoning'],
            confidence=data['confidence'],
            result_id=data.get('result_id'),
            children=data.get('children', []),
            timestamp=data.get('timestamp', datetime.utcnow().isoformat())
        )


class DecisionCapture:
    """
    Capture and trace decision trees for agent sessions.
    
    Provides:
    - Recording WHY each decision was made
    - Building decision trees per session/agent
    - "Explain" queries to trace back why a result happened
    - Async-safe JSONL persistence
    
    Usage:
        capture = DecisionCapture('/var/log/picoclaw/decisions')
        await capture.record_decision(
            agent_id='agent-001',
            trigger='User requested file analysis',
            options=['scan', 'ignore', 'ask'],
            chosen='scan',
            reasoning='Security policy requires scanning unknown files',
            confidence=0.95
        )
    """
    
    def __init__(self, log_dir: str):
        """
        Initialize decision capture.
        
        Args:
            log_dir: Directory to store decision logs (JSONL files)
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory indexes for fast queries
        self._decisions: dict[str, DecisionNode] = {}  # decision_id -> node
        self._session_trees: dict[str, dict[str, DecisionNode]] = defaultdict(dict)  # session_id -> nodes
        self._agent_sessions: dict[str, set[str]] = defaultdict(set)  # agent_id -> session_ids
        self._result_index: dict[str, str] = {}  # result_id -> decision_id
        self._root_decisions: dict[str, str] = {}  # session_id -> root decision_id
        
        # Thread-safe locks
        self._write_lock = Lock()
        self._index_lock = Lock()
        
        # Load existing decisions from disk
        self._load_from_disk()
    
    def _get_log_path(self, session_id: str = None) -> Path:
        """Get path to JSONL log file"""
        if session_id:
            return self.log_dir / f"decisions_{session_id}.jsonl"
        return self.log_dir / "decisions_all.jsonl"
    
    def _load_from_disk(self):
        """Load existing decisions from disk into memory indexes"""
        for jsonl_path in self.log_dir.glob("decisions_*.jsonl"):
            try:
                with open(jsonl_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            node = DecisionNode.from_dict(data)
                            self._index_decision(node)
                        except json.JSONDecodeError as e:
                            logger.warning(f"Invalid JSON in {jsonl_path}: {e}")
            except Exception as e:
                logger.error(f"Failed to load decisions from {jsonl_path}: {e}")
    
    def _index_decision(self, node: DecisionNode):
        """Index a decision node for fast lookups"""
        self._decisions[node.decision_id] = node
        self._session_trees[node.session_id][node.decision_id] = node
        self._agent_sessions[node.agent_id].add(node.session_id)
        
        if node.result_id:
            self._result_index[node.result_id] = node.decision_id
        
        # Track root decisions (no parent)
        if node.parent_id is None:
            self._root_decisions[node.session_id] = node.decision_id
        
        # Update parent's children list
        if node.parent_id and node.parent_id in self._decisions:
            parent = self._decisions[node.parent_id]
            if node.decision_id not in parent.children:
                parent.children.append(node.decision_id)
    
    async def record_decision(
        self,
        agent_id: str,
        trigger: str,
        options: list[str],
        chosen: str,
        reasoning: str,
        confidence: float,
        session_id: str = None,
        parent_id: str = None,
        result_id: str = None
    ) -> str:
        """
        Record a decision point.
        
        Args:
            agent_id: Unique identifier for the agent making the decision
            trigger: What triggered this decision
            options: List of options that were considered
            chosen: The option that was chosen
            reasoning: Why this option was chosen
            confidence: Confidence level (0.0 to 1.0)
            session_id: Optional session ID (generated if not provided)
            parent_id: Optional parent decision ID for tree structure
            result_id: Optional ID linking this decision to a final result
        
        Returns:
            The decision_id of the recorded decision
        """
        # Generate IDs
        decision_id = str(uuid.uuid4())
        if session_id is None:
            session_id = str(uuid.uuid4())
        
        # Validate confidence
        if not 0.0 <= confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {confidence}")
        
        # Validate chosen is in options
        if chosen not in options:
            logger.warning(f"Chosen option '{chosen}' not in options list: {options}")
        
        # Create decision node
        node = DecisionNode(
            decision_id=decision_id,
            agent_id=agent_id,
            session_id=session_id,
            parent_id=parent_id,
            trigger=trigger,
            options_considered=options,
            chosen_option=chosen,
            reasoning=reasoning,
            confidence=confidence,
            result_id=result_id
        )
        
        # Persist and index
        await self._persist_decision(node)
        
        async with self._index_lock:
            self._index_decision(node)
        
        logger.debug(f"Recorded decision {decision_id} for agent {agent_id}")
        
        return decision_id
    
    async def _persist_decision(self, node: DecisionNode):
        """Persist decision to JSONL files (async-safe)"""
        data = node.to_dict()
        json_line = json.dumps(data)
        
        async with self._write_lock:
            try:
                # Write to session-specific file
                session_path = self._get_log_path(node.session_id)
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self._write_jsonl(session_path, json_line)
                )
                
                # Also write to all-decisions file
                all_path = self._get_log_path()
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self._write_jsonl(all_path, json_line)
                )
            except Exception as e:
                logger.error(f"Failed to persist decision {node.decision_id}: {e}")
                raise
    
    def _write_jsonl(self, path: Path, line: str):
        """Write a line to JSONL file (synchronous helper)"""
        with open(path, 'a') as f:
            f.write(line + '\n')
    
    def get_decision(self, decision_id: str) -> Optional[dict]:
        """
        Get a specific decision by ID.
        
        Args:
            decision_id: The decision's unique identifier
        
        Returns:
            Decision dictionary or None if not found
        """
        if decision_id in self._decisions:
            return self._decisions[decision_id].to_dict()
        return None
    
    def get_decision_tree(self, session_id: str) -> dict:
        """
        Return the full decision tree for a session.
        
        Args:
            session_id: The session identifier
        
        Returns:
            Dictionary containing the full decision tree with:
            - root: The root decision node
            - nodes: All decision nodes in the session
            - traversal: List of decision IDs in traversal order
        """
        if session_id not in self._session_trees:
            return {
                'session_id': session_id,
                'root': None,
                'nodes': {},
                'traversal': []
            }
        
        nodes = self._session_trees[session_id]
        root_id = self._root_decisions.get(session_id)
        
        # Build traversal order (depth-first from root)
        traversal = self._build_traversal(root_id) if root_id else list(nodes.keys())
        
        return {
            'session_id': session_id,
            'root': root_id,
            'nodes': {nid: node.to_dict() for nid, node in nodes.items()},
            'traversal': traversal
        }
    
    def _build_traversal(self, decision_id: str, visited: set = None) -> list[str]:
        """Build depth-first traversal order of decisions"""
        if visited is None:
            visited = set()
        
        if decision_id in visited:
            return []
        
        visited.add(decision_id)
        
        if decision_id not in self._decisions:
            return []
        
        node = self._decisions[decision_id]
        traversal = [decision_id]
        
        for child_id in node.children:
            traversal.extend(self._build_traversal(child_id, visited))
        
        return traversal
    
    def get_session_for_result(self, result_id: str) -> Optional[str]:
        """
        Find the session ID associated with a result.
        
        Args:
            result_id: The result identifier
        
        Returns:
            Session ID or None if not found
        """
        if result_id in self._result_index:
            decision_id = self._result_index[result_id]
            if decision_id in self._decisions:
                return self._decisions[decision_id].session_id
        return None
    
    def explain_result(self, result_id: str) -> list[dict]:
        """
        Trace why a result was reached.
        
        Walks backward from the decision linked to the result,
        following parent relationships to build the full chain
        of reasoning.
        
        Args:
            result_id: The result identifier to explain
        
        Returns:
            List of decision dictionaries in reverse chronological order
            (most recent decision first, back to root)
        """
        # Find the decision linked to this result
        if result_id not in self._result_index:
            # Try to find by scanning decisions
            for decision_id, node in self._decisions.items():
                if node.result_id == result_id:
                    self._result_index[result_id] = decision_id
                    break
            else:
                return []
        
        decision_id = self._result_index.get(result_id)
        if not decision_id:
            return []
        
        # Build chain of decisions
        chain = []
        current_id = decision_id
        visited = set()
        
        while current_id and current_id not in visited:
            visited.add(current_id)
            
            if current_id not in self._decisions:
                break
            
            node = self._decisions[current_id]
            chain.append(node.to_dict())
            
            current_id = node.parent_id
        
        return chain
    
    def explain_decision(self, decision_id: str) -> list[dict]:
        """
        Explain a specific decision by tracing its ancestry.
        
        Similar to explain_result but starts from a decision ID
        instead of a result ID.
        
        Args:
            decision_id: The decision to explain
        
        Returns:
            List of decision dictionaries from root to this decision
        """
        if decision_id not in self._decisions:
            return []
        
        # Build chain from root to this decision
        chain = []
        current_id = decision_id
        visited = set()
        
        # First, collect ancestors (in reverse order)
        ancestors = []
        while current_id and current_id not in visited:
            visited.add(current_id)
            
            if current_id not in self._decisions:
                break
            
            node = self._decisions[current_id]
            ancestors.append(node.to_dict())
            
            current_id = node.parent_id
        
        # Reverse to get root-first order
        ancestors.reverse()
        return ancestors
    
    def get_agent_sessions(self, agent_id: str) -> list[dict]:
        """
        Get all sessions for an agent.
        
        Args:
            agent_id: The agent identifier
        
        Returns:
            List of session summaries with decision counts
        """
        if agent_id not in self._agent_sessions:
            return []
        
        sessions = []
        for session_id in self._agent_sessions[agent_id]:
            nodes = self._session_trees.get(session_id, {})
            sessions.append({
                'session_id': session_id,
                'decision_count': len(nodes),
                'first_decision': min(
                    (n.timestamp for n in nodes.values()),
                    default=None
                ),
                'last_decision': max(
                    (n.timestamp for n in nodes.values()),
                    default=None
                )
            })
        
        return sessions
    
    def search_decisions(
        self,
        query: str,
        agent_id: str = None,
        session_id: str = None,
        min_confidence: float = None
    ) -> list[dict]:
        """
        Search decisions by various criteria.
        
        Args:
            query: Text to search in trigger, reasoning, or chosen_option
            agent_id: Filter by agent
            session_id: Filter by session
            min_confidence: Minimum confidence threshold
        
        Returns:
            List of matching decision dictionaries
        """
        results = []
        query_lower = query.lower() if query else None
        
        # Determine scope
        if session_id:
            nodes = self._session_trees.get(session_id, {}).values()
        elif agent_id:
            nodes = []
            for sid in self._agent_sessions.get(agent_id, set()):
                nodes.extend(self._session_trees.get(sid, {}).values())
        else:
            nodes = self._decisions.values()
        
        for node in nodes:
            # Apply confidence filter
            if min_confidence is not None and node.confidence < min_confidence:
                continue
            
            # Apply text search
            if query_lower:
                searchable = ' '.join([
                    node.trigger.lower(),
                    node.reasoning.lower(),
                    node.chosen_option.lower()
                ])
                if query_lower not in searchable:
                    continue
            
            results.append(node.to_dict())
        
        return results
    
    def get_statistics(self) -> dict:
        """
        Get overall statistics about recorded decisions.
        
        Returns:
            Dictionary with aggregate statistics
        """
        total_decisions = len(self._decisions)
        total_sessions = len(self._session_trees)
        total_agents = len(self._agent_sessions)
        
        decisions_per_session = [
            len(nodes) for nodes in self._session_trees.values()
        ]
        avg_decisions = (
            sum(decisions_per_session) / len(decisions_per_session)
            if decisions_per_session else 0
        )
        
        avg_confidence = (
            sum(n.confidence for n in self._decisions.values()) / total_decisions
            if total_decisions else 0
        )
        
        return {
            'total_decisions': total_decisions,
            'total_sessions': total_sessions,
            'total_agents': total_agents,
            'avg_decisions_per_session': avg_decisions,
            'avg_confidence': avg_confidence,
            'sessions': {
                'by_agent': {
                    aid: len(sids)
                    for aid, sids in self._agent_sessions.items()
                }
            }
        }
    
    async def link_result(self, decision_id: str, result_id: str):
        """
        Link a decision to a final result.
        
        Args:
            decision_id: The decision to link
            result_id: The result ID to link to
        """
        if decision_id not in self._decisions:
            raise ValueError(f"Decision {decision_id} not found")
        
        node = self._decisions[decision_id]
        node.result_id = result_id
        
        # Update index
        self._result_index[result_id] = decision_id
        
        # Re-persist
        await self._persist_decision(node)
    
    def prune_session(self, session_id: str) -> bool:
        """
        Remove a session's decisions from memory (keeps disk files).
        
        Args:
            session_id: Session to prune
        
        Returns:
            True if session was found and pruned
        """
        if session_id not in self._session_trees:
            return False
        
        # Remove from indexes
        for decision_id in list(self._session_trees[session_id].keys()):
            if decision_id in self._decisions:
                node = self._decisions[decision_id]
                # Remove from result index
                if node.result_id and node.result_id in self._result_index:
                    del self._result_index[node.result_id]
                del self._decisions[decision_id]
        
        # Remove agent session references
        for agent_id in list(self._agent_sessions.keys()):
            self._agent_sessions[agent_id].discard(session_id)
        
        # Remove session trees and root
        del self._session_trees[session_id]
        if session_id in self._root_decisions:
            del self._root_decisions[session_id]
        
        return True


# Singleton instance support
_decision_capture: Optional[DecisionCapture] = None


def get_decision_capture(log_dir: str = None) -> DecisionCapture:
    """
    Get or create singleton DecisionCapture instance.
    
    Args:
        log_dir: Directory for logs (only used on first call)
    
    Returns:
        DecisionCapture instance
    """
    global _decision_capture
    if _decision_capture is None:
        if log_dir is None:
            log_dir = os.environ.get('PICOTCLAW_LOG_DIR', '/var/log/picoclaw/decisions')
        _decision_capture = DecisionCapture(log_dir)
    return _decision_capture


async def record_decision(
    agent_id: str,
    trigger: str,
    options: list[str],
    chosen: str,
    reasoning: str,
    confidence: float,
    **kwargs
) -> str:
    """
    Convenience function to record a decision using the default capture.
    
    Args:
        agent_id: Agent making the decision
        trigger: What triggered the decision
        options: Options considered
        chosen: Option chosen
        reasoning: Why chosen
        confidence: Confidence level (0-1)
        **kwargs: Additional args passed to record_decision
    
    Returns:
        Decision ID
    """
    return await get_decision_capture().record_decision(
        agent_id=agent_id,
        trigger=trigger,
        options=options,
        chosen=chosen,
        reasoning=reasoning,
        confidence=confidence,
        **kwargs
    )