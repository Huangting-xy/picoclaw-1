"""
Swarm Detector - Multi-Agent Detection.

This module identifies agent swarms (coordinated multi-agent systems)
by analyzing IP patterns, timing correlations, and shared resources.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Self
import math


class SwarmType(Enum):
    """Types of agent swarms."""
    COORDINATED = "coordinated"  # Agents working together intentionally
    PARALLEL = "parallel"  # Agents running same task in parallel
    DORMANT_CELL = "dormant_cell"  # Inactive agents waiting for activation
    RESOURCE_SHARING = "resource_sharing"  # Agents sharing resources
    UNKNOWN = "unknown"


class DetectionMethod(Enum):
    """Methods used for swarm detection."""
    IP_CORRELATION = "ip_correlation"
    TIMING_CORRELATION = "timing_correlation"
    RESOURCE_SHARING = "resource_sharing"
    BEHAVIOR_PATTERN = "behavior_pattern"
    CAPABILITY_OVERLAP = "capability_overlap"


class SwarmError(Exception):
    """Base exception for swarm detector errors."""
    pass


@dataclass
class SwarmMember:
    """A member of a detected swarm."""
    agent_id: str
    join_time: float
    role: str = "member"  # member, leader, worker
    confidence: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "join_time": self.join_time,
            "role": self.role,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass
class DetectedSwarm:
    """A detected agent swarm."""
    swarm_id: str
    swarm_type: SwarmType
    detection_methods: list[DetectionMethod]
    members: list[SwarmMember]
    detected_at: float
    confidence: float
    source_ips: list[str] = field(default_factory=list)
    shared_resources: list[str] = field(default_factory=list)
    timing_correlation: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.members)

    def to_dict(self) -> dict[str, Any]:
        return {
            "swarm_id": self.swarm_id,
            "swarm_type": self.swarm_type.value,
            "detection_methods": [m.value for m in self.detection_methods],
            "members": [m.to_dict() for m in self.members],
            "detected_at": self.detected_at,
            "confidence": self.confidence,
            "source_ips": self.source_ips,
            "shared_resources": self.shared_resources,
            "timing_correlation": self.timing_correlation,
            "metadata": self.metadata,
            "size": self.size,
        }


@dataclass
class AgentObservation:
    """Observation data for an agent."""
    agent_id: str
    source_ip: str | None = None
    last_heartbeat: float = 0.0
    heartbeat_times: list[float] = field(default_factory=list)
    resources_accessed: set[str] = field(default_factory=set)
    capabilities: list[str] = field(default_factory=list)
    owner: str = ""
    platform: str = ""
    status: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "source_ip": self.source_ip,
            "last_heartbeat": self.last_heartbeat,
            "heartbeat_times": self.heartbeat_times,
            "resources_accessed": list(self.resources_accessed),
            "capabilities": self.capabilities,
            "owner": self.owner,
            "platform": self.platform,
            "status": self.status,
        }


class SwarmDetector:
    """
    Detects agent swarms through pattern analysis.

    Detection methods:
    - IP correlation: Multiple agents from same IP
    - Timing correlation: Coordinated heartbeat timing
    - Resource sharing: Agents accessing same resources
    - Behavior pattern: Similar activity patterns
    """

    # Minimum agents to consider a swarm
    MIN_SWARM_SIZE = 2
    # Maximum agents in a swarm analysis
    MAX_AGENTS = 1000
    # Timing correlation threshold (seconds)
    TIMING_THRESHOLD = 10.0
    # Minimum confidence to report swarm
    MIN_CONFIDENCE = 0.5

    def __init__(
        self,
        min_swarm_size: int = MIN_SWARM_SIZE,
        timing_threshold: float = TIMING_THRESHOLD,
        min_confidence: float = MIN_CONFIDENCE,
        history_window: float = 3600.0,  # 1 hour
    ):
        """
        Initialize swarm detector.

        Args:
            min_swarm_size: Minimum agents to be considered a swarm
            timing_threshold: Seconds window for timing correlation
            min_confidence: Minimum confidence threshold
            history_window: Time window to keep observation history
        """
        self._observations: dict[str, AgentObservation] = {}
        self._swarms: dict[str, DetectedSwarm] = {}
        self._swarm_membership: dict[str, str] = {}  # agent_id -> swarm_id

        self._min_swarm_size = min_swarm_size
        self._timing_threshold = timing_threshold
        self._min_confidence = min_confidence
        self._history_window = history_window

        self._lock = asyncio.Lock()

    async def observe(
        self,
        agent_id: str,
        source_ip: str | None = None,
        resources: list[str] | None = None,
        capabilities: list[str] | None = None,
        owner: str = "",
        platform: str = "",
        status: str = "unknown",
    ) -> None:
        """
        Record observation of agent activity.

        Args:
            agent_id: Agent identifier
            source_ip: Source IP address
            resources: Resources being accessed
            capabilities: Agent capabilities
            owner: Agent owner
            platform: Agent platform
            status: Agent status
        """
        async with self._lock:
            now = time.time()

            if agent_id not in self._observations:
                self._observations[agent_id] = AgentObservation(agent_id=agent_id)

            obs = self._observations[agent_id]
            obs.last_heartbeat = now
            obs.heartbeat_times.append(now)

            # Trim old heartbeats
            cutoff = now - self._history_window
            obs.heartbeat_times = [t for t in obs.heartbeat_times if t >= cutoff][-100:]

            if source_ip:
                obs.source_ip = source_ip
            if resources:
                obs.resources_accessed.update(resources)
            if capabilities:
                obs.capabilities = capabilities
            if owner:
                obs.owner = owner
            if platform:
                obs.platform = platform
            if status:
                obs.status = status

    async def detect_swarms(
        self,
        agents: list[dict[str, Any]] | None = None,
    ) -> list[DetectedSwarm]:
        """
        Find likely swarms by analyzing patterns.

        Args:
            agents: Optional list of agent data to analyze
                   If None, uses internal observations

        Returns:
            List of detected swarms
        """
        async with self._lock:
            # Use provided agents or internal observations
            if agents:
                await self._process_agent_list(agents)

            now = time.time()
            detected: list[DetectedSwarm] = []
            processed_ids: set[str] = set()

            # Group by IP
            ip_groups = self._group_by_ip()

            # Find timing-correlated groups
            timing_groups = self._find_timing_correlations()

            # Find resource-sharing groups
            resource_groups = self._find_resource_sharing()

            # Combine groups into potential swarms
            potential_swarms = self._combine_groups(
                ip_groups, timing_groups, resource_groups
            )

            # Convert to detected swarms
            for group in potential_swarms:
                # Skip if already processed
                if any(aid in processed_ids for aid in group):
                    continue

                # Get detection methods and confidence
                methods, confidence = self._calculate_detection_methods(
                    group, ip_groups, timing_groups, resource_groups
                )

                # Skip if below threshold
                if len(group) < self._min_swarm_size or confidence < self._min_confidence:
                    continue

                # Determine swarm type
                swarm_type = self._determine_swarm_type(group, methods)

                # Create swarm
                swarm_id = self._generate_swarm_id(group)
                members = [
                    SwarmMember(
                        agent_id=aid,
                        join_time=now,
                        role=self._determine_member_role(aid, group, methods),
                        confidence=confidence,
                    )
                    for aid in group
                ]

                swarm = DetectedSwarm(
                    swarm_id=swarm_id,
                    swarm_type=swarm_type,
                    detection_methods=methods,
                    members=members,
                    detected_at=now,
                    confidence=confidence,
                    source_ips=self._get_source_ips(group),
                    shared_resources=self._get_shared_resources(group),
                    timing_correlation=self._calculate_timing_correlation(group),
                )

                self._swarms[swarm_id] = swarm

                # Update membership
                for member in members:
                    self._swarm_membership[member.agent_id] = swarm_id

                processed_ids.update(group)
                detected.append(swarm)

            return detected

    def get_swarm_members(self, swarm_id: str) -> list[SwarmMember]:
        """
        Get agents in a swarm.

        Args:
            swarm_id: Swarm identifier

        Returns:
            List of swarm members

        Raises:
            KeyError: If swarm not found
        """
        if swarm_id not in self._swarms:
            raise KeyError(f"Swarm not found: {swarm_id}")
        return self._swarms[swarm_id].members

    def get_swarms(self) -> list[DetectedSwarm]:
        """
        List all detected swarms.

        Returns:
            List of all detected swarms
        """
        return list(self._swarms.values())

    def get_agent_swarm(self, agent_id: str) -> DetectedSwarm | None:
        """
        Get the swarm an agent belongs to.

        Args:
            agent_id: Agent identifier

        Returns:
            Swarm if agent belongs to one, None otherwise
        """
        swarm_id = self._swarm_membership.get(agent_id)
        if swarm_id:
            return self._swarms.get(swarm_id)
        return None

    def get_swarm_by_ip(self, ip: str) -> DetectedSwarm | None:
        """
        Get swarm by source IP.

        Args:
            ip: IP address

        Returns:
            Swarm if found, None otherwise
        """
        for swarm in self._swarms.values():
            if ip in swarm.source_ips:
                return swarm
        return None

    async def _process_agent_list(
        self,
        agents: list[dict[str, Any]],
    ) -> None:
        """Process a list of agent data."""
        for agent in agents:
            await self.observe(
                agent_id=agent.get("agent_id", ""),
                source_ip=agent.get("source_ip"),
                resources=agent.get("resources", []),
                capabilities=agent.get("capabilities", []),
                owner=agent.get("owner", ""),
                platform=agent.get("platform", ""),
                status=agent.get("status", "unknown"),
            )

    def _group_by_ip(self) -> dict[str, set[str]]:
        """Group agents by source IP."""
        groups: dict[str, set[str]] = defaultdict(set)
        for agent_id, obs in self._observations.items():
            if obs.source_ip:
                groups[obs.source_ip].add(agent_id)
        return dict(groups)

    def _find_timing_correlations(self) -> list[set[str]]:
        """Find groups with correlated timing."""
        if len(self._observations) < 2:
            return []

        # Get all heartbeat times
        agent_times: dict[str, list[float]] = {}
        for agent_id, obs in self._observations.items():
            if obs.heartbeat_times:
                agent_times[agent_id] = sorted(obs.heartbeat_times)

        if not agent_times:
            return []

        # Find correlated pairs
        groups: list[set[str]] = []
        processed: set[str] = set()

        for aid1, times1 in agent_times.items():
            if aid1 in processed:
                continue

            group: set[str] = {aid1}

            for aid2, times2 in agent_times.items():
                if aid2 == aid1 or aid2 in processed:
                    continue

                # Check timing correlation
                if self._are_times_correlated(times1, times2):
                    group.add(aid2)
                    processed.add(aid2)

            if len(group) >= self._min_swarm_size:
                groups.append(group)

            processed.add(aid1)

        return groups

    def _are_times_correlated(
        self,
        times1: list[float],
        times2: list[float],
    ) -> bool:
        """Check if two sets of times are correlated."""
        if not times1 or not times2:
            return False

        # Count times within threshold of each other
        matches = 0
        threshold = self._timing_threshold

        for t1 in times1[-20:]:  # Only check recent times
            for t2 in times2[-20:]:
                if abs(t1 - t2) <= threshold:
                    matches += 1
                    break

        # Need at least 2 matches in recent history
        min_matches = min(2, min(len(times1), len(times2)))
        return matches >= min_matches

    def _find_resource_sharing(self) -> list[set[str]]:
        """Find groups sharing resources."""
        # Build reverse index: resource -> agents
        resource_agents: dict[str, set[str]] = defaultdict(set)
        for agent_id, obs in self._observations.items():
            for resource in obs.resources_accessed:
                resource_agents[resource].add(agent_id)

        # Group by shared resources
        groups: list[set[str]] = []
        seen_groups: set[frozenset] = set()

        for resource, agents in resource_agents.items():
            if len(agents) >= self._min_swarm_size:
                group_key = frozenset(agents)
                if group_key not in seen_groups:
                    groups.append(set(agents))
                    seen_groups.add(group_key)

        return groups

    def _combine_groups(
        self,
        ip_groups: dict[str, set[str]],
        timing_groups: list[set[str]],
        resource_groups: list[set[str]],
    ) -> list[set[str]]:
        """Combine groups from different detection methods."""
        all_groups: list[set[str]] = []
        seen_agents: set[str] = set()

        # Start with IP groups (highest confidence)
        for agents in ip_groups.values():
            if len(agents) >= self._min_swarm_size:
                if not agents.isdisjoint(seen_agents):
                    # Merge with existing group
                    for i, g in enumerate(all_groups):
                        if not agents.isdisjoint(g):
                            all_groups[i] = g.union(agents)
                            break
                else:
                    all_groups.append(agents.copy())
                seen_agents.update(agents)

        # Add timing groups
        for agents in timing_groups:
            if not agents.isdisjoint(seen_agents):
                # Merge with existing group
                for i, g in enumerate(all_groups):
                    if not agents.isdisjoint(g):
                        all_groups[i] = g.union(agents)
                        break
            else:
                all_groups.append(agents.copy())
            seen_agents.update(agents)

        # Add resource groups
        for agents in resource_groups:
            if not agents.isdisjoint(seen_agents):
                for i, g in enumerate(all_groups):
                    if not agents.isdisjoint(g):
                        all_groups[i] = g.union(agents)
                        break
            else:
                all_groups.append(agents.copy())

        return all_groups

    def _calculate_detection_methods(
        self,
        group: set[str],
        ip_groups: dict[str, set[str]],
        timing_groups: list[set[str]],
        resource_groups: list[set[str]],
    ) -> tuple[list[DetectionMethod], float]:
        """Calculate detection methods and confidence for a group."""
        methods: list[DetectionMethod] = []
        confidence_scores: list[float] = []

        # Check IP correlation
        for agents in ip_groups.values():
            if agents == group or agents.issubset(group):
                methods.append(DetectionMethod.IP_CORRELATION)
                confidence_scores.append(0.9)
                break

        # Check timing correlation
        for agents in timing_groups:
            if agents == group or agents.issubset(group):
                methods.append(DetectionMethod.TIMING_CORRELATION)
                confidence_scores.append(0.7)
                break

        # Check resource sharing
        for agents in resource_groups:
            if agents == group or agents.issubset(group):
                methods.append(DetectionMethod.RESOURCE_SHARING)
                confidence_scores.append(0.8)
                break

        # Check capability overlap
        capabilities_count: dict[str, int] = defaultdict(int)
        for agent_id in group:
            if agent_id in self._observations:
                for cap in self._observations[agent_id].capabilities:
                    capabilities_count[cap] += 1

        if capabilities_count:
            max_overlap = max(capabilities_count.values())
            if max_overlap >= len(group) * 0.5:  # 50% overlap
                methods.append(DetectionMethod.CAPABILITY_OVERLAP)
                confidence_scores.append(0.6)

        # Calculate overall confidence
        if confidence_scores:
            confidence = sum(confidence_scores) / len(confidence_scores)
            # Boost confidence for multiple methods
            if len(methods) > 1:
                confidence = min(1.0, confidence * (1 + 0.1 * (len(methods) - 1)))
        else:
            confidence = 0.0

        return methods, confidence

    def _determine_swarm_type(
        self,
        group: set[str],
        methods: list[DetectionMethod],
    ) -> SwarmType:
        """Determine the type of swarm."""
        # Check for coordinated activity
        if DetectionMethod.TIMING_CORRELATION in methods:
            return SwarmType.COORDINATED

        # Check for resource sharing
        if DetectionMethod.RESOURCE_SHARING in methods:
            return SwarmType.RESOURCE_SHARING

        # Check for same-origin (IP correlation)
        if DetectionMethod.IP_CORRELATION in methods:
            # Could be parallel execution
            return SwarmType.PARALLEL

        return SwarmType.UNKNOWN

    def _determine_member_role(
        self,
        agent_id: str,
        group: set[str],
        methods: list[DetectionMethod],
    ) -> str:
        """Determine an agent's role in the swarm."""
        # Check if this agent has more resources than others
        if agent_id not in self._observations:
            return "member"

        obs = self._observations[agent_id]
        avg_resources = sum(
            len(self._observations[aid].resources_accessed)
            for aid in group if aid in self._observations
        ) / len(group)

        if len(obs.resources_accessed) > avg_resources * 1.5:
            return "leader"

        return "member"

    def _generate_swarm_id(self, group: set[str]) -> str:
        """Generate a unique swarm ID."""
        data = "".join(sorted(group)) + str(time.time())
        return "swarm_" + hashlib.md5(data.encode()).hexdigest()[:12]

    def _get_source_ips(self, group: set[str]) -> list[str]:
        """Get unique source IPs for a group."""
        ips: set[str] = set()
        for agent_id in group:
            if agent_id in self._observations:
                ip = self._observations[agent_id].source_ip
                if ip:
                    ips.add(ip)
        return list(ips)

    def _get_shared_resources(self, group: set[str]) -> list[str]:
        """Get resources shared by group members."""
        if not group:
            return []

        resource_count: dict[str, int] = defaultdict(int)
        for agent_id in group:
            if agent_id in self._observations:
                for resource in self._observations[agent_id].resources_accessed:
                    resource_count[resource] += 1

        # Resources used by more than one member
        return [r for r, c in resource_count.items() if c > 1]

    def _calculate_timing_correlation(self, group: set[str]) -> float:
        """Calculate timing correlation score for a group."""
        if len(group) < 2:
            return 0.0

        # Get all heartbeat times
        all_times: dict[str, list[float]] = {}
        for agent_id in group:
            if agent_id in self._observations:
                all_times[agent_id] = self._observations[agent_id].heartbeat_times

        if len(all_times) < 2:
            return 0.0

        # Calculate pairwise correlations
        correlations: list[float] = []
        agents = list(all_times.keys())

        for i in range(len(agents)):
            for j in range(i + 1, len(agents)):
                times1 = all_times[agents[i]][-20:]
                times2 = all_times[agents[j]][-20:]

                if times1 and times2:
                    # Simple correlation: count times within threshold
                    matches = sum(
                        1 for t1 in times1
                        if any(abs(t1 - t2) <= self._timing_threshold for t2 in times2)
                    )
                    corr = matches / max(len(times1), len(times2))
                    correlations.append(corr)

        if not correlations:
            return 0.0

        return sum(correlations) / len(correlations)

    def clear_stale_observations(self, max_age: float = 3600.0) -> int:
        """
        Clear stale observations.

        Args:
            max_age: Maximum age in seconds

        Returns:
            Number of cleared observations
        """
        now = time.time()
        to_remove = [
            agent_id
            for agent_id, obs in self._observations.items()
            if (now - obs.last_heartbeat) > max_age
        ]

        for agent_id in to_remove:
            del self._observations[agent_id]
            # Also remove from swarm membership
            if agent_id in self._swarm_membership:
                swarm_id = self._swarm_membership.pop(agent_id)
                if swarm_id in self._swarms:
                    # Remove member from swarm
                    self._swarms[swarm_id].members = [
                        m for m in self._swarms[swarm_id].members
                        if m.agent_id != agent_id
                    ]

        return len(to_remove)

    def get_statistics(self) -> dict[str, Any]:
        """Get detection statistics."""
        now = time.time()

        # Count by type
        type_counts: dict[str, int] = defaultdict(int)
        for swarm in self._swarms.values():
            type_counts[swarm.swarm_type.value] += 1

        # Calculate average swarm size
        if self._swarms:
            avg_size = sum(s.size for s in self._swarms.values()) / len(self._swarms)
        else:
            avg_size = 0

        return {
            "total_observations": len(self._observations),
            "total_swarms": len(self._swarms),
            "swarms_by_type": dict(type_counts),
            "average_swarm_size": avg_size,
            "agents_in_swarms": len(self._swarm_membership),
            "detection_methods_used": list(set(
                m.value for s in self._swarms.values() for m in s.detection_methods
            )),
        }