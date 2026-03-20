"""
Policy Engine for Picoclaw Governance Module.

This module provides policy-based access control for agents,
allowing fine-grained control over actions and resources.
"""

from __future__ import annotations

import re
import json
import fnmatch
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Callable
import asyncio
from abc import ABC, abstractmethod
from threading import RLock


class Effect(str, Enum):
    """Policy effect type."""
    ALLOW = "allow"
    DENY = "deny"
    

class PolicyPriority(int, Enum):
    """Policy priority levels."""
    OVERRIDE = 100  # Always evaluated first, cannot be overridden
    ADMIN = 75
    HIGH = 50
    NORMAL = 25
    LOW = 10
    DEFAULT = 0


class ResourceType(str, Enum):
    """Resource type identifiers."""
    FILE = "file"
    DIRECTORY = "directory"
    NETWORK = "network"
    PROCESS = "process"
    TOOL = "tool"
    API = "api"
    DATA = "data"
    SYSTEM = "system"


@dataclass
class PolicyRule:
    """A single rule within a policy."""
    field: str  # e.g., "action", "resource", "agent_id"
    operator: str  # "equals", "not_equals", "contains", "matches", "in", "not_in"
    value: Any
    
    def evaluate(self, context: dict[str, Any]) -> bool:
        """Evaluate rule against context."""
        actual = context.get(self.field)
        expected = self.value
        
        if self.operator == "equals":
            return actual == expected
        elif self.operator == "not_equals":
            return actual != expected
        elif self.operator == "contains":
            return actual is not None and expected in actual
        elif self.operator == "not_contains":
            return actual is not None and expected not in actual
        elif self.operator == "matches":
            return actual is not None and bool(re.match(expected, str(actual)))
        elif self.operator == "in":
            return actual in expected
        elif self.operator == "not_in":
            return actual not in expected
        elif self.operator == "starts_with":
            return actual is not None and str(actual).startswith(expected)
        elif self.operator == "ends_with":
            return actual is not None and str(actual).endswith(expected)
        elif self.operator == "greater_than":
            return actual is not None and actual > expected
        elif self.operator == "less_than":
            return actual is not None and actual < expected
        elif self.operator == "exists":
            return actual is not None
        elif self.operator == "not_exists":
            return actual is None
        else:
            return False
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize rule to dictionary."""
        return {
            "field": self.field,
            "operator": self.operator,
            "value": self.value,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyRule":
        """Deserialize rule from dictionary."""
        return cls(
            field=data["field"],
            operator=data["operator"],
            value=data["value"],
        )


@dataclass
class PolicyCondition:
    """A condition that must be met for policy to apply."""
    type: str  # "all", "any", "none"
    rules: list[PolicyRule]
    
    def evaluate(self, context: dict[str, Any]) -> bool:
        """Evaluate condition against context."""
        if not self.rules:
            return True
        
        results = [rule.evaluate(context) for rule in self.rules]
        
        if self.type == "all":
            return all(results)
        elif self.type == "any":
            return any(results)
        elif self.type == "none":
            return not any(results)
        else:
            return False
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize condition to dictionary."""
        return {
            "type": self.type,
            "rules": [r.to_dict() for r in self.rules],
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyCondition":
        """Deserialize condition from dictionary."""
        return cls(
            type=data["type"],
            rules=[PolicyRule.from_dict(r) for r in data.get("rules", [])],
        )


@dataclass
class Policy:
    """
    A security policy definition.
    
    Policies define rules for allowing or denying actions on resources.
    """
    name: str
    rules: list[PolicyRule] = field(default_factory=list)
    effect: Effect = Effect.DENY
    priority: int = PolicyPriority.NORMAL
    description: str = ""
    conditions: list[PolicyCondition] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def evaluate(self, context: dict[str, Any]) -> bool:
        """
        Evaluate if policy applies to context.
        
        Returns True if policy matches (applies), False otherwise.
        """
        if not self.enabled:
            return False
        
        # Check all conditions
        for condition in self.conditions:
            if not condition.evaluate(context):
                return False
        
        # Check all rules (AND logic)
        for rule in self.rules:
            if not rule.evaluate(context):
                return False
        
        return True
    
    def get_effect_for_context(self, context: dict[str, Any]) -> Optional[Effect]:
        """
        Get the effect if policy applies to context.
        
        Returns the effect if policy matches, None otherwise.
        """
        if self.evaluate(context):
            return self.effect
        return None
    
    def add_rule(self, rule: PolicyRule) -> None:
        """Add a rule to the policy."""
        self.rules.append(rule)
        self.updated_at = datetime.utcnow()
    
    def remove_rule(self, index: int) -> bool:
        """Remove a rule by index."""
        if 0 <= index < len(self.rules):
            self.rules.pop(index)
            self.updated_at = datetime.utcnow()
            return True
        return False
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize policy to dictionary."""
        return {
            "name": self.name,
            "rules": [r.to_dict() for r in self.rules],
            "effect": self.effect.value,
            "priority": self.priority,
            "description": self.description,
            "conditions": [c.to_dict() for c in self.conditions],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "enabled": self.enabled,
            "tags": self.tags,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        """Deserialize policy from dictionary."""
        return cls(
            name=data["name"],
            rules=[PolicyRule.from_dict(r) for r in data.get("rules", [])],
            effect=Effect(data.get("effect", "deny")),
            priority=data.get("priority", PolicyPriority.NORMAL),
            description=data.get("description", ""),
            conditions=[PolicyCondition.from_dict(c) for c in data.get("conditions", [])],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            created_by=data.get("created_by"),
            enabled=data.get("enabled", True),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""
    allowed: bool
    effect: Effect
    matched_policies: list[str]
    denied_by: list[str]
    explanations: list[str]
    context: dict[str, Any]
    evaluated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize decision to dictionary."""
        return {
            "allowed": self.allowed,
            "effect": self.effect.value,
            "matched_policies": self.matched_policies,
            "denied_by": self.denied_by,
            "explanations": self.explanations,
            "context": self.context,
            "evaluated_at": self.evaluated_at.isoformat(),
        }


class PolicyEngine:
    """
    Policy evaluation engine.
    
    Manages policies and evaluates access decisions for agent actions.
    """
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize the policy engine.
        
        Args:
            storage_path: Path to store policy data
        """
        self.storage_path = storage_path or Path.home() / ".picoclaw" / "governance" / "policies"
        self._policies: dict[str, Policy] = {}
        self._lock = RLock()
        self._initialized = False
        
        # Custom evaluators
        self._custom_evaluators: dict[str, Callable] = {}
    
    async def initialize(self) -> None:
        """Initialize the policy engine and load existing policies."""
        with self._lock:
            if self._initialized:
                return
            
            self.storage_path.mkdir(parents=True, exist_ok=True)
            await self._load_policies()
            
            # Load predefined policies
            self._load_predefined_policies()
            
            self._initialized = True
    
    async def _load_policies(self) -> None:
        """Load policies from storage."""
        policies_file = self.storage_path / "policies.jsonl"
        if not policies_file.exists():
            return
        
        loop = asyncio.get_event_loop()
        content = await loop.run_in_executor(None, policies_file.read_text)
        
        for line in content.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                policy = Policy.from_dict(data)
                self._policies[policy.name] = policy
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"Warning: Failed to load policy: {e}")
    
    async def _save_policies(self) -> None:
        """Save policies to storage."""
        policies_file = self.storage_path / "policies.jsonl"
        
        lines = []
        for policy in sorted(self._policies.values(), key=lambda p: -p.priority):
            lines.append(json.dumps(policy.to_dict()))
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            policies_file.write_text,
            "\n".join(lines) + "\n"
        )
    
    def _load_predefined_policies(self) -> None:
        """Load predefined security policies."""
        # File access limits
        file_access_policy = Policy(
            name="file_access_limits",
            effect=Effect.DENY,
            priority=PolicyPriority.HIGH,
            description="Restrict access to sensitive files and directories",
            rules=[
                PolicyRule("resource", "matches", r".*/\.ssh/.*"),
                PolicyRule("resource", "matches", r".*/\.gnupg/.*"),
                PolicyRule("resource", "matches", r".*/\.(?:bash_history|ssh_history).*"),
                PolicyRule("resource", "matches", r".*\.pem$"),
                PolicyRule("resource", "matches", r".*\.key$"),
            ],
            tags=["security", "file", "sensitive"],
        )
        
        # Network restrictions
        network_policy = Policy(
            name="network_restrictions",
            effect=Effect.DENY,
            priority=PolicyPriority.HIGH,
            description="Restrict network access to sensitive endpoints",
            rules=[
                PolicyRule("action", "equals", "network:connect"),
            ],
            conditions=[
                PolicyCondition(
                    type="any",
                    rules=[
                        PolicyRule("resource", "matches", r".*\.internal\..*"),
                        PolicyRule("resource", "matches", r"^https?://localhost.*"),
                        PolicyRule("resource", "matches", r"^https?://192\.168\..*"),
                        PolicyRule("resource", "matches", r"^https?://10\..*"),
                        PolicyRule("resource", "matches", r"^https?://172\.(1[6-9]|2[0-9]|3[0-1])\..*"),
                    ]
                )
            ],
            tags=["security", "network", "private"],
        )
        
        # Tool restrictions
        tool_policy = Policy(
            name="tool_restrictions",
            effect=Effect.DENY,
            priority=PolicyPriority.HIGH,
            description="Restrict access to dangerous tools",
            rules=[
                PolicyRule("action", "in", [
                    "exec:elevated",
                    "shell:root",
                    "system:modify",
                ]),
            ],
            tags=["security", "tool", "dangerous"],
        )
        
        # Default deny
        default_deny = Policy(
            name="default_deny",
            effect=Effect.DENY,
            priority=PolicyPriority.DEFAULT,
            description="Default deny policy - explicit allow required",
            rules=[
                PolicyRule("action", "exists", True),
            ],
            enabled=False,  # Disabled by default
        )
        
        # Admin override
        admin_override = Policy(
            name="admin_override",
            effect=Effect.ALLOW,
            priority=PolicyPriority.OVERRIDE,
            description="Allow admins to override other policies",
            conditions=[
                PolicyCondition(
                    type="all",
                    rules=[
                        PolicyRule("agent_capabilities", "contains", "admin"),
                    ]
                )
            ],
            tags=["admin", "override"],
        )
        
        # Add predefined policies
        for policy in [file_access_policy, network_policy, tool_policy, default_deny, admin_override]:
            if policy.name not in self._policies:
                self._policies[policy.name] = policy
    
    def add_policy(self, policy: Policy) -> None:
        """
        Add a security policy.
        
        Args:
            policy: Policy to add
        
        Raises:
            ValueError: If policy with same name exists
        """
        with self._lock:
            if policy.name in self._policies:
                raise ValueError(f"Policy {policy.name} already exists")
            self._policies[policy.name] = policy
    
    async def add_policy_async(self, policy: Policy) -> None:
        """Add a policy and persist."""
        self.add_policy(policy)
        await self._save_policies()
    
    def remove_policy(self, name: str) -> bool:
        """
        Remove a policy by name.
        
        Args:
            name: Policy name to remove
        
        Returns:
            True if removed, False if not found
        """
        with self._lock:
            if name in self._policies:
                del self._policies[name]
                return True
            return False
    
    async def remove_policy_async(self, name: str) -> bool:
        """Remove a policy and persist."""
        result = self.remove_policy(name)
        if result:
            await self._save_policies()
        return result
    
    def get_policy(self, name: str) -> Optional[Policy]:
        """Get policy by name."""
        return self._policies.get(name)
    
    def list_policies(
        self,
        effect: Optional[Effect] = None,
        tag: Optional[str] = None,
        enabled_only: bool = True,
    ) -> list[Policy]:
        """
        List policies with optional filtering.
        
        Args:
            effect: Filter by effect type
            tag: Filter by tag
            enabled_only: Only return enabled policies
        
        Returns:
            List of matching policies
        """
        policies = list(self._policies.values())
        
        if enabled_only:
            policies = [p for p in policies if p.enabled]
        
        if effect:
            policies = [p for p in policies if p.effect == effect]
        
        if tag:
            policies = [p for p in policies if tag in p.tags]
        
        return sorted(policies, key=lambda p: -p.priority)
    
    def evaluate(
        self,
        agent_id: str,
        action: str,
        resource: str,
        context: Optional[dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Evaluate if action is allowed.
        
        Policies are evaluated in priority order (highest first).
        Deny policies take precedence over allow policies at the same priority.
        
        Args:
            agent_id: Agent performing the action
            action: Action being performed
            resource: Resource being accessed
            context: Additional context for evaluation
        
        Returns:
            PolicyDecision with result and explanation
        """
        # Build evaluation context
        eval_context = {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            **(context or {}),
        }
        
        matched_policies: list[str] = []
        denied_by: list[str] = []
        explanations: list[str] = []
        
        # Sort by priority (highest first), then effect (deny before allow)
        policies = sorted(
            self._policies.values(),
            key=lambda p: (-p.priority, 0 if p.effect == Effect.DENY else 1)
        )
        
        final_effect: Optional[Effect] = None
        
        for policy in policies:
            if not policy.enabled:
                continue
            
            effect = policy.get_effect_for_context(eval_context)
            if effect is None:
                continue
            
            matched_policies.append(policy.name)
            explanation = f"Policy '{policy.name}' ({effect.value}) matched"
            explanations.append(explanation)
            
            if effect == Effect.DENY:
                denied_by.append(policy.name)
                final_effect = Effect.DENY
                break  # Deny immediately
            elif final_effect is None:
                final_effect = Effect.ALLOW
        
        # Default to deny if no policy matched
        if final_effect is None:
            final_effect = Effect.DENY
            explanations.append("No matching policy - default deny")
        
        return PolicyDecision(
            allowed=final_effect == Effect.ALLOW,
            effect=final_effect,
            matched_policies=matched_policies,
            denied_by=denied_by,
            explanations=explanations,
            context=eval_context,
        )
    
    def explain(
        self,
        agent_id: str,
        action: str,
        resource: str,
        context: Optional[dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Explain WHY a decision was made.
        
        Provides detailed explanation of policy evaluation.
        
        Args:
            agent_id: Agent performing the action
            action: Action being performed
            resource: Resource being accessed
            context: Additional context
        
        Returns:
            PolicyDecision with detailed explanations
        """
        # Run evaluation
        decision = self.evaluate(agent_id, action, resource, context)
        
        # Add detailed explanations
        eval_context = {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            **(context or {}),
        }
        
        detailed = [f"Evaluating action '{action}' by agent '{agent_id}' on '{resource}'"]
        
        # Explain each evaluated policy
        policies = sorted(
            self._policies.values(),
            key=lambda p: (-p.priority, 0 if p.effect == Effect.DENY else 1)
        )
        
        for policy in policies:
            if not policy.enabled:
                continue
            
            # Check conditions
            if policy.conditions:
                cond_results = []
                for cond in policy.conditions:
                    result = cond.evaluate(eval_context)
                    cond_results.append(f"condition({cond.type}): {result}")
                
                if not all(cond.evaluate(eval_context) for cond in policy.conditions):
                    detailed.append(f"  Policy '{policy.name}' - conditions not met: {', '.join(cond_results)}")
                    continue
            
            # Check rules
            rule_results = []
            matched = True
            for rule in policy.rules:
                result = rule.evaluate(eval_context)
                rule_results.append(f"{rule.field} {rule.operator} {rule.value}: {result}")
                if not result:
                    matched = False
            
            if matched:
                detailed.append(f"  Policy '{policy.name}' [{policy.effect.value}] - MATCHED")
                detailed.extend([f"    - {r}" for r in rule_results])
            else:
                detailed.append(f"  Policy '{policy.name}' - not matched")
        
        decision.explanations = detailed + decision.explanations
        return decision
    
    def register_evaluator(self, name: str, evaluator: Callable) -> None:
        """Register a custom evaluator function."""
        self._custom_evaluators[name] = evaluator
    
    def create_file_policy(
        self,
        name: str,
        patterns: list[str],
        effect: Effect = Effect.DENY,
        priority: int = PolicyPriority.NORMAL,
    ) -> Policy:
        """
        Create a file access policy.
        
        Args:
            name: Policy name
            patterns: File patterns to match
            effect: Allow or deny
            priority: Policy priority
        
        Returns:
            Created policy
        """
        rules = [PolicyRule("resource", "matches", p) for p in patterns]
        policy = Policy(
            name=name,
            rules=rules,
            effect=effect,
            priority=priority,
            description=f"File access policy for patterns: {patterns}",
            tags=["file", "generated"],
        )
        return policy
    
    def create_network_policy(
        self,
        name: str,
        patterns: list[str],
        effect: Effect = Effect.DENY,
        priority: int = PolicyPriority.NORMAL,
    ) -> Policy:
        """
        Create a network access policy.
        
        Args:
            name: Policy name
            patterns: URL patterns to match
            effect: Allow or deny
            priority: Policy priority
        
        Returns:
            Created policy
        """
        rules = [PolicyRule("resource", "matches", p) for p in patterns]
        policy = Policy(
            name=name,
            rules=rules,
            effect=effect,
            priority=priority,
            description=f"Network access policy for patterns: {patterns}",
            tags=["network", "generated"],
        )
        return policy
    
    def create_tool_policy(
        self,
        name: str,
        tools: list[str],
        effect: Effect = Effect.DENY,
        priority: int = PolicyPriority.HIGH,
    ) -> Policy:
        """
        Create a tool restriction policy.
        
        Args:
            name: Policy name
            tools: Tool names to restrict
            effect: Allow or deny
            priority: Policy priority
        
        Returns:
            Created policy
        """
        rules = [PolicyRule("action", "in", tools)]
        policy = Policy(
            name=name,
            rules=rules,
            effect=effect,
            priority=priority,
            description=f"Tool restriction policy for: {tools}",
            tags=["tool", "generated"],
        )
        return policy


# Convenience functions

_engine: Optional[PolicyEngine] = None


def get_engine() -> PolicyEngine:
    """Get or create the default policy engine."""
    global _engine
    if _engine is None:
        _engine = PolicyEngine()
    return _engine


def add_policy(policy: Policy) -> None:
    """Add a policy to the default engine."""
    get_engine().add_policy(policy)


def remove_policy(name: str) -> bool:
    """Remove a policy from the default engine."""
    return get_engine().remove_policy(name)


def evaluate(agent_id: str, action: str, resource: str, context: Optional[dict[str, Any]] = None) -> PolicyDecision:
    """Evaluate action using default engine."""
    return get_engine().evaluate(agent_id, action, resource, context)


def explain(agent_id: str, action: str, resource: str, context: Optional[dict[str, Any]] = None) -> PolicyDecision:
    """Explain decision using default engine."""
    return get_engine().explain(agent_id, action, resource, context)


__all__ = [
    "Effect",
    "PolicyPriority",
    "ResourceType",
    "PolicyRule",
    "PolicyCondition",
    "Policy",
    "PolicyDecision",
    "PolicyEngine",
    "get_engine",
    "add_policy",
    "remove_policy",
    "evaluate",
    "explain",
]