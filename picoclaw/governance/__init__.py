"""
Picoclaw Governance & Identity Module.

This module provides comprehensive governance capabilities for autonomous
agents including identity management, policy enforcement, audit logging,
consent management, and resource quotas.

Example usage:

    from picoclaw.governance import (
        IdentityManager,
        PolicyEngine,
        AuditLog,
        ConsentManager,
        QuotaManager,
    )
    
    # Initialize managers
    identity_manager = IdentityManager()
    policy_engine = PolicyEngine()
    audit_log = AuditLog()
    consent_manager = ConsentManager()
    quota_manager = QuotaManager()
    
    # Register an agent identity
    identity, private_key = await identity_manager.register_identity(
        agent_id="agent_001",
        capabilities=[Capability.FILE_READ, Capability.NETWORK_HTTP],
    )
    
    # Evaluate a policy decision
    decision = policy_engine.evaluate(
        agent_id="agent_001",
        action="file:read",
        resource="/etc/passwd",
    )
    
    # Grant user consent
    grant = await consent_manager.grant_consent(
        user_id="user_123",
        agent_id="agent_001",
        scope=ConsentScope.READ,
        duration=timedelta(days=7),
    )
    
    # Set resource quotas
    quota_manager.set_quota(
        agent_id="agent_001",
        resource=ResourceType.API_CALLS,
        limit=10000,
    )
    
    # Log an action
    await audit_log.log_action(
        agent_id="agent_001",
        action="file:read",
        resource="/data/example.txt",
        outcome=AuditOutcome.SUCCESS,
    )
"""

from .identity import (
    # Enums
    Capability,
    IdentityStatus,
    
    # Classes
    CapabilityAttestation,
    AgentIdentity,
    SignatureVerification,
    IdentityManager,
    
    # Functions
    list_identities,
    get_identity,
    get_identity_by_public_key,
    register_identity,
    verify_identity,
    revoke_identity,
    get_default_manager,
)

from .policy import (
    # Enums
    Effect,
    PolicyPriority,
    ResourceType,
    
    # Classes
    PolicyRule,
    PolicyCondition,
    Policy,
    PolicyDecision,
    PolicyEngine,
    
    # Functions
    get_engine,
    add_policy,
    remove_policy,
    evaluate,
    explain,
)

from .audit import (
    # Enums
    AuditOutcome,
    AuditSeverity,
    
    # Classes
    AuditEntry,
    AuditLogWriter,
    AuditLog,
    
    # Functions
    get_audit_log,
    log_action,
    query_by_agent,
    query_by_action,
    query_suspicious,
    export_audit,
)

from .consent import (
    # Enums
    ConsentScope,
    ConsentStatus,
    
    # Classes
    ConsentGrant,
    ConsentRequest,
    ConsentManager,
    
    # Functions
    get_manager as get_consent_manager,
    grant_consent,
    revoke_consent,
    check_consent,
    list_consents,
)

from .quota import (
    # Enums
    ResourceType as QuotaResourceType,
    QuotaPeriod,
    
    # Classes
    QuotaLimit,
    QuotaUsage,
    QuotaStatus,
    QuotaManager,
    
    # Functions
    get_manager as get_quota_manager,
    set_quota,
    check_quota,
    record_usage,
    get_usage,
    get_quota_status,
)


# Convenience initialization function
async def initialize_governance(
    storage_path: str | None = None,
    load_existing: bool = True,
) -> dict:
    """
    Initialize all governance components.
    
    Args:
        storage_path: Base path for storage (None uses default)
        load_existing: Whether to load existing data
    
    Returns:
        Dictionary of initialized managers
    """
    from pathlib import Path
    
    base_path = Path(storage_path) if storage_path else None
    
    identity_mgr = IdentityManager(
        storage_path=base_path / "identities" if base_path else None
    )
    policy_eng = PolicyEngine(
        storage_path=base_path / "policies" if base_path else None
    )
    audit = AuditLog(
        storage_path=base_path / "audit" if base_path else None
    )
    consent = ConsentManager(
        storage_path=base_path / "consent" if base_path else None
    )
    quota = QuotaManager(
        storage_path=base_path / "quotas" if base_path else None
    )
    
    if load_existing:
        await identity_mgr.initialize()
        await policy_eng.initialize()
        await audit.initialize()
        await consent.initialize()
        await quota.initialize()
    
    return {
        "identity": identity_mgr,
        "policy": policy_eng,
        "audit": audit,
        "consent": consent,
        "quota": quota,
    }


__all__ = [
    # Identity
    "Capability",
    "IdentityStatus",
    "CapabilityAttestation",
    "AgentIdentity",
    "SignatureVerification",
    "IdentityManager",
    "list_identities",
    "get_identity",
    "get_identity_by_public_key",
    "register_identity",
    "verify_identity",
    "revoke_identity",
    "get_default_manager",
    
    # Policy
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
    
    # Audit
    "AuditOutcome",
    "AuditSeverity",
    "AuditEntry",
    "AuditLogWriter",
    "AuditLog",
    "get_audit_log",
    "log_action",
    "query_by_agent",
    "query_by_action",
    "query_suspicious",
    "export_audit",
    
    # Consent
    "ConsentScope",
    "ConsentStatus",
    "ConsentGrant",
    "ConsentRequest",
    "ConsentManager",
    "get_consent_manager",
    "grant_consent",
    "revoke_consent",
    "check_consent",
    "list_consents",
    
    # Quota
    "QuotaResourceType",
    "QuotaPeriod",
    "QuotaLimit",
    "QuotaUsage",
    "QuotaStatus",
    "QuotaManager",
    "get_quota_manager",
    "set_quota",
    "check_quota",
    "record_usage",
    "get_usage",
    "get_quota_status",
    
    # Initialization
    "initialize_governance",
]