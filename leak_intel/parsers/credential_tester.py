"""Fail-closed, provider-injected Leak Intel credential validation.

Real provider adapters are intentionally absent at Gate 0.  The only supported
execution path is an explicitly allowlisted injected fixture/provider adapter
with exact target scope, credential-use approval, rate, attempt, and audit
bindings.  Direct legacy provider methods do not exist.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from common.base_module import BaseModule, ModuleResult
from common.action_authorization import (
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    consume_authorization,
)
from common.credential_boundary import (
    CredentialReference,
    CredentialUseApproval,
    InMemorySecretProvider,
    wipe_mapping,
)
from common.db import save_audit_log
from common.redaction import (
    redact_exception,
    redact_secret_fragments,
    redact_value,
)
from common.scope import canonical_target


log = logging.getLogger("forge.leak_intel.credential_tester")


def _redact_exact(value: Any, secrets: set[str] | tuple[str, ...] = ()) -> Any:
    """Redact resolved values even when a provider uses an arbitrary label."""
    safe = redact_value(value)
    literals = tuple(
        sorted(
            {item for item in secrets if isinstance(item, str) and item},
            key=len,
            reverse=True,
        )
    )

    def replace(item: Any) -> Any:
        if isinstance(item, str):
            return redact_secret_fragments(item, literals)
        if isinstance(item, dict):
            return {replace(key): replace(child) for key, child in item.items()}
        if isinstance(item, list):
            return [replace(child) for child in item]
        return item

    return replace(safe)


def _resolved_secret_values(values: Mapping[str, Any]) -> tuple[str, ...]:
    """Return only credential-bearing resolved values for exact echo removal."""
    ignored = {"username", "source", "cred_type"}
    return tuple(
        str(value)
        for key, value in values.items()
        if str(key).lower() not in ignored
        and isinstance(value, str)
        and value
    )


@dataclass
class CredentialPair:
    """Transient intake structure; values move immediately behind a reference."""

    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    access_key: str = field(default="", repr=False)
    secret_key: str = field(default="", repr=False)
    token: str = field(default="", repr=False)
    source: str = ""
    cred_type: str = "password"

    def secret_values(self) -> dict[str, str]:
        return {
            key: value
            for key, value in {
                "username": self.username,
                "password": self.password,
                "access_key": self.access_key,
                "secret_key": self.secret_key,
                "token": self.token,
                "source": self.source,
                "cred_type": self.cred_type,
            }.items()
            if value
        }

    def clear(self) -> None:
        self.username = ""
        self.password = ""
        self.access_key = ""
        self.secret_key = ""
        self.token = ""
        self.source = ""

    def __repr__(self) -> str:
        return f"CredentialPair(cred_type={self.cred_type!r}, values=<redacted>)"


@dataclass
class TestResult:
    """Redacted provider result metadata."""

    service: str
    success: bool = False
    detail: str = ""
    tested_at: float = 0.0

    def __post_init__(self) -> None:
        if not self.tested_at:
            self.tested_at = time.time()
        self.detail = str(redact_value(self.detail))


@dataclass(frozen=True)
class _CredentialAuthorizationAnchor:
    """Construction-time runtime facts independent of a supplied envelope."""

    tenant_id: str
    engagement_id: str
    run_id: str
    job_id: str
    operator_id: str
    operator_role: str
    scope_policy_version: str
    safety_mode: str
    target: str
    allowed_scope: tuple[str, ...]
    excluded_scope: tuple[str, ...]


class CredentialTester(BaseModule):
    """Credential validation boundary, disabled unless every policy fact matches."""

    NAME = "credential_tester"
    DESCRIPTION = "Separately authorized, rate-bounded credential validation"
    PHASE = 0
    TAGS = ["leak_intel", "credential", "validation", "auth"]

    _REQUIRED_POLICY_FIELDS = frozenset(
        {
            "enabled",
            "provider",
            "target",
            "allowed_scope",
            "credential_reference",
            "credential_use_approved",
            "credential_use_approval_id",
            "audit_enabled",
            "max_attempts",
            "rate_per_second",
        }
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._authorization_anchor = self._snapshot_authorization_anchor()
        self._secret_provider = InMemorySecretProvider("leak-fixture")
        self._credential_refs: list[CredentialReference] = []
        self._results: list[TestResult] = []
        self._audit_log: list[dict[str, Any]] = []

    def _snapshot_authorization_anchor(self) -> _CredentialAuthorizationAnchor | None:
        """Capture launcher facts once; later config mutation is never authority."""
        runtime = self.config.extra.get("authorization_runtime")
        job_id = self.config.extra.get("job_id")
        if not isinstance(runtime, Mapping) or not isinstance(job_id, str):
            return None
        required = (
            "tenant_id",
            "engagement_id",
            "run_id",
            "operator_id",
            "operator_role",
            "scope_policy_version",
            "safety_mode",
        )
        values: dict[str, str] = {}
        for field_name in required:
            value = runtime.get(field_name)
            if not isinstance(value, str) or not value.strip():
                return None
            values[field_name] = value.strip()
        normalized_job = job_id.strip()
        target = str(self.config.target or "").strip()
        if (
            not normalized_job
            or values["run_id"] != self.run_id
            or not target
        ):
            return None
        return _CredentialAuthorizationAnchor(
            tenant_id=values["tenant_id"],
            engagement_id=values["engagement_id"],
            run_id=values["run_id"],
            job_id=normalized_job,
            operator_id=values["operator_id"],
            operator_role=values["operator_role"],
            scope_policy_version=values["scope_policy_version"],
            safety_mode=values["safety_mode"],
            target=target,
            allowed_scope=tuple(str(item).strip() for item in self.scope.targets),
            excluded_scope=tuple(str(item).strip() for item in self.scope.excluded),
        )

    def _authorization_anchor_is_unchanged(self) -> bool:
        anchor = self._authorization_anchor
        if anchor is None or self.run_id != anchor.run_id:
            return False
        current = self._snapshot_authorization_anchor()
        return current is not None and current == anchor

    def add_credential(self, cred: CredentialPair) -> CredentialReference:
        """Move transient intake values into the local single-use provider."""
        reference = self._secret_provider.put(cred.secret_values())
        self._credential_refs.append(reference)
        cred.clear()
        return reference

    def add_credential_reference(self, reference: CredentialReference | str) -> None:
        """Register an already provider-held reference without resolving it."""
        self._credential_refs.append(CredentialReference.parse(reference))

    async def run(self) -> ModuleResult:
        return await self._run_impl()

    async def _run_impl(self) -> ModuleResult:
        start = time.monotonic()
        policy = self.config.extra.get("credential_validation_policy")
        reason = self._policy_denial_reason(policy)
        if reason:
            self._purge_credentials()
            return self._make_result(start, skipped=True, skip_reason=reason)
        assert isinstance(policy, dict)

        provider = str(policy["provider"]).strip().lower()
        target = str(policy["target"]).strip()
        requested_ref = str(policy["credential_reference"]).strip()
        adapter = self.config.extra.get("credential_validation_provider")
        if not callable(adapter):
            # Compatibility name remains fixture-only; it does not activate a
            # built-in real provider path.
            adapter = self.config.extra.get("credential_validation_fake_provider")
        if not callable(adapter):
            self._purge_credentials()
            return self._make_result(
                start,
                skipped=True,
                skip_reason="credential validation provider is unsupported",
            )

        references = [
            ref for ref in self._credential_refs if ref.value == requested_ref
        ]
        if len(references) != 1:
            self._purge_credentials()
            return self._make_result(
                start,
                skipped=True,
                skip_reason="credential reference is unavailable or ambiguous",
            )

        reference = references[0]
        approval = CredentialUseApproval(
            approval_id=str(policy["credential_use_approval_id"]),
            provider=provider,
            target=target,
            credential_reference=reference.value,
            # The provider handoff itself is single-use.  ``max_attempts`` is
            # an execution budget, never permission to resolve a reference
            # more than once.
            max_uses=1,
        )
        interval = 1.0 / float(policy["rate_per_second"])
        max_attempts = int(policy["max_attempts"])
        attempts = 0
        last_attempt = 0.0
        try:
            with self._secret_provider.resolve(
                reference,
                approval=approval,
                target=target,
            ) as values:
                exact_secrets = _resolved_secret_values(values)
                if attempts >= max_attempts:
                    return self._make_result(start)
                wait_for = interval - (time.monotonic() - last_attempt)
                if last_attempt and wait_for > 0:
                    await asyncio.sleep(wait_for)
                attempts += 1
                last_attempt = time.monotonic()
                audit_ok = self._audit(
                    provider,
                    False,
                    "attempt_started",
                    reference=reference,
                    target=target,
                    secret_values=exact_secrets,
                )
                if not audit_ok:
                    return self._make_result(
                        start,
                        skipped=True,
                        skip_reason="credential validation audit is unavailable",
                    )
                try:
                    credential_payload = dict(values)
                    try:
                        outcome = adapter(
                            provider=provider,
                            target=target,
                            credential_reference=reference.value,
                            credential=credential_payload,
                        )
                        if hasattr(outcome, "__await__"):
                            outcome = await outcome
                        success = bool(outcome.get("success")) if isinstance(outcome, Mapping) else False
                        raw_detail = outcome.get("detail", "") if isinstance(outcome, Mapping) else ""
                        detail = str(_redact_exact(raw_detail, exact_secrets))
                        self._results.append(TestResult(provider, success, detail))
                        self._audit(
                            provider,
                            success,
                            detail,
                            reference=reference,
                            target=target,
                            secret_values=exact_secrets,
                        )
                    finally:
                        wipe_mapping(credential_payload)
                except Exception as exc:
                    safe_exception = str(_redact_exact(redact_exception(exc), exact_secrets))
                    self._results.append(TestResult(provider, False, safe_exception))
                    self._audit(
                        provider,
                        False,
                        safe_exception,
                        reference=reference,
                        target=target,
                        secret_values=exact_secrets,
                    )
        finally:
            # Any never-used fixture references are purged when this module
            # instance is discarded; resolved values are wiped by the provider.
            self._purge_credentials()

        return self._make_result(start)

    def _purge_credentials(self) -> None:
        self._secret_provider.discard_all()
        self._credential_refs.clear()

    def _policy_denial_reason(self, policy: Any) -> str:
        if not isinstance(policy, dict) or policy.get("enabled") is not True:
            return "credential validation disabled by default"
        if not self._REQUIRED_POLICY_FIELDS.issubset(policy):
            return "credential validation not authorized"
        provider = str(policy.get("provider", "")).strip().lower()
        target = str(policy.get("target", "")).strip()
        reference = str(policy.get("credential_reference", "")).strip()
        allowed_providers = {
            str(item).strip().lower()
            for item in self.config.extra.get(
                "safe_credential_validation_providers", []
            )
        }
        allowed_scope = policy.get("allowed_scope")
        excluded_scope = policy.get("excluded_scope", self.scope.excluded)
        rate = policy.get("rate_per_second")
        attempts = policy.get("max_attempts")
        try:
            parsed_reference = CredentialReference.parse(reference)
        except (TypeError, ValueError):
            parsed_reference = None
        anchor = self._authorization_anchor
        configured_target = anchor.target if anchor is not None else ""
        try:
            current_target = canonical_target(str(self.config.target or "").strip())
            target_matches_config = bool(configured_target) and (
                canonical_target(target) == canonical_target(configured_target)
                and current_target == canonical_target(configured_target)
            )
        except (TypeError, ValueError):
            target_matches_config = False
        scope_targets = anchor.allowed_scope if anchor is not None else ()
        scope_excluded = anchor.excluded_scope if anchor is not None else ()
        scope_is_unchanged = (
            tuple(str(item).strip() for item in self.scope.targets) == scope_targets
            and tuple(str(item).strip() for item in self.scope.excluded)
            == scope_excluded
        )
        policy_scope = (
            tuple(str(item).strip() for item in allowed_scope)
            if isinstance(allowed_scope, (list, tuple))
            else ()
        )
        policy_excluded = (
            tuple(str(item).strip() for item in excluded_scope)
            if isinstance(excluded_scope, (list, tuple))
            else ()
        )
        scope_allows_target = False
        try:
            scope_allows_target = bool(self.scope.decision(target).allowed)
        except Exception:
            scope_allows_target = False
        rate_value = (
            float(rate)
            if isinstance(rate, (int, float)) and not isinstance(rate, bool)
            else -1.0
        )
        if (
            not provider
            or provider not in allowed_providers
            or not target
            or parsed_reference is None
            or parsed_reference.provider != provider
            or not target_matches_config
            or not scope_is_unchanged
            or not self._authorization_anchor_is_unchanged()
            or not scope_allows_target
            or policy_scope != scope_targets
            or policy_excluded != scope_excluded
            or not reference.startswith("cred:")
            or policy.get("credential_use_approved") is not True
            or not str(policy.get("credential_use_approval_id", "")).strip()
            or policy.get("audit_enabled") is not True
            or type(attempts) is not int
            or not 1 <= attempts <= 10
            or type(rate) not in {int, float}
            or not 0 < rate_value <= 10
        ):
            return "credential validation not authorized"
        if parsed_reference is None:
            return "credential validation not authorized"
        authorization_reason = self._authorization_denial_reason(
            policy,
            provider=provider,
            target=target,
            reference=parsed_reference,
        )
        if authorization_reason:
            return authorization_reason
        return ""

    def _authorization_value(self) -> Any:
        """Resolve the caller-supplied envelope without treating policy flags as auth."""
        for key in (
            "credential_validation_authorization",
            "credential_use_authorization",
            "authorized_credential_envelope",
        ):
            value = self.config.extra.get(key)
            if value is not None:
                return value
        return None

    def _authorization_denial_reason(
        self,
        policy: Mapping[str, Any],
        *,
        provider: str,
        target: str,
        reference: CredentialReference,
    ) -> str:
        raw_envelope = self._authorization_value()
        if raw_envelope is None:
            return "credential validation authorization envelope is missing"
        try:
            envelope = ActionAuthorizationEnvelope.from_value(raw_envelope)
        except Exception:
            return "credential validation authorization envelope is invalid"
        if (
            envelope.decision_outcome != "allow"
            or envelope.engine.lower() != "leak_intel"
            or not envelope.credential_approval_required
            or envelope.credential_reference != reference.value
            or reference.provider != provider
            or envelope.action_kind.lower() != "credential.validate"
            or envelope.module_id.lower()
            not in {f"{self.NAME}:{provider}", f"{self.NAME}/{provider}"}
            or str(policy.get("credential_use_approval_id", ""))
            not in {envelope.decision_id, envelope.action_id}
        ):
            return "credential validation authorization does not match provider or reference"

        anchor = self._authorization_anchor
        if anchor is None:
            return "credential validation runtime authorization context is missing"
        if not self._authorization_anchor_is_unchanged():
            return "credential validation runtime authorization context does not match module run"
        try:
            expected = AuthorizationContext(
                tenant_id=anchor.tenant_id,
                engagement_id=anchor.engagement_id,
                run_id=anchor.run_id,
                job_id=anchor.job_id,
                operator_id=anchor.operator_id,
                operator_role=anchor.operator_role,
                action_kind="credential.validate",
                engine="leak_intel",
                module_id=envelope.module_id,
                requested_target=anchor.target,
                resolved_target=anchor.target,
                allowed_scope=anchor.allowed_scope,
                excluded_scope=anchor.excluded_scope,
                scope_policy_version=anchor.scope_policy_version,
                safety_mode=anchor.safety_mode,
                credential_approval_required=True,
                network_escalation_approval_required=(
                    envelope.network_escalation_approval_required
                ),
                high_risk_approval_required=envelope.high_risk_approval_required,
                confirmation_method=envelope.confirmation_method,
                confirmed_by=anchor.operator_id,
                credential_reference=reference.value,
                parent_decision_id=envelope.parent_decision_id,
            )
            decision = consume_authorization(
                session=self.db,
                envelope=envelope,
                expected=expected,
                boundary="leak_intel.credential",
            )
        except Exception:
            return "credential validation authorization could not be verified"
        if not decision.allowed:
            return "credential validation authorization could not be verified"
        # Retain only the parsed immutable envelope for audit metadata; policy
        # dictionaries remain untrusted and are never treated as capability.
        self.authorization_envelope = envelope
        self.authorization_context = expected
        self.authorization_boundary = "leak_intel.credential"
        return ""

    def _audit(
        self,
        service: str,
        success: bool,
        detail: Any,
        *,
        reference: CredentialReference,
        target: str,
        secret_values: tuple[str, ...] = (),
    ) -> bool:
        entry = _redact_exact(
            {
                "timestamp": time.time(),
                "service": service,
                "target": target,
                "credential_reference": reference.value,
                "success": success,
                "detail": detail,
            },
            secret_values,
        )
        self._audit_log.append(entry)
        try:
            save_audit_log(
                self.db,
                {
                    "timestamp": entry["timestamp"],
                    "tenant_id": (
                        self.authorization_envelope.tenant_id
                        if self.authorization_envelope is not None
                        else "default"
                    ),
                    "operator": (
                        self.authorization_envelope.operator_id
                        if self.authorization_envelope is not None
                        else ""
                    ),
                    "role": (
                        self.authorization_envelope.operator_role
                        if self.authorization_envelope is not None
                        else ""
                    ),
                    "action": "credential_validation",
                    "object_id": reference.value,
                    "status": "success" if success else "attempt",
                    "detail": entry,
                },
            )
        except Exception as exc:
            self.log.error("Credential validation audit persistence failed (%s)", type(exc).__name__)
            return False
        self.log.log(
            logging.WARNING if success else logging.DEBUG,
            "[AUDIT] Credential validation service=%s target=%s success=%s ref=%s detail=%s",
            service,
            target,
            success,
            reference.value,
            entry["detail"],
        )
        return True
