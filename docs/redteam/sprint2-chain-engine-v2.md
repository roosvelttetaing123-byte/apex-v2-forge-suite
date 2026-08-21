# Sprint 2 — Chain Engine v2

## Goal
Upgrade ChainEngine from reactive single-hop to proactive multi-hop with scoring and state tracking.

## Files to Modify
- `common/attack_chains.py` — main engine upgrade

## Engine Upgrades

### 1. Multi-hop chains
Current: A→B only. New: A→B→C→D with chain continuation. When chain step B completes, engine checks for next step C.

### 2. Chain state machine
Track per-chain: `PENDING` → `IN_PROGRESS` → `COMPLETED` | `FAILED` | `BLOCKED`. Expose via `engine.chain_states`.

### 3. Conditional branching
If SSRF reaches cloud metadata → trigger cloud IAM path. If SSRF reaches internal service → trigger pivot path. Implement as `branch_conditions` on ChainTrigger.

### 4. Failure adaptation
On PsExec failure → try WinRM → try WMI → try SSH. Implement as `fallback_modules: list[str]` on ChainTrigger.

### 5. Chain scoring
Score = `impact × P(success) × stealth_multiplier`. Execute highest-score chain first. Add `impact_score`, `success_probability`, `stealth_cost` to ChainTrigger.

### 6. Chain dependency DAG
Build directed acyclic graph of chain prerequisites. Finding X unlocks chains Y and Z. Expose via `engine.dependency_graph()`.

### 7. OSINT-driven proactive chains
Chain engine proactively fires leak scanners before other modules. LeakIntel findings feed into credential testing chains.

## New Attack Chains (24 total, 14 new)

Add to `_CHAIN_DEFINITIONS`:

| # | chain_id | trigger_types | next_module | opsec | auto |
|---|----------|--------------|-------------|-------|------|
| 11 | `lfi_to_cred_harvest` | lfi | source_code_parser | STEALTH | yes |
| 12 | `ssrf_to_cloud_iam` | ssrf, blind_ssrf | cloud_metadata | STEALTH | yes |
| 13 | `kerberoast_to_lateral` | kerberoast_hash | hash_crack | STANDARD | yes |
| 14 | `spray_to_mfa_bypass` | password_spray | mfa_bypass | STANDARD | no |
| 15 | `adcs_to_domain_admin` | adcs_vuln | cert_request | STANDARD | no |
| 16 | `webshell_to_beacon` | webshell | reverse_shell | STANDARD | yes |
| 17 | `subdomain_takeover_to_phish` | subdomain_takeover | phishing_page | STEALTH | no |
| 18 | `graphql_to_exfil` | graphql_introspection | sqli | STEALTH | yes |
| 19 | `jwt_to_admin` | jwt_weak_secret | jwt_forge | STEALTH | yes |
| 20 | `redirect_to_oauth_theft` | open_redirect | oauth_intercept | STEALTH | no |
| 21 | `deser_to_beacon` | deserialization | rce_exec | STANDARD | yes |
| 22 | `ntlm_to_adcs_da` | ntlm_relay | adcs_relay | NOISY | no |
| 23 | `race_to_privesc` | race_condition | priv_esc_check | STANDARD | yes |
| 24 | `cache_to_session` | cache_poison | xss | STEALTH | yes |

Plus leak-intel chains from Sprint 0 (#1-5).

## Acceptance Criteria

- [ ] Multi-hop chain fires B→C after A→B completes
- [ ] State machine tracks all 24+ chains
- [ ] Failure adaptation falls back to alternative modules
- [ ] Chain scoring prioritizes highest-ROI chain
- [ ] DAG correctly maps prerequisites
