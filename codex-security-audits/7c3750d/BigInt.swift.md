# Security Audit Report: BigInt.swift

Date: 2026-01-18
Scope: Sources/xuanxue/BigInt.swift
Reviewer: Codex (AI)
Reference: codex-security-audits/af3203b/bcrypt_pbkdf.md

## Summary
- Findings: 1 total (low)
- Primary risks: intermediate RSA values may persist in memory.

## Findings

### 1) Sensitive intermediate buffers not zeroized (Low)
Evidence: `BigIntOps.subtractOne` and `BigIntOps.modulo` allocate intermediate arrays (`result`, `dividend`, `divisor`, `effectiveDivisor`, `remainder`) that may include RSA private parameters or derived values (e.g., dp/dq). These were not explicitly wiped after use.

Impact: Potential residual exposure of RSA-related intermediate values in memory.

Recommendation: Explicitly zeroize intermediate arrays once their values are no longer needed.

## Remediation Plan (if approved)
- Add a local zeroization helper and wipe intermediate arrays before returning.
- Ensure all temporary arrays in `subtractOne` and `modulo` are cleared via defer.
- Run swift test and report results.

## Remediation Applied
- Added a local zeroization helper for byte arrays.
- Wiped intermediate arrays in `subtractOne` and `modulo` using deterministic zeroization and defer.

## Tests
- swift test (passed)
