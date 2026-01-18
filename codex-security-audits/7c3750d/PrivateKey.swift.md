# Security Audit Report: PrivateKey.swift

Date: 2026-01-18
Scope: Sources/xuanxue/PrivateKey.swift
Reviewer: Codex (AI)

## Summary
- Findings: 2 total (1 medium, 1 low)
- Primary risks: sensitive key material may remain in memory; passphrase handling via String increases residual exposure risk.

## Findings

### 1) Sensitive buffers not zeroized (Medium)
Evidence: The OpenSSH parsing and KDF/decryption flow creates temporary buffers for decrypted key blocks, derived keys/IVs, and raw private key material (RSA d/p/q/iqmp, ECDSA scalar, Ed25519 seed). These buffers are not explicitly zeroed after use, so secrets may remain in memory.

Impact: Potential secret disclosure via memory reuse, crash dumps, or other memory inspection.

Recommendation: Add explicit zeroization for all sensitive buffers using a deterministic wipe method, and ensure it runs via defer paths.

### 2) Passphrase handled as String (Low)
Evidence: Passphrase input is accepted as String, which is immutable and may be copied or stored in multiple internal buffers. This makes reliable zeroization impossible and can prolong secret lifetime in memory.

Impact: Increased exposure window for passphrase material in memory; higher risk under memory inspection or diagnostics.

Recommendation: Migrate passphrase API to Data and use raw bytes for KDF input to reduce unnecessary copies and enable zeroization.

## Remediation Plan (if approved)
- Migrate passphrase API from String to Data for OpenSSH key loading.
- Introduce zeroization helpers and apply them to all sensitive buffers, including derived keys/IVs and decrypted key blocks.
- Review RSA helper math intermediates and wipe temporary buffers used in dp/dq derivation.
- Run swift test and report results.

## Remediation Applied
- Passphrase API migrated to Data; KDF now consumes raw bytes directly.
- Added zeroization helpers and applied defer-based wipes for decrypted key blocks, derived key/IV, and RSA/ECDSA/Ed25519 secret material.
- Added zeroization in RSA helper math intermediates and AES CBC/CTR internal buffers for defense in depth.
- Updated tests and documentation to use Data passphrases.

## Tests
- swift test (passed)
