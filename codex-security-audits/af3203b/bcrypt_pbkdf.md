# Security Audit Report: bcrypt_pbkdf.c

Date: 2026-01-18
Scope: dependencies/libbcrypt/bcrypt_pbkdf.c
Reviewer: Codex (AI)

## Summary
- Findings: 2 total (1 medium, 1 low)
- Primary risks: sensitive data may remain in memory due to non-guaranteed zeroization; potential NULL pointer deref if caller passes NULL with nonzero length.

## Findings

### 1) Non-guaranteed zeroization of sensitive buffers (Medium)
Evidence: `bcrypt_pbkdf` clears `sha2pass`, `sha2salt`, `tmpout`, and `out` with `memset` (lines 518-522). Optimizing compilers may remove these writes because the buffers are not used afterwards, which can leave derived key material in memory.

Impact: Potential secret disclosure via memory reuse, crash dumps, or other memory inspection.

Recommendation: Use an explicit zeroization routine (e.g., `explicit_bzero`-style or a volatile function pointer wipe) for sensitive buffers. Also clear sensitive contexts (`SHA512_CTX`) and derived data in `bcrypt_hash` (`blf_ctx`, `cdata`) for defense in depth.

### 2) Missing NULL pointer validation for pass/salt/key (Low)
Evidence: The function validates only lengths (lines 465-469) and then calls `SHA512_Update(&ctx, pass, passlen)` and `SHA512_Update(&ctx, salt, saltlen)` (lines 474-489). If a caller passes NULL with a nonzero length, this will dereference NULL. The output `key` is also written without a NULL check (lines 507-514).

Impact: Undefined behavior / crash (DoS) on invalid API usage.

Recommendation: Reject invalid input by returning an error when `pass`, `salt`, or `key` is NULL.

## Notes
- `bcrypt_hash` keeps derived values in stack locals (`blf_ctx ctx`, `blf_word cdata[]`) and does not wipe them before returning. This is not a direct vulnerability on its own, but zeroization would improve defense in depth.

## Remediation Plan (if approved)
- Add a secure zeroization utility and use it for all sensitive buffers and contexts.
- Add input pointer validation in `bcrypt_pbkdf`.
- Run `swift test` and report results.

## Remediation Applied
- Implemented `secure_memzero` and replaced `memset` wipes with secure zeroization for `sha2pass`, `sha2salt`, `tmpout`, `out`, `countsalt`, and `SHA512_CTX` in `bcrypt_pbkdf`.
- Added secure zeroization for `blf_ctx` and `cdata` in `bcrypt_hash` for defense in depth.
- Added early NULL checks for `pass`, `salt`, and `key` in `bcrypt_pbkdf`.
- Tests: `swift test` (passed; SwiftPM emitted resource warnings unrelated to this change).
