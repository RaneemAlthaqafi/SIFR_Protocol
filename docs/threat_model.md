# Threat Model

## In Scope
- Message tampering after signing.
- Wrong public-key verification.
- Unsigned messages.
- Unauthorized tool actions.
- Expired grants.
- Over-budget grants.
- Changed audit messages.
- Missing audit parents.

## Out of Scope for v0.1
- Network attackers.
- Compromised private keys.
- Full prompt-injection defense.
- Sandboxed arbitrary code execution.
- DID/VC trust-chain validation.
- Multi-writer distributed log consensus.
