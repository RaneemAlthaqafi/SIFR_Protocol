# Formal Model

SIFR v0.2 ships a TLA+ model of the **capability authorization state machine**, model-checked with TLC. The model lives in `formal/sifr_capability.tla` with TLC config in `formal/MC.cfg`.

## Scope

The model covers:

- The lifecycle states `unissued -> active -> {expired | revoked}`.
- The actions `Issue`, `Expire`, `Revoke`, `Consume` with their preconditions.
- The replay set `(subject, message_id) \in consumedMsg`.
- A bounded budget `MaxCalls` per capability.
- A history sequence used to express order-dependent invariants (e.g., "no consume after revoke").

The model does NOT cover:

- Cryptography. Signatures, key resolution, and DID document validation are handled by other layers (`sifr/crypto.py`, `sifr/did/`). The model assumes these layers correctly authenticate the subject and issuer; it abstracts to `subject = s` as a guard.
- Network transport. The QUIC layer is orthogonal.
- Side channels.

## Invariants checked

| Invariant | Code mapping (verifies the spec is enforced) |
|---|---|
| `NoOverBudgetConsume` | `sifr/capabilities.py:authorize_action` raises `UnauthorizedAction("CALL_BUDGET_EXCEEDED")` when `store.usage(cap_id) >= max_calls`. |
| `NoWrongSubjectConsume` | `authorize_action` raises `UnauthorizedAction("WRONG_SUBJECT")` when `payload["subject"] != action.sender_id`. |
| `NoUnauthorizedActionConsume` | `authorize_action` raises `UnauthorizedAction("UNAUTHORIZED_ACTION")` when `action not in grant.actions`. |
| `NoReplayedConsume` | `sifr/replay.py:ReplayCache.check_and_record` raises `ReplayError("duplicate")` when `(sender, session, msg_id)` is already in the cache. |
| `NoConsumeAfterRevoke` | `authorize_action` consults the `RevocationRegistry`; `is_revoked(cap_id)` is non-None after `RevocationRegistry.revoke(cap_id, ...)` and triggers `UnauthorizedAction("REVOKED_CAPABILITY")`. |
| `NoConsumeAfterExpire` | `authorize_action` raises `UnauthorizedAction("EXPIRED_CAPABILITY")` when `now >= grant.expires_at`. |

Each TLA+ invariant maps to one or more Python error paths exercised by tests in `tests/test_network_adversary.py` (the 11-attack suite).

## Running TLC

This project does NOT bundle Java or `tla2tools.jar`. To check the model on your host:

1. Install a JRE 11+:
   - Windows: `winget install Microsoft.OpenJDK.17`
   - Ubuntu: `apt-get install default-jre`
   - macOS: `brew install openjdk@17`
2. Download `tla2tools.jar`:
   - Windows: `pwsh scripts/install_tla.ps1` (downloads to `formal/tools/`)
   - Or manually from https://github.com/tlaplus/tlaplus/releases
3. Set the env var so the wrappers can find the jar:
   - PowerShell: `$env:TLA_TOOLS_PATH = "C:/path/to/tla2tools.jar"`
   - bash: `export TLA_TOOLS_PATH=/path/to/tla2tools.jar`
4. Run:
   - PowerShell: `pwsh formal/run_tlc.ps1`
   - bash: `bash formal/run_tlc.sh`

Output lands at `formal/output/tlc_output.txt`. The `tests/test_formal_artifacts.py` test will then parse this output and assert TLC found no errors and exercised every invariant declared in `MC.cfg`.

## Trap-acceptance

`tests/test_formal_artifacts.py` enforces:

- The model file exists and declares each expected invariant by name.
- `MC.cfg` lists the invariants (so renaming an invariant in the model without updating MC.cfg breaks the test).
- If `tlc_output.txt` is present on the host, it MUST contain a TLC success marker AND every invariant from MC.cfg.
- If `tlc_output.txt` is absent, the freshness test skips with a clear instruction. A reviewer producing a release artifact runs TLC and commits the output; the test then enforces the artifact is fresh.

This means **adding an invariant to MC.cfg without re-running TLC** fails the test in CI / release verification.

## What we explicitly do NOT claim

- **Cryptographic proof.** Tools like ProVerif or Tamarin model cryptographic protocols and adversaries. SIFR's TLA+ model does not. We make no claim about the security of Ed25519, our DID resolution, or our capability credential proofs at the cryptographic level.
- **Liveness.** The model checks safety invariants (nothing bad happens). Liveness (something good eventually happens) is not modeled.
- **Implementation correctness.** The model captures the *spec* of authorization. Code review of `sifr/capabilities.py` and the trap-acceptance tests in `tests/test_network_adversary.py` jointly attest that the implementation matches the spec; the TLA+ model alone is insufficient evidence of that.
- **Real concurrency.** TLC explores interleavings of actions but the SIFR implementation runs single-threaded per process. Multi-process race conditions are out of model scope.

## Bounded constants

`MC.cfg` uses small constants for tractable model checking: `Caps = {c1, c2}`, `Subs = {alice, bob}`, `Acts = {add, multiply}`, `Msgs = {m1, m2}`, `MaxCalls = 2`. Larger constants would not change the truth of the invariants under the TLA+ assumption that data abstraction holds; they would only enlarge the state space.
