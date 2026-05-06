# SIFR Protocol Specification v0.1

Status: research prototype specification. This document uses RFC-style language. It is not an Internet Standard.

## 1. Abstract

SIFR, Secure Interchange for Federated Reasoning, defines a signed typed frame format for AI-agent communication. SIFR v0.1 specifies message envelopes, canonical serialization, Ed25519 signing, capability grants, local transport, TensorFrame demonstration encoding, and audit-DAG lineage. QUIC, WASM/WASI isolation, DID resolution, Verifiable Credentials, replay caches, and revocation are not implemented in v0.1.

## 2. Goals

SIFR v0.1 has these goals:

- Messages MUST have explicit types.
- Messages SHOULD be signed before transmission.
- Signed bytes MUST be deterministic under canonical serialization.
- Protected Action and ToolUse messages MUST be checked against a signed capability grant.
- Accepted messages SHOULD be recorded in an audit DAG.
- Tampering with signed messages or stored DAG messages MUST be detectable.

## 3. Non-goals

SIFR v0.1 does not provide:

- Production transport security.
- QUIC implementation.
- DID method implementation or DID resolution.
- Verifiable Credential issuance or verification.
- WASM/WASI sandbox isolation.
- Real KV-cache sharing.
- Formal security proofs.
- Distributed consensus or multi-writer log replication.

## 4. Terminology

Agent: a communicating principal.

Frame: a SIFR message envelope plus payload and optional signature.

Capability Grant: a signed message authorizing a subject to perform bounded actions.

CID: content identifier in the form `sha256:<hex>`.

Audit DAG: a directed acyclic graph of message nodes linked by parent CIDs.

## 5. System Model

Agents exchange SIFR frames over a transport abstraction. v0.1 implements `LocalTransport` using in-memory queues. A verifier is assumed to know the sender public key out of band. This assumption MUST be replaced by a real trust and key-discovery model before production use.

## 6. Threat Assumptions

SIFR v0.1 considers attackers who can:

- Modify a message after signing.
- Substitute a sender field.
- Verify with the wrong public key.
- Send unsigned messages.
- Reuse expired grants.
- Request unauthorized actions.
- Exceed call budgets.
- Mutate locally stored audit messages.
- Remove parent messages from a DAG.

SIFR v0.1 does not defend against compromised private keys, network attackers, prompt injection, sandbox escapes, or distributed log equivocation.

## 7. Message Envelope

Each frame MUST use this logical structure:

```json
{
  "version": "sifr/0.1",
  "message_id": "msg_unique_id",
  "session_id": "sess_unique_id",
  "type": "Action",
  "sender_id": "did:sifr:agent_a",
  "receiver_id": "did:sifr:agent_b",
  "timestamp": "ISO-8601 UTC timestamp",
  "parents": ["sha256:parent_cid"],
  "capability_id": "cap_optional",
  "payload": {},
  "signature": {
    "alg": "Ed25519",
    "kid": "did:sifr:agent_a#key-1",
    "value": "base64_signature"
  }
}
```

`message_id` MUST be unique within a deployment scope. `session_id` SHOULD remain stable across a workflow. `timestamp` MUST include UTC timezone information. `parents` MAY be empty for root messages.

## 8. Message Types

Valid message types are:

- Hello
- CapabilityOffer
- CapabilityGrant
- Thought
- Action
- ToolUse
- Observation
- Result
- Critique
- Error
- TensorFrame

Implementations MUST reject unknown message types unless an extension negotiation mechanism is added.

## 9. Canonical Serialization

For signing and hashing:

1. Remove the `signature` field if present.
2. Serialize JSON with sorted keys.
3. Use compact separators: comma and colon with no extra whitespace.
4. Encode as UTF-8.

Implementations MUST NOT sign pretty-printed JSON or runtime object memory layouts.

## 10. Signing Rules

v0.1 uses Ed25519. Implementations MUST NOT implement Ed25519 manually. A signature MUST cover canonical bytes without the `signature` field. The signature value MUST be base64 encoded. The key identifier SHOULD identify the signing agent key.

## 11. Verification Rules

Verification MUST fail when:

- The signature field is missing.
- The signature algorithm is unsupported.
- The signature value is malformed.
- The wrong public key is used.
- Any signed field changes after signing.

Verification alone does not authorize an action.

## 12. Capability Grants

A CapabilityGrant payload MUST include:

- `capability_id`
- `issuer`
- `subject`
- `actions`
- `resource_scope`
- `issued_at`
- `expires_at`
- `budget`
- `constraints`

The grant MUST be signed by the issuer. The `issuer` field MUST match the grant message sender.

## 13. Capability Budgets

The budget object MAY include:

```json
{
  "max_calls": 5,
  "max_payload_bytes": 10000
}
```

Implementations MUST reject an action if accepting it would exceed `max_calls` or `max_payload_bytes`.

## 14. Expiration

Implementations MUST reject a grant when current UTC time is greater than or equal to `expires_at`. Clock synchronization and skew policy are future work.

## 15. Replay Protection

v0.1 includes unique message identifiers but does not implement a replay cache. A production implementation MUST store recently seen message IDs or nonces and reject duplicates within a policy window.

## 16. Audit DAG

An audit node SHOULD include:

```json
{
  "cid": "sha256:...",
  "message_id": "msg_...",
  "type": "Action",
  "sender_id": "did:sifr:agent_a",
  "receiver_id": "did:sifr:agent_b",
  "parents": ["sha256:..."],
  "timestamp": "...",
  "signature_valid": true
}
```

The CID MUST be computed as SHA-256 over canonical message bytes without the signature field. Implementations MUST detect missing parents and changed stored messages.

## 17. TensorFrame

TensorFrame v0.1 carries demonstration numeric vectors. The implemented encoding is raw float32 bytes encoded with base64. Implementations MUST validate dtype, shape, and payload length before decoding. v0.1 MUST NOT be described as real KV-cache sharing or privacy-preserving latent communication.

## 18. Tool Sandbox Interface

v0.1 defines a `SandboxedToolRunner` interface and a calculator stub supporting `tool.calculator.add(a, b)`. Tool execution MUST occur only after signature and capability verification. The Python calculator stub is not a WASM sandbox.

## 19. Transport Abstraction

The transport interface is:

```python
class Transport:
    async def send(self, message): ...
    async def recv(self): ...
```

v0.1 implements local in-memory queues. The simulated HTTP JSON baseline is serialization-only and is not a real HTTP server.

## 20. QUIC Future Backend

QUIC is specified as the intended future low-latency transport backend. No QUIC implementation is present in v0.1.

## 21. Interoperability Bridges

MCP, A2A, ACP, ANP, and HTTP JSON adapters are future work. v0.1 MUST NOT claim compatibility with these protocols beyond architectural discussion.

## 22. Error Codes

Representative errors:

- `UNAUTHORIZED_ACTION`
- `WRONG_SUBJECT`
- `EXPIRED_CAPABILITY`
- `CALL_BUDGET_EXCEEDED`
- `PAYLOAD_BUDGET_EXCEEDED`
- `DELEGATION_NOT_ALLOWED`
- `CAPABILITY_MISMATCH`

## 23. Versioning

Implementations MUST reject unsupported major versions. Extension negotiation is future work.

## 24. Security Considerations

Signatures provide integrity under the assumed key. They do not provide authorization, trust, identity discovery, revocation, replay defense, confidentiality, or sandboxing. Capability checks MUST be performed before protected actions. Denied and malformed requests SHOULD be logged in future versions.

## 25. Limitations

SIFR v0.1 is a research artifact intended to make a protocol idea concrete and testable. It is not production-ready.
