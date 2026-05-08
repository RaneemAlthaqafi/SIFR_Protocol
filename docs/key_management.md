# Key Management

This document covers the on-disk encrypted keystore in `sifr/key_management.py`.

## Threat model

In scope:
- Compromise of a private-key file at rest. An attacker with read access to the keystore file but no passphrase cannot recover private keys.
- Tampering with the keystore file (changing ciphertext, swapping entries between kids, modifying metadata).
- Single-user, single-process key rotation.

Out of scope:
- HSM-grade key storage. SIFR makes no claim of FIPS-140-3 or hardware-backed key isolation.
- Enterprise PKI. There is no certificate authority, no chain validation, and no out-of-band trust establishment.
- Compromise of the host process while the keystore is open. The derived key is held in memory; an attacker with full process access can read it.
- Multi-process concurrent writes. The keystore uses write-then-rename atomic swap, but two processes opening the same keystore for write concurrently is undefined.
- Side-channel attacks (timing, cache, EM).

## File format

Single JSON file. All bytes encoded as base64 in JSON strings.

```json
{
    "version": 1,
    "argon2": {"time_cost": 3, "memory_cost": 65536, "parallelism": 1},
    "salt": "<16 random bytes, base64>",
    "entries": [
        {
            "kid": "did:sifr:alice#key-1",
            "public_key": "<32 bytes Ed25519, base64>",
            "created_at": "2026-05-08T13:24:11.124000+00:00",
            "revoked_at": null,
            "revoked_reason": null,
            "ciphertext": "<AES-256-GCM(private_key_raw_32_bytes), base64>",
            "nonce": "<12 random bytes per entry, base64>"
        }
    ]
}
```

## Cryptographic construction

- **KDF**: Argon2id from `argon2-cffi`. Parameters travel with the file (so old files keep working when defaults change). Production defaults: `time_cost=3`, `memory_cost=65536` (64 MiB), `parallelism=1`, `hash_len=32`. Tests override with `TEST_ARGON2_PARAMS` (`memory_cost=8`) for speed.
- **AEAD**: AES-256-GCM with a 12-byte random nonce per entry. The kid is bound as Additional Authenticated Data (AAD), so swapping `ciphertext` between entries (e.g., putting Alice's encrypted private key into Bob's entry) makes decryption fail.
- **Salt**: 16 random bytes generated when the keystore is created. Stored alongside the entries.

## Trap-acceptance tests

Tests in `tests/test_key_management.py` enforce the following non-trivial properties:

| Test | What it proves |
|---|---|
| `test_keystore_file_does_not_contain_raw_private_key` | The JSON file does not contain the private key bytes verbatim — encryption is real, not a label. |
| `test_wrong_passphrase_rejected` | A keystore opened with a different passphrase cannot decrypt entries. |
| `test_tampered_ciphertext_rejected` | Modifying the ciphertext breaks decryption (GCM tag verification). |
| `test_kid_aad_binding_prevents_ciphertext_swap` | Swapping `ciphertext`/`nonce` between two entries fails because the kid is bound as AAD. |
| `test_rotation_old_signature_still_verifies_via_resolver` | After rotation, signatures made with the prior kid still verify if the prior kid is still in the store. |

## Rotation policy (recommended)

1. `generate_keypair("agent#key-N+1")` to add a fresh kid.
2. Issue all new grants and signatures using the new kid.
3. Keep the old kid in the store (un-revoked) until all in-flight grants signed under it have expired. Revoking too early invalidates legitimate verifications.
4. Once no grants reference the old kid, call `revoke(old_kid, reason)`.

## Limitations

- `EncryptedFileKeyStore` does not support concurrent writers.
- There is no built-in passphrase strength check. A weak passphrase makes the Argon2 work factor meaningless.
- The `KeyringKeyStore` opt-in backend is not implemented in v0.2 — only the file backend is shipped.
