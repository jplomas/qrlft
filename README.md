# qrlft - QRL File Tools

Command-line tools for quantum-resistant file signing, verification, and hashing using post-quantum cryptographic algorithms.

## Installation

```bash
go install github.com/theQRL/qrlft/v4@latest
```

Or build from source:
```bash
git clone https://github.com/theQRL/qrlft
cd qrlft
go build
```

## Supported Algorithms

| Algorithm | Description | Context Required |
|-----------|-------------|------------------|
| `dilithium` | CRYSTALS-Dilithium (pre-FIPS) | No |
| `mldsa` | ML-DSA-87 (FIPS 204 standard) | Yes |

## Commands

### Generate Keypair

```bash
# Dilithium
qrlft new -a dilithium mykey
qrlft new-dilithium -a dilithium mykey  # alias

# ML-DSA-87 (requires context)
qrlft new -a mldsa --context="myapp" mykey
qrlft new-mldsa -a mldsa --context="myapp" mykey  # alias

# Print to console instead of file
qrlft new -a dilithium --print
```

Output files: `mykey` (private key), `mykey.pub` (public key), and
`mykey.private.hexseed` (compatibility copy of the private seed key)

ML-DSA-87 private and public keys use the standardized RFC 9881 PKCS#8 and
SubjectPublicKeyInfo encodings. Both `mykey` and the retained
`mykey.private.hexseed` compatibility filename contain the same recommended
seed-only PKCS#8 private-key representation and can be supplied to `--keyfile`.

### Sign Files

```bash
# Using hexseed file
qrlft sign -a dilithium --keyfile=mykey.private.hexseed document.txt

# Using hexseed directly
qrlft sign -a dilithium --hexseed=abc123... document.txt

# ML-DSA-87 with context and its standard private key
qrlft sign -a mldsa --context="myapp" --keyfile=mykey document.txt

# Sign a string
qrlft sign -a dilithium -s --hexseed=abc123... "Hello World"

# Quiet mode (signature only)
qrlft sign -a dilithium --quiet --keyfile=mykey.private.hexseed document.txt
```

### Verify Signatures

```bash
# From signature file
qrlft verify -a dilithium --sigfile=document.sig --pkfile=mykey.pub document.txt

# From command line
qrlft verify -a dilithium --signature=abc123... --publickey=def456... document.txt

# ML-DSA-87 with context
qrlft verify -a mldsa --context="myapp" --sigfile=document.sig --pkfile=mykey.pub document.txt
```

### Extract Public Key

```bash
# Write to file
qrlft publickey -a dilithium --hexseed=abc123... mykey.pub

# Print to console
qrlft publickey -a dilithium --print --hexseed=abc123...

# ML-DSA-87
qrlft publickey -a mldsa --context="myapp" --hexseed=abc123... mykey.pub
```

### Hash Files

All hash algorithms are post-quantum secure.

```bash
qrlft hash --sha3-512 document.txt   # Recommended
qrlft hash --sha256 document.txt
qrlft hash --keccak-256 document.txt
qrlft hash --keccak-512 document.txt
qrlft hash --blake2s document.txt

# Hash a string
qrlft hash -s --sha3-512 "Hello World"
```

### Generate Random Salt

```bash
qrlft salt 32  # Generate 32 bytes of random salt
```

## Key File Formats

Keys are stored using RFC 7468 textual encodings:

**Dilithium:**
```
-----BEGIN DILITHIUM PRIVATE KEY-----
...base64 encoded key...
-----END DILITHIUM PRIVATE KEY-----
```

Legacy pre-FIPS Dilithium has no finalized PKIX key format, so its labels and
raw payload remain qrlft-specific.

**ML-DSA-87 (RFC 9881):**
```
-----BEGIN PRIVATE KEY-----
...base64 encoded PKCS#8 OneAsymmetricKey containing the seed...
-----END PRIVATE KEY-----

-----BEGIN PUBLIC KEY-----
...base64 encoded SubjectPublicKeyInfo...
-----END PUBLIC KEY-----
```

The algorithm remains required. When a PEM key file is supplied, its custom
header or, for standard ML-DSA files, its algorithm identifier is detected and
checked against `--algorithm`; a mismatch is rejected. Older qrlft ML-DSA files
with algorithm-specific labels remain readable for migration.

## ML-DSA-87 Context

ML-DSA-87 (FIPS 204) requires a context parameter for domain separation:

- Context is a string of 0-255 bytes
- Must be the same for signing and verification
- Signatures created with one context won't verify with another

```bash
# Sign with context
qrlft sign -a mldsa --context="myapp-v1" --keyfile=key doc.txt > doc.sig

# Verify with same context (succeeds)
qrlft verify -a mldsa --context="myapp-v1" --sigfile=doc.sig --pkfile=key.pub doc.txt

# Verify with different context (fails)
qrlft verify -a mldsa --context="different" --sigfile=doc.sig --pkfile=key.pub doc.txt
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success / Signature valid |
| 1 | Signature invalid |
| 61-84 | Various errors (missing args, file not found, etc.) |

## Large File Handling

**Hashing** uses streaming reads (64KB buffer) and can handle files of any size with constant memory usage.

**Signing and verification** require the entire file to be loaded into memory because the underlying Dilithium/ML-DSA algorithms need the complete message. For very large files, use the hash-then-sign approach:

```bash
# 1. Hash the large file (uses streaming - constant memory)
HASH=$(qrlft hash --sha3-512 --quiet largefile.bin)

# 2. Sign the hash (small string, minimal memory)
qrlft sign -a dilithium -s --hexseed=abc123... "$HASH" > largefile.sig

# 3. Verify: hash the file and verify the signature matches
HASH=$(qrlft hash --sha3-512 --quiet largefile.bin)
# Compare with the signed hash or verify programmatically
```

This approach is standard practice for signing large files and is used by tools like GPG.

## Security Considerations

- **Private key files** are created with `0600` permissions (owner read/write only)
- **Public key files** are created with `0644` permissions (world-readable)
- **Do not expose as a service**: This is a CLI tool designed for local use. Post-quantum cryptographic operations are computationally expensive. If you need to expose signing/verification as a service, implement proper rate limiting, authentication, and resource controls
- **Context for ML-DSA-87**: Always use a unique, application-specific context string to ensure domain separation between different uses of the same key

## Development checks

Run the complete local gate with `make check`. Coverage is ratcheted at 100%:
`make coverage` generates `coverage.out`, applies source-level exclusions with
the pinned `go-ignore-cov` version, and fails unless the processed profile is
exactly 100%. Every exclusion must use an approved reason from
`.coverage-reasons.yml` and include an adjacent `//rationale:` comment;
testable behavior must be covered by a test instead.

## License

MIT
