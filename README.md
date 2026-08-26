# qrlft - QRL File Tools

Command-line tools for quantum-resistant file signing, verification, and hashing using post-quantum cryptographic algorithms.

## Installation

### Pre-built binaries

Download the archive for your platform from the
[releases page](https://github.com/theQRL/qrlft/releases) and check it against
the published signatures (see [Verifying a Release](#verifying-a-release)).
Unzip it and move the `qrlft` binary onto your `PATH` — usually
`/usr/local/bin` on macOS and Linux, or any directory listed in `PATH` on
Windows — otherwise you have to invoke it by its full path.

### With Go

```bash
go install github.com/theQRL/qrlft/v4@latest
```

This installs into `$(go env GOPATH)/bin`, which must itself be on your `PATH`
for `qrlft` to resolve as a bare command.

### From source

```bash
git clone https://github.com/theQRL/qrlft
cd qrlft
go build
```

`go build` leaves the binary in the checkout, so either run it as `./qrlft` or
move it onto your `PATH` as above.

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

## Verifying a Release

Every release archive is signed in CI with ML-DSA-87 (FIPS 204). Each release
publishes a `qrlft_<tag>_signatures.txt` alongside the binaries, holding one
line per archive:

```
<hex signature> qrlft_v4.1.0_linux_amd64.zip
```

Release signatures use the context string **`qrlft-release-signatures`**. A
signature only verifies under that exact context, so it has to be passed on
every verification.

### Release public key

The signing key is checked in as [`qrlft-release-key.pub`](qrlft-release-key.pub):

```
-----BEGIN ML-DSA-87 PUBLIC KEY-----
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
-----END ML-DSA-87 PUBLIC KEY-----
```

### Checking an archive

Download the archive and the signatures file from the release, then pull out the
line for your archive and verify it. `--sigfile` expects a file holding nothing
but the signature, so the signatures file cannot be passed to it directly:

```bash
FILE=qrlft_v4.1.0_linux_amd64.zip
SIG=$(grep " $FILE\$" qrlft_v4.1.0_signatures.txt | cut -d' ' -f1)

qrlft verify -a mldsa \
  --context="qrlft-release-signatures" \
  --signature="$SIG" \
  --pkfile=qrlft-release-key.pub \
  "$FILE"
```

`Signature is valid` with exit code 0 means the archive is byte-for-byte what CI
built and signed. A modified archive, the wrong key, or a mistyped context all
print `Signature is not valid` and exit 1 — treat any of these as a failed
download and do not run the binary.

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
