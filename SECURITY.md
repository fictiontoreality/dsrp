# Security Policy

## Overview

Security is a critical priority for dsrp, a cryptographic library implementing the Secure Remote Password (SRP) protocol. We take all security vulnerabilities seriously and appreciate your efforts to responsibly disclose your findings.

## Supported Versions

We provide security updates for the following versions:

| Version      | Supported          |
|--------------|--------------------|
| 0.5.x (beta) | :white_check_mark: |
| < 0.5        | :x:                |

**Note:** Once version 1.0.0 is released, we will support the latest major version and provide critical security fixes for the last beta version for 6 months.

## Reporting a Vulnerability

**⚠️ IMPORTANT: Do NOT report security vulnerabilities through public Codeberg issues, discussions, or pull requests.**

### Private Disclosure Process

To report a security vulnerability:

1. **Email the maintainers directly** at the email address listed in the [pubspec.yaml](pubspec.yaml) or repository settings.

2. **Include the following information:**
   - Description of the vulnerability.
   - Steps to reproduce the issue.
   - Affected versions.
   - Potential impact.
   - Any suggested fixes (if you have them).
   - Your contact information for follow-up.

3. **Use encryption (optional but recommended):**
   - If you have a PGP key for the maintainer, encrypt your report.
   - This ensures sensitive details remain confidential.

### What to Expect

After you submit a report:

- **Acknowledgment**: We will try to acknowledge receipt within 48 hours.
- **Initial assessment**: We will provide an initial assessment within 5 business days.
- **Updates**: We will keep you informed of our progress.
- **Coordinated disclosure**: We will work with you to understand the issue and develop a fix.
- **Credit**: We will credit you in the security advisory (unless you prefer to remain anonymous).

### Disclosure Timeline

Our goal is to address security issues promptly:

1. **Critical vulnerabilities**: Fix within 7 days, release within 14 days
2. **High severity**: Fix within 14 days, release within 30 days
3. **Medium/Low severity**: Fix in next regular release cycle

We ask that you:
- Give us reasonable time to address the issue before public disclosure.
- Avoid exploiting the vulnerability or sharing it with others.
- Do not access, modify, or delete data that doesn't belong to you.

## Security Best Practices for Users

When using dsrp in your application, follow these security best practices:

### 1. Generate Custom Safe Primes (Critical)

**⚠️ The default safe prime is NOT recommended for production use.**

```dart
// DON'T: Use default safe prime in production
final saltedKey = await User.createSaltedVerificationKey(
  password: password,
);

// DO: Generate and use custom safe primes
final customPrime = // ... generated using scripts/generate_safe_primes
final saltedKey = await User.createSaltedVerificationKey(
  password: password,
  safePrime: customPrime,
);
```

**Why:** Widely-used safe primes may be targets for pre-computed attacks. Custom primes significantly increase attacker costs.

**How:** Use the script in `scripts/generate_safe_primes/` to generate your own 2048-bit (or larger) safe prime.

### 2. Use Strong Key Derivation Functions

```dart
// DO: Use Argon2id (default and recommended)
final saltedKey = await User.createSaltedVerificationKey(
  password: password,
  kdf: KdfChoice.argon2id, // Memory-hard, GPU-resistant
);

// DON'T: Use fast hash-based KDFs in production
final saltedKey = await User.createSaltedVerificationKey(
  password: password,
  kdf: KdfChoice.sha256, // Fast to compute = vulnerable to brute-force
);
```

**Why:** Slow, memory-hard KDFs like Argon2id make brute-force attacks on compromised verification keys computationally infeasible.

### 3. Always Use TLS/HTTPS

**⚠️ SRP is NOT a replacement for TLS.**

```dart
// DO: Use SRP over TLS/HTTPS
final response = await https.post(
  Uri.https('api.example.com', '/auth/challenge'),
  body: jsonEncode(verifiers.toJson()),
);

// DON'T: Send SRP data over unencrypted HTTP
final response = await http.post( // ❌ Insecure!
  Uri.http('api.example.com', '/auth/challenge'),
  body: jsonEncode(verifiers.toJson()),
);
```

**Why:** SRP provides zero-knowledge password proof and mutual authentication, but TLS is still needed to:
- Prevent man-in-the-middle attacks during the handshake
- Protect session keys and verifiers in transit
- Provide transport-layer security

### 4. Handle Sensitive Data Securely

```dart
// DO: Use Uint8List for passwords and zero them out.
final passwordBytes = password.utf8Bytes;
password = null; // Allow GC.

final saltedKey = await User.createSaltedVerificationKeyFromBytes(
  passwordBytes: passwordBytes,
);

passwordBytes.overwriteWithZeros(); // Erase from memory.
saltedKey.erase(); // Erase after sending to server.

// DON'T: Use String-based APIs without cleanup.
final saltedKey = await User.createSaltedVerificationKey(
  password: password, // String lingers in memory until GC.
);
password = null; // Delayed GC. No way to immediately securely erase.
```

**Why:** Strings are immutable in Dart and cannot be securely erased. Uint8List can be overwritten with zeros to prevent sensitive data from lingering in memory.

### 5. Validate Cryptographic Parameters

When receiving SRP parameters from a server (especially in a challenge), validate them:

```dart
final challenge = Challenge.fromJson(serverResponse);

// Validate parameters before using them
verifySafePrime(challenge.safePrime, 2048); // Minimum 2048 bits
verifyGenerator(challenge.generator, challenge.safePrime);
verifySalt(challenge.verifierKeySalt); // Minimum 16 bytes

// Only proceed if validation passes
final user = await User.fromUserCredsAndChallenge(
  userId: userId,
  password: password,
  challenge: challenge,
);
```

**Why:** Malicious servers could provide weak parameters to compromise security. Always validate before use.

### 6. Use Strong Passwords

SRP does not make weak passwords secure. Enforce strong password requirements following [2025 NIST guideliness](https://proton.me/blog/nist-password-guidelines):

- Minimum 8 characters (16+ recommended, up to 64).
- Password length and uniqueness is far more important than character complexity.
- Blocklist known breached passwords, patterns, and common variations.
- Do not reuse across services.
- Consider MFA and password managers.

### 7. Protect Stored Verification Keys

Server-side storage of verification keys:

- Treat verification keys like password hashes.
- Store in a secure database with access controls.
- Never log verification keys.
- Never send them back to users after registration.
- Use parameterized queries to prevent SQL injection.
- Implement rate limiting on authentication endpoints.

### 8. Implement Proper Error Handling

```dart
// DO: Generic error messages for authentication failures
try {
  await server.verifySession(
    userSessionKeyVerifier: verifier,
    ephemeralUserPublicKey: publicKey,
  );
} catch (e) {
  // Generic message - don't reveal whether user exists or password is wrong
  return Response.unauthorized('Authentication failed');
}

// DON'T: Reveal specific failure reasons
catch (e) {
  if (e is UserNotFoundException) {
    return 'User does not exist'; // ❌ Leaks information
  }
  if (e is AuthenticationFailure) {
    return 'Invalid password'; // ❌ Confirms user exists
  }
}
```

**Why:** Specific error messages can leak information about valid usernames, helping attackers enumerate accounts.

## Known Security Considerations

### Current Limitations

1. **Timing Attacks**: While we use constant-time operations where possible in the cryptography library, perfect timing attack resistance is difficult in high-level languages. For maximum security, implement rate limiting and consider additional protections at the network layer.

2. **Memory Safety**: Dart's garbage collector determines when objects are freed. We provide `.overwriteWithZeros()` for immediate erasure of sensitive data, but this doesn't prevent all memory disclosure vectors.

3. **Default Safe Prime**: The included default safe prime is for testing/development only. Production deployments should generate custom safe primes.

### Attack Mitigations

| Attack Type | Mitigation |
|-------------|------------|
| Brute-force on verifier | Use Argon2id KDF (default) |
| Pre-computed attacks | Generate custom safe primes |
| Man-in-the-middle | Always use TLS/HTTPS |
| Timing attacks | Use constant-time operations where possible, implement rate limiting |
| Memory disclosure | Use Uint8List with `.overwriteWithZeros()` |
| Invalid parameters | Validate all cryptographic parameters |
| User enumeration | Return generic error messages |

## Cryptographic Algorithm Choices

### Recommended (Production)

- **KDF**: Argon2id (memory-hard, GPU-resistant)
- **Hash**: SHA-256 (balance of security and performance)
- **Safe Prime**: Custom generated 2048-bit or 4096-bit prime
- **Generator**: 2 (standard, efficient)
- **Salt**: 32 bytes (256 bits)

### Not Recommended (Compatibility Only)

- **KDF**: SHA-1, SHA-256, SHA-512 hash-based KDFs (fast = vulnerable)
- **Hash**: SHA-1 (cryptographically weak, use only for RFC5054 compatibility)
- **Safe Prime**: Default or RFC5054 primes (may be pre-computed)

## References

- [RFC 5054: Using the Secure Remote Password (SRP) Protocol for TLS Authentication](https://datatracker.ietf.org/doc/html/rfc5054)
- [RFC 2945: The SRP Authentication and Key Exchange System](https://datatracker.ietf.org/doc/html/rfc2945)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf)

## Security Updates

Security updates will be announced through:

1. Codeberg Security Advisories
2. Release notes on pub.dev
3. CHANGELOG.md in the repository

Subscribe to repository releases to be notified of security updates.

---

Thank you for helping keep dsrp and its users secure!
