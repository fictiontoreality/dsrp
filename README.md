# dsrp

A pure Dart implementation of the [Secure Remote Password (SRP-6a)](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol) protocol for secure user authentication.

SRP allows password-based authentication without transmitting password-equivalent information to the server, protecting against man-in-the-middle attacks and server database breaches.

## Features

* **Zero-knowledge password proof** - Server never receives password or password-equivalent data.
* **Pure Dart** - Works on all Dart platforms (Flutter mobile, web, desktop, and server).
* **Mutual authentication** - Both client and server verify each other's identity.
* **Secure session keys** - Generates shared symmetric keys for encrypted communication to optionally supplement other encryption layers such as TLS.
* **RFC5054 compliant** - compatible with SRP-6a, the most widely adopted standard for SRP.
* **Customizable cryptography** - Support for multiple hash algorithms (SHA256, SHA512, SHA1) and KDFs (Argon2id, PBKDF2).
* **Custom safe primes** - Generate your own primes to reduce vulnerability to pre-computed attacks.
* **Memory security** - Uses `Uint8List` for passwords with secure erasure via `overwriteWithZeros()`.
* **Python interoperability** - Fully compatible with [pysrp](https://github.com/cocagne/pysrp) library.

## Installation

Add `dsrp` to your `pubspec.yaml`:

```yaml
dependencies:
  dsrp: ^0.0.1
```

Then run:
```bash
dart pub get
```

If using with Flutter, you can add the [`cryptography_flutter` package](https://github.com/dint-dev/cryptography/tree/master/cryptography_flutter) for platform-specific performance optimizations:

```
dependencies:
  cryptography_flutter: ^2.3.2
```

## Usage

SRP authentication consists of two phases:

### 1. Registration Phase

The user creates a salted verification key from their credentials and sends it to the server for storage:

```dart
import 'package:dsrp/dsrp.dart';

// User creates salted verification key from password
final saltedVerificationKey = await User.createSaltedVerificationKey(
  userId: 'alice',
  password: 'secure-password-123',
);

// Send saltedVerificationKey.key and saltedVerificationKey.salt to server.
// Server stores these for future authentication.
```

### 2. Authentication Phase

The user and server mutually authenticate and derive a shared session key, all
without the user ever sending their password to the server:

```dart
// 1. User requests challenge from server (sends userId).
final server = Server(
  userId: 'alice',
  salt: saltedVerificationKey.salt,        // Retrieved from database
  verifierKey: saltedVerificationKey.key,  // Retrieved from database
);
final challenge = await server.createChallenge();

// 2. User processes challenge and generates session verifiers.
final user = await User.fromUserCredsAndChallenge(
  userId: 'alice',
  password: 'secure-password-123',
  challenge: challenge,
);
final userSessionVerifiers = user.getUserSessionVerifiers();

// 3. Server verifies user and generates server verifier.
final serverSessionKeyVerifier = await server.verifySession(
  ephemeralUserPublicKey: userSessionVerifiers.ephemeralUserPublicKey,
  userSessionKeyVerifier: userSessionVerifiers.sessionKeyVerifier,
);

// 4. User verifies server (throws exception if verification fails).
await user.verifySession(serverSessionKeyVerifier);

// 5. Both parties now have identical symmetric session keys for encrypted communication.
final userSessionKey = user.sessionKey;
final serverSessionKey = server.sessionKey;
// userSessionKey == serverSessionKey
```

**Note**: Session keys supplement but do not replace TLS encryption. Always use TLS for transport security.

A complete working example is in [examples/srp.dart](examples/srp.dart): 

```
dart examples/srp.dart
```

## Security Best Practices

### 1. Generate Custom Safe Primes (Critical for Production)

**⚠️ Default primes are NOT recommended for production use.**

The default safe prime from RFC5054 may be vulnerable to pre-computed attacks. For production deployments, generate your own custom safe primes.

See [`scripts/generate_safe_primes/README.md`](scripts/generate_safe_primes/README.md) for details.

### 2. Use Strong Key Derivation Functions

The default KDF is Argon2id, which is memory-hard and recommended for password-based key derivation. Alternative KDFs (PBKDF2-SHA256, PBKDF2-SHA512) are available but less secure against brute-force attacks.

### 3. SRP Complements, Not Replaces, TLS

SRP provides authentication and session key derivation. **Always use TLS** or similar for transport encryption. SRP session keys can be used for additional application-layer encryption if needed.

### 4. Handle Sensitive Data Securely

**Best Practice**: Use `Uint8List` for passwords instead of `String` to enable secure memory erasure.

Unlike `String` (which is immutable), `Uint8List` can be zeroed out after use to prevent sensitive data from lingering in memory:

```dart
// Method 1: Use the utf8Bytes extension for convenience.
final passwordBytes = password.utf8Bytes;
password = ""; // Clear string reference for garbage collection.

final saltedKey = await User.createSaltedVerificationKeyFromBytes(
  userIdBytes: 'alice'.utf8Bytes,
  passwordBytes: passwordBytes,
);

// Zero out sensitive data when done. Does not rely on GC timing.
passwordBytes.overwriteWithZeros();
saltedKey.erase();

// Method 2: String-based API (simpler but potentially less secure).
final saltedKey = await User.createSaltedVerificationKey(
  userId: 'alice',
  password: 'secure-password-123', // String persists until GC
);
```

**Key principles:**
- Convert strings to bytes as early as possible.
- Remove references to strings as soon as possible to allow them to be garbage collected, e.g. `password = ""` or `password = null` .
- Zero out byte arrays when no longer needed using `.overwriteWithZeros()`.
- Use `.erase()` methods on SRP objects (`SaltedVerificationKey`, `Challenge`, `UserSessionVerifiers`) when they are no longer needed.
- Strings cannot be securely erased like byte arrays can - use byte-based APIs (`createSaltedVerificationKeyFromBytes`, `fromUserCredsBytesAndChallenge`) for maximum security, especially if strings can be avoided entirely.

**Sensitive data examples:**
- Passwords
- Private keys
- User IDs (if privacy-sensitive)

## Additional Resources

- **Examples**: See [examples/srp.dart](examples/srp.dart) for a complete authentication flow
- **API Documentation**: Full API docs available at [pub.dev](https://pub.dev/documentation/dsrp/latest/)
- **Issues**: Report bugs at the [issue tracker](https://github.com/YOUR_USERNAME/dsrp/issues)
- **RFC5054**: [SRP specification](https://datatracker.ietf.org/doc/html/rfc5054)

## Contributions

TODO: See [CONTRIBUTION.md](CONTRIBUTION.md).

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
