<!--
This README describes the package. If you publish this package to pub.dev,
this README's contents appear on the landing page for your package.

For information about how to write a good package README, see the guide for
[writing package pages](https://dart.dev/guides/libraries/writing-package-pages).

For general information about developing packages, see the Dart guide for
[creating packages](https://dart.dev/guides/libraries/create-library-packages)
and the Flutter guide for
[developing packages and plugins](https://flutter.dev/developing-packages).
-->

dsrp is a pure Dart implementation of the [Secure Remote Password (SRP)](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)
user authentication protocol.

SRP allows a user to authenticate with a server without ever passing
password-equivalent information to the server, avoiding a large class
of man-in-the-middle attacks.

## Features

* implements both user and server side of authentication.
* allows custom safe primes and generators to be used to decrease chance of pre-computed brute force attacks.
* fully interopable with [pysrp](https://github.com/cocagne/pysrp), a Python SRP library.

## Getting started

Simply add dsrp to your Dart or Flutter project's `pubspec.yaml`:

```
dependencies:
   dsrp: ^0.0.1
```

## Usage

SRP is divided into two phases:

1. Registration, where the user registers a username and associated salted verification key with a server.
2. Authentication, where user and server both derive and mutually
   authenticate session keys which are used to encrypt all further
   communication between the two (in addition to TLS and other
   encryption).

```dart
// Registration.
final user = User(userId: "fakeuserid", password: "fakepassword");
final saltedVerificationKey = await user.createSaltedVerificationKey();

// Authentication.
final startAuthData = user.startAuthentication();

final server = Server(
  userId: startAuthData.userId,
  salt: saltedVerificationKey.salt,
  verifierKey: saltedVerificationKey.key,
  ephemeralUserPublicKey: startAuthData.ephemeralUserPublicKey,
);
final challenge = await server.createChallenge();

final userSessionKeyVerifier =
    await user.processChallenge(challenge.salt, challenge.ephemeralServerPublicKey);

// At this point all further messages between user and server should be encrypted using the session key (e.g., user.getSessionKey(), server.getSessionKey()), in addition to TLS or other encryption.

final serverSessionKeyVerifier = await server.verifySession(userSessionKeyVerifier);

await user.verifySession(serverSessionKeyVerifier);
```
This and other usage examples are in the `/examples` folder.

## Security Best Practices

### Generate Safe Primes

Pre-published safe primes such as those published in RFC5054 have
likely been incorporated into pre-computed attacks, which may
significantly reduce the compute time needed to infer the user
password and break SFC encryption from eons to hours or even minutes.

Thus it is recommended to generate and use your own safe primes.

A Python 3 script is included for generating safe primes. See the [README in `scripts/generate_safe_primes`](scripts/generate_safe_primes/README.md) for details.

### Erase Sensitive Data

1. **Use [Uint8List] for sensitive data**: Unlike [String], [Uint8List] can
   be zeroed out after use to prevent sensitive data from lingering in
   memory. Always call [overwriteWithZeros()] on the resulting bytes when
   done.

2. **Minimize string lifetime**: Convert strings to bytes as early as
   possible and zero them out as soon as they're no longer needed.

3. **Avoid string copies**: Strings are immutable in Dart and cannot be
   securely erased from memory. The original string may persist in memory
   until garbage collected.

**Example:**
```dart
// Convert `password` string obtained from form to bytes, 
// or more ideally use a secure form that directly stores 
// the password as bytes to avoid relying no the garbage 
// collector to delete the string.
final passwordBytes = password.utf8Bytes;
// Remove the password String reference so it can be gargbage collected.
password = "";

// Use the bytes for cryptographic operations.
final saltedKey = await User.createSaltedVerificationKey(
  userId: 'alice',
  password: passwordBytes,
);

// Zero out sensitive data when done.
passwordBytes.overwriteWithZeros();
```

**Sensitive data examples:**
- Passwords
- Passphrases
- Secret keys
- User identifiers (if privacy-sensitive)
- Any sensitive string data used in cryptographic operations

## Additional Information

TODO: Tell users more about the package: where to find more information, how to
contribute to the package, how to file issues, what response they can expect
from the package authors, and more.
