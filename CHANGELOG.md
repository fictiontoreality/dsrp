## 0.5.5

Migrate from Codeberg to Github.

This was done in part to ease contribution, but also because Github has better
security advisory features, especially important for security-focused packages
like this one.

## 0.5.4

Fix README installation instructions.

## 0.5.3

- Fix README links.
- Minor improvements to documentation and release script.

## 0.5.2

Minor changes to improve package score.

Also adds a release script (`scripts/release`) to guardrail future releases
prior to publishing.

## 0.5.1

Fixes ASCII sequence diagram formatting in README.

## 0.5.0

Initial beta release. Has been tested in production with pysrp server interop
for several years, but could use wider testing before a 1.0 release, especially
from those using Dart server-side.

### Features
- Pure Dart SRP-6a protocol implementation
- Client and server authentication
- Multiple KDF algorithms (Argon2id, PBKDF2-SHA256/512, SHA1)
- Multiple hash algorithms (SHA1, SHA256, SHA512)
- Safe prime and generator verification
- Interoperable with pysrp Python library
- Secure memory handling with Uint8List for passwords
- Defensive copying to prevent state mutation

### Security
- Passwords stored as Uint8List and zeroed after use
- Input validation for cryptographic parameters
- Protection against timing attacks via constant-time operations where possible

### Documentation
- Comprehensive API documentation
- Security best practices guide
- Usage examples for common scenarios
