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
