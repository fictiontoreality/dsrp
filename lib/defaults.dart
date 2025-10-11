import 'package:dsrp/crypto/hash.dart';
import 'package:dsrp/crypto/kdf.dart';

/// Default hash function choice for SRP operations.
///
/// SHA-256 provides a balance between compatibility, speed and security:
/// - No performance penalty on 32-bit systems (unlike SHA-512).
/// - Avoids SHA-1 vulnerabilities to pre-image attacks.
/// - Widely supported and well-tested.
///
/// You can override this by specifying a different [HashFunctionChoice] when
/// creating [User] or [Server] instances.
const defaultHashFunctionChoice = HashFunctionChoice.sha256;

/// Default key derivation function (KDF) choice for password-based key derivation.
///
/// Argon2id is intentionally slow and memory-intensive to protect against
/// brute-force attempts to derive passwords from verification keys:
/// - Memory-hard design resists GPU and ASIC attacks.
/// - Winner of the 2015 Password Hashing Competition.
/// - Recommended by security experts for password hashing.
///
/// You can override this by specifying a different [KdfChoice] when calling
/// [User.createSaltedVerificationKey] or [User.fromUserCredsAndChallenge].
const defaultKdfChoice = KdfChoice.argon2id;

/// Default generator for SRP group operations.
///
/// The value 2 is the standard generator from RFC5054. It offers:
/// - Computational efficiency (modular exponentiation is just a left shift).
/// - Does not have to match the generator used to create the safe prime.
/// - Widely supported in SRP implementations.
///
/// **Note:** When using a custom safe prime with this generator, you must verify
/// that g^q mod N ≠ 1 (where g = 2, N = safe prime, q = (N-1)/2) to ensure
/// it generates the large order-q subgroup. Use [verifyGenerator] for this.
///
/// You can override this by specifying a custom generator when creating [User]
/// or [Server] instances.
final defaultGenerator = BigInt.from(2);

/// Default 2048-bit safe prime for SRP operations.
///
/// **⚠️ WARNING: NOT RECOMMENDED FOR PRODUCTION USE.**
///
/// This safe prime was generated using `scripts/generate_safe_primes` and is
/// provided for testing and development purposes only.
///
/// **For production deployments, generate your own safe prime** using
/// the script in `scripts/generate_safe_primes/`. Using a custom safe prime
/// reduces the risk that attackers have pre-computed attack tables for this
/// well-known prime.
///
/// **Security rationale:**
/// - Widely-used safe primes (like those from RFC5054 or this default) may be
///   targets for pre-computed attacks.
/// - Custom primes significantly increase the computational cost for attackers.
/// - 2048-bit length is currently considered secure for most applications.
///
/// Generate a custom safe prime and provide it when creating [User] or [Server]
/// instances for production use.
final defaultSafePrime = BigInt.parse('ef0e3dc9ba1d254350c23c3d13dc91d6243d3701dcd1fd7ec084b3bebc0e0eb9b3bd795e7fc0b30b606a6ee5a8482eee75843fc63c1a5f309d40f6b4b544b6a69b3d778949dd16d857c29b3803e0538972427d95c59d74a147777aaff3ef9b397c64423bbdbc039e57960ecc9079ec14f5bbfe455baf7a8edb6cc7ce85973379941d81221601171add5c2a7292b5e03c97d2f1a08345c182843372ecd6072ebdac0dc64b5bcdae93bca495a67454ad38ecc0b9fc2fab3a2723bf2ebdb9418b92684152caba282159c0d20f4514ea8b6c7613f4d3ac3cef1ee4046283cd4003088d928dd8337c7c5391c75a26e1ab49c372ddf2f702f7f9a7226cad4572e39d53', radix: 16);

/// Default salt length for salted verification keys (32 bytes / 256 bits).
///
/// This provides a balance of security and performance:
/// - 32 bytes (256 bits) provides excellent protection against rainbow table attacks.
/// - Exceeds NIST's minimum recommendation of 16 bytes (128 bits).
/// - Going beyond this length is largely harmless but provides diminishing returns.
///
/// This salt is used during user registration when creating the verification key.
/// A random salt of this length is generated automatically if not provided to
/// [User.createSaltedVerificationKey].
const defaultSaltByteLengthForSaltedVerificationKey = 32;

/// Derives the optimal byte length for ephemeral keys based on safe prime size.
///
/// This function returns a byte length that matches the safe prime's bit length,
/// optimizing for security with negligible performance impact. Ephemeral keys
/// of this length provide maximum security for the given safe prime.
///
/// **Parameters:**
/// - [safePrimeBitLength]: Bit length of the safe prime (e.g., 2048 for a 2048-bit prime).
///
/// **Returns:** Optimal byte length for ephemeral keys (safePrimeBitLength / 8).
///
/// For example, a 2048-bit safe prime would result in 256-byte ephemeral keys.
int deriveOptimalByteLengthForEphemeralKeys(int safePrimeBitLength) {
  return safePrimeBitLength ~/ 8;
}
