import 'package:dsrp/hash.dart';
import 'package:dsrp/kdf.dart';

/// Balance between compatibility, speed and security.
///
/// No performance penalty on 32-bit systems, unlike SHA512. Avoids SHA1
/// vulnerability to pre-image attacks that could eventually be exploited in a
/// brute-force-on-the-verifier scenario.
final defaultHashAlgorithmChoice = HashAlgorithmChoice.sha256;

/// Intentionally slow and memory intensive to optimize for protection from
/// brute-force attempts to derive the password from the verifier.
final defaultKdfAlgorithmChoice = KdfAlgorithmChoice.sha256;
//TODO: Switch default to Argon2id.
// final defaultKdfAlgorithmChoice = KdfAlgorithmChoice.arg2id;

/// 2 is the standard generator from RFC5054.
///
/// Computationally efficient (just a left shift). Does not have to match the
/// generator used to create the safe prime. You must verify g^q mod p ≠ 1
/// (where g = this generator, p = large safe prime, q = (p-1)/2) to ensure it
/// is a generator of the large order-q subgroup.
final defaultGenerator = BigInt.from(2);

/// 2048-bit safe prime generated using scripts/generate_safe_primes.
///
/// IT IS RECOMMENDED TO GENERATE YOUR OWN SAFE PRIMES FOR ADDED SECURITY.
///
/// By not reusing a published safe prime (such as one from RFC5054), odds are
/// reduced that the prime has been integrated into pre-computed attack methods.
final defaultSafePrime = BigInt.parse('ef0e3dc9ba1d254350c23c3d13dc91d6243d3701dcd1fd7ec084b3bebc0e0eb9b3bd795e7fc0b30b606a6ee5a8482eee75843fc63c1a5f309d40f6b4b544b6a69b3d778949dd16d857c29b3803e0538972427d95c59d74a147777aaff3ef9b397c64423bbdbc039e57960ecc9079ec14f5bbfe455baf7a8edb6cc7ce85973379941d81221601171add5c2a7292b5e03c97d2f1a08345c182843372ecd6072ebdac0dc64b5bcdae93bca495a67454ad38ecc0b9fc2fab3a2723bf2ebdb9418b92684152caba282159c0d20f4514ea8b6c7613f4d3ac3cef1ee4046283cd4003088d928dd8337c7c5391c75a26e1ab49c372ddf2f702f7f9a7226cad4572e39d53', radix: 16);

/// Balance of security and performance.
///
/// Going beyond this length is largely harmless, though probably does not
/// improve security appreciably.
final defaultSaltByteLengthForSaltedVerificationKey = 32;

/// Balance of security and performance.
///
/// Should match the byte length of the safe prime.
/// In this case 512 bytes = 4096 bit length prime.
final defaultByteLengthForEphemeralKeys = 512;
