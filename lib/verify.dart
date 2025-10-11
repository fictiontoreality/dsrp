/// Methods to verify SRP primitives are secure.
///
/// Primarily useful for users to verify SRP primitives provided by a server are
/// secure.
///
/// SRP primitives include:
/// - safe prime
/// - generator
/// - salt
/// - ephemeral keys
library;

import 'dart:typed_data';
import 'package:dsrp/exceptions.dart';
import 'package:dsrp/util/prime.dart';

/// Verifies that a number is a safe prime.
///
/// A safe prime N is a prime number of the form N = 2q + 1, where q is also
/// prime (q is called a Sophie Germain prime).
///
/// Note: This uses a probabilistic primality test (Miller-Rabin) which is
/// computationally efficient but has a very small chance of false positives.
/// For cryptographic applications, this is generally acceptable.
///
/// **Parameters:**
/// - [safePrime]: The number to verify as a safe prime.
/// - [minimumBitLength]: Minimum required bit length for the safe prime (recommended: ≥ 2048).
///
/// **Throws:**
/// - [InvalidParameterException] if the number is not prime, not a safe prime,
///   or has insufficient bit length.
void verifySafePrime(BigInt safePrime, int minimumBitLength) {
  // Check if N is prime
  if (!isProbablyPrime(safePrime)) {
    throw InvalidParameterException('Provided "safe prime" is likely not prime.');
  }

  // Check if q = (N - 1) / 2 is also prime.
  final sophieGermainPrime = (safePrime - BigInt.one) ~/ BigInt.two;
  if (!isProbablyPrime(sophieGermainPrime)) {
    throw InvalidParameterException('The Sophie Germain prime of the provided "safe prime" is not prime.');
  }

  // Verify the relationship N = 2q + 1.
  if (safePrime != BigInt.two * sophieGermainPrime + BigInt.one) {
    throw InvalidParameterException('Provided "safe prime" does not have a Sophie Germain prime.');
  }

  // Verifies that a safe prime has the required bit length.
  //
  // A safe prime should use all bits of the specified length, with the highest
  // bit set to 1 to ensure it is sufficiently large.
  if (safePrime.bitLength < minimumBitLength) {
    throw InvalidParameterException('Safe prime has bit length ${safePrime.bitLength} which is less than the minimum bit length of $minimumBitLength.');
  }
}

/// Verifies that a generator is valid for the given safe prime.
///
/// For a safe prime N = 2q + 1, a generator g must satisfy:
///   g^q mod N ≠ 1
///
/// This ensures g generates the large order-q subgroup, which is required
/// for SRP security.
///
/// Note: This uses a probabilistic primality test (Miller-Rabin) which is
/// computationally efficient but has a very small chance of false positives.
/// For cryptographic applications, this is generally acceptable.
///
/// **Parameters:**
/// - [generator]: The generator value to verify (typically 2 or 5).
/// - [safePrime]: The safe prime N that the generator should work with.
///
/// **Throws:**
/// - [InvalidParameterException] if the generator is out of range, not prime,
///   or does not generate the correct subgroup.
void verifyGenerator(BigInt generator, BigInt safePrime) {
  if (generator < BigInt.two || generator >= safePrime) {
    throw InvalidParameterException('Generator $generator is out of range 2 <= generator <= safe prime.');
  }

  if (!isProbablyPrime(generator)) {
    throw InvalidParameterException('Generator $generator is unlikely to be prime.');
  }

  // q = (N - 1) / 2
  final q = (safePrime - BigInt.one) ~/ BigInt.two;

  // Check g^2 mod N ≠ 1
  if (generator.modPow(BigInt.from(2), safePrime) == BigInt.one) {
    throw InvalidParameterException('Generator $generator only generates the trivial subgroup of the safe prime.');
  }
  // Check g^q mod N ≠ 1
  if (generator.modPow(q, safePrime) == BigInt.one) {
    throw InvalidParameterException('Generator $generator does not generate the full subgroup of the safe prime.');
  }
}

/// Minimum recommended byte length for salts to ensure sufficient entropy.
///
/// 16 bytes (128 bits) is the minimum recommended by NIST and other standards
/// to prevent rainbow table and brute-force attacks.
const int minimumRecommendedSaltByteLength = 16;

/// Verifies that a salt meets security requirements.
///
/// A salt must meet the minimum recommended length (16 bytes / 128 bits by
/// default).
///
/// The minimum length can be overridden with [minimumByteLength], but values
/// below 16 bytes are not recommended for production use.
///
/// **Parameters:**
/// - [salt]: The salt bytes to verify.
/// - [minimumByteLength]: Minimum required byte length (default: 16 bytes / 128 bits).
///
/// **Throws:**
/// - [InvalidParameterException] if the salt is shorter than the minimum length.
void verifySalt(Uint8List salt, {int minimumByteLength = minimumRecommendedSaltByteLength}) {
  if (salt.length < minimumByteLength) {
    throw InvalidParameterException(
      'Salt length (${salt.length} bytes) is below the recommended minimum '
      '($minimumByteLength bytes). This may be cryptographically insecure.'
    );
  }
}

/// Verifies that an ephemeral public key is valid.
///
/// An ephemeral public key (A for user, B for server) must not be zero
/// modulo the safe prime (i.e., key % N ≠ 0). This prevents certain attacks
/// where an attacker can force the session key to a known value.
///
/// **Parameters:**
/// - [publicKey]: The ephemeral public key to verify (A for user, B for server).
/// - [safePrime]: The safe prime N used in the SRP exchange.
/// - [keyName]: Descriptive name for error messages (e.g., 'A (user)' or 'B (server)').
///
/// **Throws:**
/// - [InvalidParameterException] if the key is invalid (key % N == 0),
///   which may indicate an attack attempt.
void verifyEphemeralKey(BigInt publicKey, BigInt safePrime, String keyName) {
  if (publicKey % safePrime == BigInt.zero) {
    throw InvalidParameterException(
      'Ephemeral public key $keyName is invalid ($keyName % N == 0). '
      'This may indicate an attack attempt.'
    );
  }
}
