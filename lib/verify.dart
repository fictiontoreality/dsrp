/// Methods to verify SRP primitives are secure.
///
/// Primarily useful for users to verify SRP primitives provided by a server are
/// secure.
///
/// SRP primitives include:
/// - safe prime
/// - generator
library;

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
void verifySafePrime(BigInt safePrime, int minimumBitLength) {
  // Check if N is prime
  if (!isProbablyPrime(safePrime)) {
    throw InvalidParameterException('Provided "safe prime" is likely not prime.');
  }

  // Check if q = (N - 1) / 2 is also prime
  final sophieGermainPrime = (safePrime - BigInt.one) ~/ BigInt.two;
  if (!isProbablyPrime(sophieGermainPrime)) {
    throw InvalidParameterException('The Sophie Germain prime of the provided "safe prime" is not prime.');
  }

  // Verify the relationship N = 2q + 1
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
