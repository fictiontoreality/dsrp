/// Utilities related to prime numbers.
library;

import 'package:dsrp/util/bytes.dart';

/// Performs a probabilistic primality test using the Miller-Rabin algorithm.
///
/// This implementation uses 20 rounds by default, which gives a probability
/// of error less than (1/4)^20 ≈ 9 × 10^-13. This level of certainty is
/// acceptable for cryptographic applications.
///
/// **Parameters:**
/// - [n]: The number to test for primality
/// - [rounds]: Number of Miller-Rabin test rounds (default: 20, higher = more certain)
///
/// **Returns:** `true` if n is probably prime, `false` if n is definitely composite
///
/// **Note:** This is a probabilistic test. A result of `true` means the number
/// is very likely prime (but not guaranteed), while `false` means it is
/// definitely not prime.
bool isProbablyPrime(BigInt n, {int rounds = 20}) {
  if (n < BigInt.two) return false;
  if (n == BigInt.two || n == BigInt.from(3)) return true;
  if (n.isEven) return false;

  // Write n - 1 as 2^r * d.
  BigInt d = n - BigInt.one;
  int r = 0;
  while (d.isEven) {
    d ~/= BigInt.two;
    r++;
  }

  // Witness loop.
  for (int i = 0; i < rounds; i++) {
    final a = generateRandomBigInt(BigInt.two, n - BigInt.two);
    BigInt x = a.modPow(d, n);

    if (x == BigInt.one || x == n - BigInt.one) {
      continue;
    }

    bool continueWitnessLoop = false;
    for (int j = 0; j < r - 1; j++) {
      x = x.modPow(BigInt.two, n);
      if (x == n - BigInt.one) {
        continueWitnessLoop = true;
        break;
      }
    }

    if (continueWitnessLoop) {
      continue;
    }

    return false;
  }

  return true;
}
