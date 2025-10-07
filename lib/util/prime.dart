/// Utilities related to prime numbers.
library;

import 'package:dsrp/util/bytes.dart';

/// Performs a probabilistic primality test (Miller-Rabin).
///
/// This implementation uses 20 rounds, which gives a probability of error
/// less than (1/4)^20 ≈ 9 × 10^-13.
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
