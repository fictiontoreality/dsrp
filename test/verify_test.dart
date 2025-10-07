import 'package:dsrp/verify.dart';
import 'package:test/test.dart';

void main() {
  group('verifySafePrime tests', () {
    test('accepts valid safe primes', () {
      // Small safe primes: N = 2q + 1 where both N and q are prime.
      final safePrimes = [
        5,   // q = 2
        7,   // q = 3
        11,  // q = 5
        23,  // q = 11
        47,  // q = 23
        59,  // q = 29
        83,  // q = 41
        107, // q = 53
      ];

      for (final p in safePrimes) {
        expect(
          () => verifySafePrime(BigInt.from(p), 2),
          returnsNormally,
          reason: '$p should be accepted as a safe prime'
        );
      }
    });

    test('rejects non-prime numbers', () {
      final composites = [4, 6, 8, 9, 10, 12, 15, 16, 20, 21];

      for (final n in composites) {
        expect(
          () => verifySafePrime(BigInt.from(n), 2),
          throwsA(anything),
          reason: '$n should be rejected (not prime)'
        );
      }
    });

    test('rejects primes that are not safe primes', () {
      // These are primes, but (N-1)/2 is not prime.
      final nonSafePrimes = [
        13, // q = 6 = 2*3
        17, // q = 8 = 2^3
        19, // q = 9 = 3^2
        29, // q = 14 = 2*7
        31, // q = 15 = 3*5
        37, // q = 18 = 2*9
      ];

      for (final p in nonSafePrimes) {
        expect(
          () => verifySafePrime(BigInt.from(p), 2),
          throwsA(anything),
          reason: '$p should be rejected (not a safe prime)'
        );
      }
    });

    test('accepts RFC5054 1024-bit safe prime', () {
      final safePrime = BigInt.parse(
        'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C'
        '9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4'
        '8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29'
        '7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A'
        'FD5138FE8376435B9FC61D2FC0EB06E3',
        radix: 16
      );

      expect(
        () => verifySafePrime(safePrime, 1024),
        returnsNormally
      );
    });

    test('rejects safe primes below minimum bit length', () {
      final safePrime = BigInt.from(11); // 4-bit safe prime

      expect(
        () => verifySafePrime(safePrime, 8),
        throwsA(anything)
      );

      expect(
        () => verifySafePrime(safePrime, 16),
        throwsA(anything)
      );
    });

    test('accepts safe primes at exact minimum bit length', () {
      final safePrime = BigInt.from(11); // 4-bit safe prime

      expect(
        () => verifySafePrime(safePrime, 4),
        returnsNormally
      );
    });

    test('accepts safe primes above minimum bit length', () {
      final safePrime = BigInt.from(107); // 7-bit safe prime

      expect(
        () => verifySafePrime(safePrime, 4),
        returnsNormally
      );
    });

    test('rejects even numbers', () {
      expect(
        () => verifySafePrime(BigInt.from(2), 2),
        throwsA(anything)
      );

      expect(
        () => verifySafePrime(BigInt.from(100), 7),
        throwsA(anything)
      );
    });

    test('rejects zero and one', () {
      expect(
        () => verifySafePrime(BigInt.zero, 1),
        throwsA(anything)
      );

      expect(
        () => verifySafePrime(BigInt.one, 1),
        throwsA(anything)
      );
    });

    test('rejects negative numbers', () {
      expect(
        () => verifySafePrime(BigInt.from(-7), 3),
        throwsA(anything)
      );

      expect(
        () => verifySafePrime(BigInt.from(-11), 4),
        throwsA(anything)
      );
    });
  });

  group('verifyGenerator tests', () {
    test('accepts valid generators for safe primes', () {
      // For safe prime 11 (q=5), generator 2 is valid.
      final safePrime = BigInt.from(11);
      final generator = BigInt.from(2);

      expect(
        () => verifyGenerator(generator, safePrime),
        returnsNormally
      );
    });

    test('accepts generator 2 for RFC5054 1024-bit safe prime', () {
      final safePrime = BigInt.parse(
        'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C'
        '9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4'
        '8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29'
        '7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A'
        'FD5138FE8376435B9FC61D2FC0EB06E3',
        radix: 16
      );
      final generator = BigInt.from(2);

      expect(
        () => verifyGenerator(generator, safePrime),
        returnsNormally
      );
    });

    test('rejects generator less than 2', () {
      final safePrime = BigInt.from(11);

      expect(
        () => verifyGenerator(BigInt.zero, safePrime),
        throwsA(anything)
      );

      expect(
        () => verifyGenerator(BigInt.one, safePrime),
        throwsA(anything)
      );
    });

    test('rejects generator equal to or greater than safe prime', () {
      final safePrime = BigInt.from(11);

      expect(
        () => verifyGenerator(BigInt.from(11), safePrime),
        throwsA(anything)
      );

      expect(
        () => verifyGenerator(BigInt.from(12), safePrime),
        throwsA(anything)
      );

      expect(
        () => verifyGenerator(BigInt.from(100), safePrime),
        throwsA(anything)
      );
    });

    test('rejects generator that only generates trivial subgroup', () {
      // For safe prime 11, generator 10 generates trivial subgroup
      // because 10^2 mod 11 = 1.
      final safePrime = BigInt.from(11);
      final generator = BigInt.from(10);

      expect(
        () => verifyGenerator(generator, safePrime),
        throwsA(anything)
      );
    });

    test('rejects generator that does not generate full subgroup', () {
      // For safe prime 23 (q=11), some generators don't work properly.
      final safePrime = BigInt.from(23);

      // Generator 22: 22^11 mod 23 = 1, so it doesn't generate full subgroup
      final badGenerator = BigInt.from(22);

      expect(
        () => verifyGenerator(badGenerator, safePrime),
        throwsA(anything)
      );
    });

    test('rejects composite generators', () {
      // Even if g^q mod N != 1, we want prime generators.
      final safePrime = BigInt.from(23);
      final compositeGenerator = BigInt.from(4); // 2^2

      expect(
        () => verifyGenerator(compositeGenerator, safePrime),
        throwsA(anything)
      );
    });

    test('rejects negative generators', () {
      final safePrime = BigInt.from(11);

      expect(
        () => verifyGenerator(BigInt.from(-2), safePrime),
        throwsA(anything)
      );
    });

    test('accepts multiple valid generators for same safe prime', () {
      final safePrime = BigInt.from(23);

      // Multiple generators can be valid for the same safe prime.
      final validGenerators = [2, 3, 5, 7, 11];

      for (final g in validGenerators) {
        final generator = BigInt.from(g);
        final q = (safePrime - BigInt.one) ~/ BigInt.two;

        // Only test if g is prime and g^q mod N != 1.
        if (generator.modPow(q, safePrime) != BigInt.one) {
          expect(
            () => verifyGenerator(generator, safePrime),
            returnsNormally,
            reason: 'Generator $g should be valid for safe prime 23'
          );
        }
      }
    });

    test('works with large safe primes and generators', () {
      // Use a smaller but still large safe prime for testing.
      final safePrime = BigInt.from(167); // 8-bit safe prime (q=83)
      final generator = BigInt.from(5);

      expect(
        () => verifyGenerator(generator, safePrime),
        returnsNormally
      );
    });
  });

  group('integration tests', () {
    test('verifies complete SRP parameter set', () {
      final safePrime = BigInt.from(23);
      final generator = BigInt.from(5);
      final minimumBitLength = 4;

      // Verify both safe prime and generator.
      expect(() {
        verifySafePrime(safePrime, minimumBitLength);
        verifyGenerator(generator, safePrime);
      }, returnsNormally);
    });

    test('rejects invalid parameter combinations', () {
      final notSafePrime = BigInt.from(17); // prime but not safe
      final minimumBitLength = 4;

      // Safe prime verification should fail.
      expect(
        () => verifySafePrime(notSafePrime, minimumBitLength),
        throwsA(anything)
      );

      // Even if we skip safe prime check, generator check should ideally fail
      // (though it might pass if g^q mod N != 1 by chance).
    });

    test('verifies RFC5054 Appendix A parameters', () {
      // RFC5054 1024-bit group parameters.
      final safePrime = BigInt.parse(
        'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C'
        '9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4'
        '8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29'
        '7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A'
        'FD5138FE8376435B9FC61D2FC0EB06E3',
        radix: 16
      );
      final generator = BigInt.from(2);
      final minimumBitLength = 1024;

      expect(() {
        verifySafePrime(safePrime, minimumBitLength);
        verifyGenerator(generator, safePrime);
      }, returnsNormally);
    });
  });
}
