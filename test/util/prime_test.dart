import 'package:dsrp/util/prime.dart';
import 'package:test/test.dart';

void main() {
  group('isProbablyPrime tests', () {
    test('identifies small primes correctly', () {
      expect(isProbablyPrime(BigInt.from(2)), true);
      expect(isProbablyPrime(BigInt.from(3)), true);
      expect(isProbablyPrime(BigInt.from(5)), true);
      expect(isProbablyPrime(BigInt.from(7)), true);
      expect(isProbablyPrime(BigInt.from(11)), true);
      expect(isProbablyPrime(BigInt.from(13)), true);
      expect(isProbablyPrime(BigInt.from(17)), true);
      expect(isProbablyPrime(BigInt.from(19)), true);
      expect(isProbablyPrime(BigInt.from(23)), true);
      expect(isProbablyPrime(BigInt.from(29)), true);
      expect(isProbablyPrime(BigInt.from(31)), true);
    });

    test('identifies small composites correctly', () {
      expect(isProbablyPrime(BigInt.from(0)), false);
      expect(isProbablyPrime(BigInt.from(1)), false);
      expect(isProbablyPrime(BigInt.from(4)), false);
      expect(isProbablyPrime(BigInt.from(6)), false);
      expect(isProbablyPrime(BigInt.from(8)), false);
      expect(isProbablyPrime(BigInt.from(9)), false);
      expect(isProbablyPrime(BigInt.from(10)), false);
      expect(isProbablyPrime(BigInt.from(12)), false);
      expect(isProbablyPrime(BigInt.from(14)), false);
      expect(isProbablyPrime(BigInt.from(15)), false);
      expect(isProbablyPrime(BigInt.from(16)), false);
    });

    test('identifies larger primes correctly', () {
      // First few hundred-digit primes.
      expect(isProbablyPrime(BigInt.from(97)), true);
      expect(isProbablyPrime(BigInt.from(101)), true);
      expect(isProbablyPrime(BigInt.from(103)), true);
      expect(isProbablyPrime(BigInt.from(107)), true);
      expect(isProbablyPrime(BigInt.from(109)), true);

      // Larger primes.
      expect(isProbablyPrime(BigInt.from(1009)), true);
      expect(isProbablyPrime(BigInt.from(10007)), true);
    });

    test('identifies larger composites correctly', () {
      expect(isProbablyPrime(BigInt.from(100)), false);
      expect(isProbablyPrime(BigInt.from(1000)), false);
      expect(isProbablyPrime(BigInt.from(10000)), false);

      // Products of two primes.
      expect(isProbablyPrime(BigInt.from(77)), false); // 7 * 11
      expect(isProbablyPrime(BigInt.from(91)), false); // 7 * 13
      expect(isProbablyPrime(BigInt.from(143)), false); // 11 * 13
    });

    test('identifies Sophie Germain primes correctly', () {
      // Sophie Germain primes: primes p where 2p+1 is also prime.
      final sophieGermainPrimes = [2, 3, 5, 11, 23, 29, 41, 53, 83, 89];

      for (final p in sophieGermainPrimes) {
        final pBig = BigInt.from(p);
        expect(isProbablyPrime(pBig), true, reason: '$p should be prime');

        final safePrime = BigInt.from(2) * pBig + BigInt.one;
        expect(isProbablyPrime(safePrime), true,
            reason: '2*$p+1 = $safePrime should be prime');
      }
    });

    test('identifies RFC5054 1024-bit safe prime correctly', () {
      // From RFC5054 Appendix A.
      final safePrime = BigInt.parse(
        'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C'
        '9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4'
        '8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29'
        '7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A'
        'FD5138FE8376435B9FC61D2FC0EB06E3',
        radix: 16
      );

      expect(isProbablyPrime(safePrime), true);

      // Verify it's a safe prime.
      final sophieGermainPrime = (safePrime - BigInt.one) ~/ BigInt.two;
      expect(isProbablyPrime(sophieGermainPrime), true);
    });

    test('works with custom round counts', () {
      final prime = BigInt.from(97);
      final composite = BigInt.from(100);

      // With fewer rounds.
      expect(isProbablyPrime(prime, rounds: 5), true);
      expect(isProbablyPrime(composite, rounds: 5), false);

      // With more rounds (slower but more certain).
      expect(isProbablyPrime(prime, rounds: 40), true);
      expect(isProbablyPrime(composite, rounds: 40), false);
    });

    test('handles negative numbers correctly', () {
      expect(isProbablyPrime(BigInt.from(-1)), false);
      expect(isProbablyPrime(BigInt.from(-2)), false);
      expect(isProbablyPrime(BigInt.from(-7)), false);
    });

    test('handles very large primes', () {
      // A known large prime (2^127 - 1, a Mersenne prime).
      final largePrime = BigInt.two.pow(127) - BigInt.one;
      expect(isProbablyPrime(largePrime), true);

      // A known large composite.
      final largeComposite = BigInt.two.pow(100);
      expect(isProbablyPrime(largeComposite), false);
    });
  });
}
