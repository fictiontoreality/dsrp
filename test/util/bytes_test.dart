import 'package:dsrp/util/bytes.dart';
import 'package:test/test.dart';

void main() {
  const bigByteList = [38, 173, 182, 68, 210, 122, 188, 207, 48, 253, 137, 75, 207, 161, 251, 108, 245, 255, 167, 202, 206, 107, 158, 251, 195, 6, 65, 137, 17, 179, 102, 100, 132, 48, 113, 113, 254, 245, 45, 219, 237, 31, 6, 151, 191, 168, 83, 66, 207, 8, 199, 134, 190, 75, 220, 9, 64, 121, 240, 52, 222, 188, 154, 105, 197, 164, 250, 30, 23, 49, 82, 177, 226, 142, 206, 13, 62, 99, 124, 227, 216, 71, 207, 125, 238, 243, 140, 229, 240, 97, 59, 147, 196, 207, 25, 45, 131, 40, 142, 179, 207, 120, 248, 12, 44, 30, 132, 18, 146, 181, 40, 228, 93, 61, 150, 122, 135, 109, 223, 183, 117, 30, 161, 177, 76, 29, 39, 62];
  const bigIntString = '27161010228836201331794825814212254193412576883239767951010568973113419272749595606994713559795908054476552975892723087928625289263682048688813889302265953405632407054280819018447028773187430846708335340490516628767589465122742382585417552365747410579614567450681640564993422830344268086482846053665685186366';
  final bigInt = BigInt.parse(bigIntString);

  group('convertByteListToBigInt tests', () {
    test('can convert large byte list', () {
      final result = convertByteListToBigInt(bigByteList);
      expect(result.toString(), bigIntString);
    });

    test('converts empty list to zero', () {
      final result = convertByteListToBigInt([]);
      expect(result, BigInt.zero);
    });

    test('converts single byte correctly', () {
      expect(convertByteListToBigInt([0]), BigInt.zero);
      expect(convertByteListToBigInt([1]), BigInt.one);
      expect(convertByteListToBigInt([255]), BigInt.from(255));
      expect(convertByteListToBigInt([128]), BigInt.from(128));
    });

    test('converts two bytes correctly', () {
      // [1, 0] = 256
      expect(convertByteListToBigInt([1, 0]), BigInt.from(256));
      // [1, 1] = 257
      expect(convertByteListToBigInt([1, 1]), BigInt.from(257));
      // [255, 255] = 65535
      expect(convertByteListToBigInt([255, 255]), BigInt.from(65535));
    });

    test('handles leading zeros correctly', () {
      // Leading zeros should not affect the value.
      expect(
        convertByteListToBigInt([0, 0, 0, 1]),
        BigInt.one
      );
      expect(
        convertByteListToBigInt([0, 0, 1, 0]),
        BigInt.from(256)
      );
    });

    test('converts small numbers correctly', () {
      expect(convertByteListToBigInt([10]), BigInt.from(10));
      expect(convertByteListToBigInt([100]), BigInt.from(100));
      expect(convertByteListToBigInt([200]), BigInt.from(200));
    });

    test('is big-endian', () {
      // Big-endian means most significant byte first.
      // [1, 2, 3] should be 1*256^2 + 2*256 + 3 = 66051.
      expect(
        convertByteListToBigInt([1, 2, 3]),
        BigInt.from(66051)
      );
    });
  });

  group('convertBigIntToByteList tests', () {
    test('can convert large BigInt', () {
      final byteList = convertBigIntToByteList(bigInt);
      expect(byteList, bigByteList);
    });

    test('converts zero to single zero byte', () {
      final result = convertBigIntToByteList(BigInt.zero);
      expect(result, [0]);
    });

    test('converts one to single byte', () {
      final result = convertBigIntToByteList(BigInt.one);
      expect(result, [1]);
    });

    test('converts single byte values correctly', () {
      expect(convertBigIntToByteList(BigInt.from(255)), [255]);
      expect(convertBigIntToByteList(BigInt.from(128)), [128]);
      expect(convertBigIntToByteList(BigInt.from(10)), [10]);
    });

    test('converts two byte values correctly', () {
      // 256 = [1, 0]
      expect(convertBigIntToByteList(BigInt.from(256)), [1, 0]);
      // 257 = [1, 1]
      expect(convertBigIntToByteList(BigInt.from(257)), [1, 1]);
      // 65535 = [255, 255]
      expect(convertBigIntToByteList(BigInt.from(65535)), [255, 255]);
    });

    test('produces minimal byte representation', () {
      // Should not have leading zeros.
      final result = convertBigIntToByteList(BigInt.from(256));
      expect(result, [1, 0]); // Not [0, 1, 0]
      if (result.isNotEmpty) {
        expect(result.first, isNonZero);
      }
    });

    test('is big-endian', () {
      // 66051 = 1*256^2 + 2*256 + 3 = [1, 2, 3]
      expect(
        convertBigIntToByteList(BigInt.from(66051)),
        [1, 2, 3]
      );
    });

    test('handles large primes correctly', () {
      // RFC5054 1024-bit safe prime.
      final safePrime = BigInt.parse(
        'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C'
        '9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4'
        '8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29'
        '7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A'
        'FD5138FE8376435B9FC61D2FC0EB06E3',
        radix: 16
      );

      final bytes = convertBigIntToByteList(safePrime);
      expect(bytes.length, greaterThanOrEqualTo(127)); // ~1024 bits
      expect(bytes.length, lessThanOrEqualTo(128));
      if (bytes.isNotEmpty) {
        expect(bytes.first, isNonZero); // No leading zeros.
      }
    });
  });

  group('round-trip conversion tests', () {
    test('BigInt -> bytes -> BigInt preserves value', () {
      final testValues = [
        BigInt.zero,
        BigInt.one,
        BigInt.from(255),
        BigInt.from(256),
        BigInt.from(65535),
        BigInt.from(1000000),
        bigInt,
      ];

      for (final value in testValues) {
        final bytes = convertBigIntToByteList(value);
        final recovered = convertByteListToBigInt(bytes);
        expect(recovered, value, reason: 'Failed for value: $value');
      }
    });

    test('bytes -> BigInt -> bytes preserves canonical form', () {
      final testCases = [
        [0],    // zero
        [1],
        [255],
        [1, 0],
        [1, 2, 3],
        [255, 255, 255],
        bigByteList,
      ];

      for (final bytes in testCases) {
        final value = convertByteListToBigInt(bytes);
        final recovered = convertBigIntToByteList(value);

        // The recovered bytes should equal original if original has no leading
        // zeros (except for [0] itself).
        if (bytes.first != 0 || bytes.length == 1) {
          expect(recovered, bytes, reason: 'Failed for bytes: $bytes');
        }
      }
    });

    test('zero round-trips correctly', () {
      // Zero should convert to [0] and back
      final bytes = [0];
      final value = convertByteListToBigInt(bytes);
      expect(value, BigInt.zero);

      final recovered = convertBigIntToByteList(value);
      expect(recovered, [0]); // Zero is represented as [0]

      // Also test the other direction
      expect(BigInt.zero.toByteList().toBigInt(), BigInt.zero);
    });

    test('zero converts to [0] not []', () {
      // This is the correct behavior for cryptographic applications
      // Empty list would mean "no data", not "value is zero"
      final zeroBytes = BigInt.zero.toByteList();

      expect(zeroBytes, [0], reason: 'Zero should be [0], not []');
      expect(zeroBytes, isNotEmpty, reason: 'Zero representation should not be empty');
      expect(zeroBytes.length, 1, reason: 'Zero should be exactly one byte');

      // Verify round-trip
      expect(zeroBytes.toBigInt(), BigInt.zero);
    });

    test('demonstrates symmetry between conversions', () {
      // [0] -> BigInt.zero -> [0] (symmetric)
      expect([0].toBigInt(), BigInt.zero);
      expect(BigInt.zero.toByteList(), [0]);

      // This symmetry is important for cryptographic correctness
      final testCases = {
        BigInt.zero: [0],
        BigInt.one: [1],
        BigInt.from(255): [255],
        BigInt.from(256): [1, 0],
      };

      testCases.forEach((bigInt, expectedBytes) {
        expect(bigInt.toByteList(), expectedBytes);
        expect(expectedBytes.toBigInt(), bigInt);
      });
    });
  });

  group('generateRandomBytes tests', () {
    test('generates requested number of bytes', () {
      expect(generateRandomBytes(0).length, 0);
      expect(generateRandomBytes(1).length, 1);
      expect(generateRandomBytes(10).length, 10);
      expect(generateRandomBytes(100).length, 100);
      expect(generateRandomBytes(1024).length, 1024);
    });

    test('generates different values on successive calls', () {
      final bytes1 = generateRandomBytes(32);
      final bytes2 = generateRandomBytes(32);
      final bytes3 = generateRandomBytes(32);

      // Very unlikely to be equal
      expect(bytes1, isNot(equals(bytes2)));
      expect(bytes2, isNot(equals(bytes3)));
      expect(bytes1, isNot(equals(bytes3)));
    });

    test('generates values in valid byte range', () {
      final bytes = generateRandomBytes(1000);
      for (final byte in bytes) {
        expect(byte, greaterThanOrEqualTo(0));
        expect(byte, lessThanOrEqualTo(255));
      }
    });

    test('generates reasonably distributed values', () {
      // Generate many bytes and check distribution
      final bytes = generateRandomBytes(10000);

      // Count occurrences of 0 and 255
      final count0 = bytes.where((b) => b == 0).length;
      final count255 = bytes.where((b) => b == 255).length;

      // With uniform distribution, expect about 39 occurrences of each (10000/256)
      // Allow wide range to avoid flaky tests
      expect(count0, greaterThan(10));
      expect(count0, lessThan(100));
      expect(count255, greaterThan(10));
      expect(count255, lessThan(100));
    });
  });

  group('generateRandomBigInt tests', () {
    test('generates values in specified range', () {
      final min = BigInt.from(100);
      final max = BigInt.from(200);

      for (var i = 0; i < 100; i++) {
        final result = generateRandomBigInt(min, max);
        expect(result, greaterThanOrEqualTo(min));
        expect(result, lessThanOrEqualTo(max));
      }
    });

    test('generates different values on successive calls', () {
      final min = BigInt.zero;
      final max = BigInt.from(1000000);

      final results = <BigInt>{};
      for (var i = 0; i < 50; i++) {
        results.add(generateRandomBigInt(min, max));
      }

      // Should have generated many different values.
      expect(results.length, greaterThan(40));
    });

    test('works with single value range', () {
      final value = BigInt.from(42);
      final result = generateRandomBigInt(value, value);
      expect(result, value);
    });

    test('works with small ranges', () {
      // Range [0, 1] should give 0 or 1.
      for (var i = 0; i < 100; i++) {
        final result = generateRandomBigInt(BigInt.zero, BigInt.one);
        expect(result, anyOf(BigInt.zero, BigInt.one));
      }
    });

    test('works with large ranges', () {
      final min = BigInt.zero;
      final max = BigInt.two.pow(256);

      final result = generateRandomBigInt(min, max);
      expect(result, greaterThanOrEqualTo(min));
      expect(result, lessThanOrEqualTo(max));
    });

    test('handles very large values', () {
      final min = BigInt.two.pow(1000);
      final max = BigInt.two.pow(1001);

      final result = generateRandomBigInt(min, max);
      expect(result, greaterThanOrEqualTo(min));
      expect(result, lessThanOrEqualTo(max));
    });
  });

  group('extension method tests', () {
    test('BigIntToByteList extension works', () {
      expect(BigInt.zero.toByteList(), [0]);
      expect(BigInt.one.toByteList(), [1]);
      expect(BigInt.from(256).toByteList(), [1, 0]);
    });

    test('ByteListToBigInt extension works', () {
      expect([0].toBigInt(), BigInt.zero);
      expect([1].toBigInt(), BigInt.one);
      expect([1, 0].toBigInt(), BigInt.from(256));
    });

    test('extension methods are inverses', () {
      final originalBigInt = BigInt.from(12345);
      expect(originalBigInt.toByteList().toBigInt(), originalBigInt);

      final originalBytes = [1, 2, 3, 4, 5];
      expect(originalBytes.toBigInt().toByteList(), originalBytes);
    });
  });
}
