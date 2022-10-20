import 'package:cryptography/cryptography.dart';
import 'package:dsrp/dsrp.dart';
import 'package:test/test.dart';

import './constants.dart';

// Python SRP library used for testing: https://github.com/cocagne/pysrp

void main() {
  final user = User();

  group('generateSaltedVerificationKey tests', () {
      test('generated verification key is same as pysrp', () async {
          const salt = [179, 213, 23, 45];
          const expectedVerificationKey = [38, 173, 182, 68, 210, 122, 188, 207, 48, 253, 137, 75, 207, 161, 251, 108, 245, 255, 167, 202, 206, 107, 158, 251, 195, 6, 65, 137, 17, 179, 102, 100, 132, 48, 113, 113, 254, 245, 45, 219, 237, 31, 6, 151, 191, 168, 83, 66, 207, 8, 199, 134, 190, 75, 220, 9, 64, 121, 240, 52, 222, 188, 154, 105, 197, 164, 250, 30, 23, 49, 82, 177, 226, 142, 206, 13, 62, 99, 124, 227, 216, 71, 207, 125, 238, 243, 140, 229, 240, 97, 59, 147, 196, 207, 25, 45, 131, 40, 142, 179, 207, 120, 248, 12, 44, 30, 132, 18, 146, 181, 40, 228, 93, 61, 150, 122, 135, 109, 223, 183, 117, 30, 161, 177, 76, 29, 39, 62];

          final saltedVerificationKey = await user.createSaltedVerificationKey(
            USERNAME, PASSWORD, hashAlgorithm: Sha256(), salt: salt);
          expect(saltedVerificationKey.salt, salt);
          expect(saltedVerificationKey.key, expectedVerificationKey);
      });
  });
}
