import 'package:cryptography/cryptography.dart';
import 'package:dsrp/dsrp.dart';
import 'package:test/test.dart';

import './constants.dart';

// Python SRP library used for testing: https://github.com/cocagne/pysrp

void main() {
  final user = User(
    userId: username,
    password: password,
    hashAlgorithm: Sha256()
  );

  group('generateSaltedVerificationKey tests', () {
      test('generated verification key is same as pysrp', () async {
          const salt = [179, 213, 23, 45];
          const expectedVerificationKey = [38, 173, 182, 68, 210, 122, 188, 207, 48, 253, 137, 75, 207, 161, 251, 108, 245, 255, 167, 202, 206, 107, 158, 251, 195, 6, 65, 137, 17, 179, 102, 100, 132, 48, 113, 113, 254, 245, 45, 219, 237, 31, 6, 151, 191, 168, 83, 66, 207, 8, 199, 134, 190, 75, 220, 9, 64, 121, 240, 52, 222, 188, 154, 105, 197, 164, 250, 30, 23, 49, 82, 177, 226, 142, 206, 13, 62, 99, 124, 227, 216, 71, 207, 125, 238, 243, 140, 229, 240, 97, 59, 147, 196, 207, 25, 45, 131, 40, 142, 179, 207, 120, 248, 12, 44, 30, 132, 18, 146, 181, 40, 228, 93, 61, 150, 122, 135, 109, 223, 183, 117, 30, 161, 177, 76, 29, 39, 62];

          final saltedVerificationKey = await user.createSaltedVerificationKey(salt: salt);
          expect(saltedVerificationKey.salt, salt);
          expect(saltedVerificationKey.key, expectedVerificationKey);
      });
  });

  group('startAuthentication tests', () {
      test('epehemeral public user key matches pysrp', () {
          final ephemeralPrivateUserKey = [232, 70, 157, 38, 48, 237, 179, 190, 222, 91, 132, 27, 167, 190, 150, 98, 47, 119, 182, 249, 138, 180, 194, 124, 66, 153, 178, 125, 47, 149, 55, 73];
          final expectedEphemeralPublicUserKey = [29, 113, 4, 60, 247, 47, 198, 246, 163, 32, 118, 226, 28, 13, 19, 229, 222, 253, 239, 86, 212, 251, 233, 233, 51, 204, 128, 73, 79, 249, 74, 249, 67, 146, 129, 247, 138, 26, 215, 37, 149, 5, 31, 174, 111, 111, 247, 182, 198, 246, 30, 215, 103, 100, 184, 188, 97, 197, 217, 193, 37, 158, 126, 188, 163, 74, 78, 110, 139, 10, 1, 206, 130, 233, 247, 169, 10, 183, 35, 60, 205, 167, 122, 124, 53, 99, 125, 24, 11, 16, 107, 18, 69, 135, 79, 9, 180, 7, 98, 27, 40, 225, 210, 216, 164, 162, 120, 175, 43, 244, 75, 138, 187, 116, 118, 112, 181, 21, 99, 121, 101, 244, 28, 125, 179, 50, 175, 120];

          final startAuthData = user.startAuthentication(ephemeralPrivateUserKeyBytes: ephemeralPrivateUserKey);
          expect(startAuthData.userId, username);
          expect(startAuthData.ephemeralPublicUserKey, expectedEphemeralPublicUserKey);
      });
  });
}
