import 'package:dsrp/defaults.dart';
import 'package:dsrp/dsrp.dart';
import 'package:test/test.dart';

import 'constants.dart';

// Python SRP library used for testing: https://github.com/cocagne/pysrp
void main() {
  const salt = [179, 213, 23, 45];

  group('createSaltedVerificationKey tests', () {
      test('generated verification key is same as pysrp', () async {
          const expectedVerifierKey = [38, 173, 182, 68, 210, 122, 188, 207, 48, 253, 137, 75, 207, 161, 251, 108, 245, 255, 167, 202, 206, 107, 158, 251, 195, 6, 65, 137, 17, 179, 102, 100, 132, 48, 113, 113, 254, 245, 45, 219, 237, 31, 6, 151, 191, 168, 83, 66, 207, 8, 199, 134, 190, 75, 220, 9, 64, 121, 240, 52, 222, 188, 154, 105, 197, 164, 250, 30, 23, 49, 82, 177, 226, 142, 206, 13, 62, 99, 124, 227, 216, 71, 207, 125, 238, 243, 140, 229, 240, 97, 59, 147, 196, 207, 25, 45, 131, 40, 142, 179, 207, 120, 248, 12, 44, 30, 132, 18, 146, 181, 40, 228, 93, 61, 150, 122, 135, 109, 223, 183, 117, 30, 161, 177, 76, 29, 39, 62];

          final verifierKey = await User.createSaltedVerificationKey(
            userId: username, password: password,
            generator: generator, safePrime: safePrime,
            kdf: kdfChoice,
            salt: salt);
          expect(verifierKey.salt, salt);
          expect(verifierKey.key, expectedVerifierKey);
      });

      test('generates different verifier when userId is excluded', () async {
          final verifierKeyWithUserId = await User.createSaltedVerificationKey(
            userId: username, password: password,
            generator: generator, safePrime: safePrime,
            kdf: kdfChoice,
            salt: salt);

          final verifierKeyWithoutUserId = await User.createSaltedVerificationKey(
            password: password,
            generator: generator, safePrime: safePrime,
            kdf: kdfChoice,
            salt: salt);
          
          expect(verifierKeyWithoutUserId.key, isNot(equals(verifierKeyWithUserId.key)));
      });

      test('verifier without userId is deterministic for same password and salt', () async {
          final verifierKey1 = await User.createSaltedVerificationKey(
            password: password,
            generator: generator, safePrime: safePrime,
            kdf: kdfChoice,
            salt: salt);

          final verifierKey2 = await User.createSaltedVerificationKey(
            password: password,
            generator: generator, safePrime: safePrime,
            kdf: kdfChoice,
            salt: salt);

          // Should generate same verifier when userId is not used.
          expect(verifierKey1.key, equals(verifierKey2.key));
      });

      test('generates random salt when not provided', () async {
          final verifierKey1 = await User.createSaltedVerificationKey(
            userId: username, password: password,
            generator: generator, safePrime: safePrime);
          final verifierKey2 = await User.createSaltedVerificationKey(
            userId: username, password: password,
            generator: generator, safePrime: safePrime);

          expect(verifierKey1.salt.length, defaultSaltByteLengthForSaltedVerificationKey);
          expect(verifierKey2.salt.length, defaultSaltByteLengthForSaltedVerificationKey);
          expect(verifierKey1.salt, isNot(equals(verifierKey2.salt)));
          expect(verifierKey1.key, isNot(equals(verifierKey2.key)));
      });

      test('uses default safe prime when not provided', () async {
          final verifierKey = await User.createSaltedVerificationKey(
            userId: username, password: password,
            generator: generator,
            salt: salt);

          expect(verifierKey.salt, salt);
          expect(verifierKey.key.length, greaterThan(0));
      });
  });

  group('User object tests', () {
      const userPrivateKey = [232, 70, 157, 38, 48, 237, 179, 190, 222, 91, 132, 27, 167, 190, 150, 98, 47, 119, 182, 249, 138, 180, 194, 124, 66, 153, 178, 125, 47, 149, 55, 73];
      const serverPublicKey = [48, 253, 127, 208, 252, 27, 19, 242, 204, 44, 60, 7, 136, 100, 251, 46, 140, 252, 127, 151, 252, 16, 29, 255, 246, 21, 160, 46, 124, 121, 153, 62, 73, 241, 233, 170, 173, 83, 15, 25, 245, 199, 107, 205, 73, 179, 55, 94, 238, 125, 99, 166, 95, 96, 178, 124, 155, 158, 137, 76, 225, 82, 97, 61, 235, 223, 232, 138, 218, 8, 109, 72, 165, 152, 87, 7, 48, 95, 52, 96, 73, 11, 65, 33, 181, 67, 197, 237, 4, 166, 56, 9, 140, 229, 191, 220, 134, 98, 44, 133, 87, 119, 57, 233, 229, 210, 96, 45, 217, 59, 192, 162, 229, 200, 32, 210, 5, 88, 76, 193, 104, 158, 238, 56, 142, 191, 86, 61];

      final challenge = Challenge(
        generator: generator, safePrime: safePrime,
        ephemeralServerPublicKey: serverPublicKey, verifierKeySalt: salt,
        hashFunction: hashFunctionChoice);

      late User user;

      setUp(() async {
          user = await User.fromUserCredsAndChallenge(
            userId: username, password: password, challenge: challenge,
            kdf: kdfChoice,
            ephemeralUserPrivateKey: userPrivateKey
          );
      });

      group('fromUserCredsAndChallenge factory tests', () {
          test('parameters are processed correctly', () {
              expect(user.generator.toInt(), generator);
              expect(user.safePrime.toByteList(), safePrime);
          });

          test('derived session key matches pysrp', () {
              final expectedSessionKey = [101, 63, 34, 246, 210, 134, 205, 205, 240, 205, 128, 100, 230, 168, 167, 194, 55, 91, 245, 230, 238, 184, 15, 28, 156, 136, 56, 1, 16, 196, 159, 25];

              expect(user.sessionKey, expectedSessionKey);
          });

          test('user session verifiers have expected values', () {
              const expectedUserPublicKey = [29, 113, 4, 60, 247, 47, 198, 246, 163, 32, 118, 226, 28, 13, 19, 229, 222, 253, 239, 86, 212, 251, 233, 233, 51, 204, 128, 73, 79, 249, 74, 249, 67, 146, 129, 247, 138, 26, 215, 37, 149, 5, 31, 174, 111, 111, 247, 182, 198, 246, 30, 215, 103, 100, 184, 188, 97, 197, 217, 193, 37, 158, 126, 188, 163, 74, 78, 110, 139, 10, 1, 206, 130, 233, 247, 169, 10, 183, 35, 60, 205, 167, 122, 124, 53, 99, 125, 24, 11, 16, 107, 18, 69, 135, 79, 9, 180, 7, 98, 27, 40, 225, 210, 216, 164, 162, 120, 175, 43, 244, 75, 138, 187, 116, 118, 112, 181, 21, 99, 121, 101, 244, 28, 125, 179, 50, 175, 120];
              final expectedSessionKeyVerifier = [112, 68, 29, 211, 34, 202, 76, 147, 231, 195, 23, 181, 197, 114, 154, 72, 227, 238, 18, 235, 59, 22, 61, 155, 143, 248, 68, 202, 125, 239, 103, 176];

              final userSessionVerifiers = user.getUserSessionVerifiers();

              expect(userSessionVerifiers.ephemeralUserPublicKey, expectedUserPublicKey);
              expect(userSessionVerifiers.sessionKeyVerifier, expectedSessionKeyVerifier);
          });

          test('generates random ephemeral private key when not provided', () async {
              final user1 = await User.fromUserCredsAndChallenge(
                userId: username, password: password, challenge: challenge);
              final user2 = await User.fromUserCredsAndChallenge(
                userId: username, password: password, challenge: challenge);

              final verifiers1 = user1.getUserSessionVerifiers();
              final verifiers2 = user2.getUserSessionVerifiers();

              expect(verifiers1.ephemeralUserPublicKey, isNot(equals(verifiers2.ephemeralUserPublicKey)));
          });

          test('session key and verifier changes when user id is not used to generate private key', () async {
              final user2 = await User.fromUserCredsAndChallenge(
                userId: username, password: password, challenge: challenge,
                kdf: kdfChoice,
                ephemeralUserPrivateKey: userPrivateKey,
                useUserIdInPrivateKey: false,
              );

              final verifiers1 = user.getUserSessionVerifiers();
              final verifiers2 = user2.getUserSessionVerifiers();

              expect(user2.sessionKey, isNot(equals(user.sessionKey)));
              // These should differ since the session key verifier is derived
              // from the session key.
              expect(verifiers2.sessionKeyVerifier, isNot(equals(verifiers1.sessionKeyVerifier)));
          });
      });

      group('getUserSessionVerifiers tests', () {
          test('returns correct userId', () {
              final userSessionVerifiers = user.getUserSessionVerifiers();
              expect(userSessionVerifiers.userId, username);
          });
      });

      group('verifySession tests', () {
          final serverSessionKeyVerifier = [11, 114, 210, 88, 9, 28, 238, 168, 77, 158, 32, 102, 43, 253, 72, 248, 164, 73, 231, 6, 105, 181, 76, 144, 203, 230, 220, 199, 102, 215, 28, 255];

          test('verification passes for correct server verifier and session key matches pysrp', () async {
              await user.verifySession(serverSessionKeyVerifier);
          });

          test('verification fails for incorrect server verifier', () {
              expect(user.verifySession(serverSessionKeyVerifier + [1, 2, 3, 4]),
                throwsA(isA<AuthenticationFailure>()));
          });
      });
  });


}
