import 'package:dsrp/dsrp.dart';
import 'package:test/test.dart';

import 'constants.dart';

// Python SRP library used for testing: https://github.com/cocagne/pysrp
void main() {
  const salt = [179, 213, 23, 45];
  const verifierKey = [38, 173, 182, 68, 210, 122, 188, 207, 48, 253, 137, 75, 207, 161, 251, 108, 245, 255, 167, 202, 206, 107, 158, 251, 195, 6, 65, 137, 17, 179, 102, 100, 132, 48, 113, 113, 254, 245, 45, 219, 237, 31, 6, 151, 191, 168, 83, 66, 207, 8, 199, 134, 190, 75, 220, 9, 64, 121, 240, 52, 222, 188, 154, 105, 197, 164, 250, 30, 23, 49, 82, 177, 226, 142, 206, 13, 62, 99, 124, 227, 216, 71, 207, 125, 238, 243, 140, 229, 240, 97, 59, 147, 196, 207, 25, 45, 131, 40, 142, 179, 207, 120, 248, 12, 44, 30, 132, 18, 146, 181, 40, 228, 93, 61, 150, 122, 135, 109, 223, 183, 117, 30, 161, 177, 76, 29, 39, 62];

  group('Server object tests', () {
    const serverPrivateKey = [249, 172, 205, 98, 151, 175, 247, 226, 73, 122, 213, 193, 100, 74, 31, 109, 129, 146, 171, 18, 219, 111, 139, 9, 43, 164, 171, 1, 17, 251, 155, 217];
    const userPublicKey = [29, 113, 4, 60, 247, 47, 198, 246, 163, 32, 118, 226, 28, 13, 19, 229, 222, 253, 239, 86, 212, 251, 233, 233, 51, 204, 128, 73, 79, 249, 74, 249, 67, 146, 129, 247, 138, 26, 215, 37, 149, 5, 31, 174, 111, 111, 247, 182, 198, 246, 30, 215, 103, 100, 184, 188, 97, 197, 217, 193, 37, 158, 126, 188, 163, 74, 78, 110, 139, 10, 1, 206, 130, 233, 247, 169, 10, 183, 35, 60, 205, 167, 122, 124, 53, 99, 125, 24, 11, 16, 107, 18, 69, 135, 79, 9, 180, 7, 98, 27, 40, 225, 210, 216, 164, 162, 120, 175, 43, 244, 75, 138, 187, 116, 118, 112, 181, 21, 99, 121, 101, 244, 28, 125, 179, 50, 175, 120];

    late Server server;

    setUp(() {
      server = Server(
        userId: username,
        salt: salt,
        verifierKey: verifierKey,
        generator: BigInt.from(generator),
        safePrime: safePrime,
        hashAlgorithm: hashAlgorithmChoice,
      );
    });

    group('Server constructor tests', () {
      test('parameters are processed correctly', () {
        expect(server.generator.toInt(), generator);
        expect(server.safePrime.toByteList(), safePrime);
        expect(server.hashAlgorithmChoice, hashAlgorithmChoice);
      });

      test('uses default generator when not provided', () {
        final serverWithDefaults = Server(
          userId: username,
          salt: salt,
          verifierKey: verifierKey,
        );
        expect(serverWithDefaults.generator.toInt(), 2);
      });
    });

    group('createChallenge tests', () {
      test('creates challenge with expected values', () async {
        final challenge = await server.createChallenge(
          ephemeralServerPrivateKeyBytes: serverPrivateKey,
        );

        expect(challenge.generator, generator);
        expect(challenge.safePrime, safePrime);
        expect(challenge.verifierKeySalt, salt);
        expect(challenge.hashAlgorithm, hashAlgorithmChoice);
      });

      test('generated server public key matches pysrp', () async {
        const expectedServerPublicKey = [48, 253, 127, 208, 252, 27, 19, 242, 204, 44, 60, 7, 136, 100, 251, 46, 140, 252, 127, 151, 252, 16, 29, 255, 246, 21, 160, 46, 124, 121, 153, 62, 73, 241, 233, 170, 173, 83, 15, 25, 245, 199, 107, 205, 73, 179, 55, 94, 238, 125, 99, 166, 95, 96, 178, 124, 155, 158, 137, 76, 225, 82, 97, 61, 235, 223, 232, 138, 218, 8, 109, 72, 165, 152, 87, 7, 48, 95, 52, 96, 73, 11, 65, 33, 181, 67, 197, 237, 4, 166, 56, 9, 140, 229, 191, 220, 134, 98, 44, 133, 87, 119, 57, 233, 229, 210, 96, 45, 217, 59, 192, 162, 229, 200, 32, 210, 5, 88, 76, 193, 104, 158, 238, 56, 142, 191, 86, 61];

        final challenge = await server.createChallenge(
          ephemeralServerPrivateKeyBytes: serverPrivateKey,
        );

        expect(challenge.ephemeralServerPublicKey, expectedServerPublicKey);
      });

      test('generates random server private key when not provided', () async {
        final challenge1 = await server.createChallenge();

        final server2 = Server(
          userId: username,
          salt: salt,
          verifierKey: verifierKey,
          generator: BigInt.from(generator),
          safePrime: safePrime,
        );
        final challenge2 = await server2.createChallenge();

        expect(challenge1.ephemeralServerPublicKey, isNot(equals(challenge2.ephemeralServerPublicKey)));
      });
    });

    group('deriveSessionKey tests', () {
      test('derived session key matches pysrp', () async {
        const expectedSessionKey = [101, 63, 34, 246, 210, 134, 205, 205, 240, 205, 128, 100, 230, 168, 167, 194, 55, 91, 245, 230, 238, 184, 15, 28, 156, 136, 56, 1, 16, 196, 159, 25];

        await server.createChallenge(
          ephemeralServerPrivateKeyBytes: serverPrivateKey,
        );

        final sessionKey = await server.deriveSessionKey(
          ephemeralUserPublicKey: userPublicKey,
        );

        expect(sessionKey, expectedSessionKey);
        expect(server.sessionKey, expectedSessionKey);
      });

      test('throws AuthenticationFailure for invalid user public key', () async {
        await server.createChallenge();

        // User public key that is 0 mod N is invalid.
        final invalidUserPublicKey = server.safePrime.toByteList();

        expect(
          server.deriveSessionKey(ephemeralUserPublicKey: invalidUserPublicKey),
          throwsA(isA<InvalidParameterException>()),
        );
      });
    });

    group('verifySession tests', () {
      const userSessionKeyVerifier = [112, 68, 29, 211, 34, 202, 76, 147, 231, 195, 23, 181, 197, 114, 154, 72, 227, 238, 18, 235, 59, 22, 61, 155, 143, 248, 68, 202, 125, 239, 103, 176];

      test('verification passes and returns correct server verifier', () async {
        const expectedServerSessionKeyVerifier = [11, 114, 210, 88, 9, 28, 238, 168, 77, 158, 32, 102, 43, 253, 72, 248, 164, 73, 231, 6, 105, 181, 76, 144, 203, 230, 220, 199, 102, 215, 28, 255];

        await server.createChallenge(
          ephemeralServerPrivateKeyBytes: serverPrivateKey,
        );

        final serverSessionKeyVerifier = await server.verifySession(
          ephemeralUserPublicKey: userPublicKey,
          userSessionKeyVerifier: userSessionKeyVerifier,
        );

        expect(serverSessionKeyVerifier, expectedServerSessionKeyVerifier);
      });

      test('verification fails for incorrect user verifier', () async {
        await server.createChallenge(
          ephemeralServerPrivateKeyBytes: serverPrivateKey,
        );

        expect(
          server.verifySession(
            ephemeralUserPublicKey: userPublicKey,
            userSessionKeyVerifier: userSessionKeyVerifier + [1, 2, 3, 4],
          ),
          throwsA(isA<AuthenticationFailure>()),
        );
      });

      test('automatically derives session key if not already derived', () async {
        await server.createChallenge(
          ephemeralServerPrivateKeyBytes: serverPrivateKey,
        );

        expect(server.sessionKey, isNull);

        await server.verifySession(
          ephemeralUserPublicKey: userPublicKey,
          userSessionKeyVerifier: userSessionKeyVerifier,
        );

        expect(server.sessionKey, isNotNull);
      });
    });
  });
}
