import 'dart:typed_data';
import 'package:dsrp/dsrp.dart';
import 'package:test/test.dart';

import './test/constants.dart';

void main() {
  authenticate(Uint8List verifierKey, Uint8List salt, {BigInt? safePrime}) async {
    final server = Server(
      userId: username,
      salt: salt, verifierKey: verifierKey,
      safePrime: safePrime,
    );
    final challenge = await server.createChallenge();

    final user = await User.fromUserCredsAndChallenge(
      userId: username, password: password,
      challenge: challenge, kdf: kdfChoice,
    );
    final userSessionVerifiers = user.getUserSessionVerifiers();

    final serverSessionKeyVerifier = await server.verifySession(
      ephemeralUserPublicKey: userSessionVerifiers.ephemeralUserPublicKey,
      userSessionKeyVerifier: userSessionVerifiers.sessionKeyVerifier);

    await user.verifySession(serverSessionKeyVerifier);

    expect(user.sessionKey, server.sessionKey);
  }

  group('end to end integration tests', () {
      test('full SRP workflow', () async {
          // Registration.
          final saltedVerificationKey = await User.createSaltedVerificationKey(
            userId: username, password: password,
            kdf: kdfChoice);
          // Authentication.
          await authenticate(saltedVerificationKey.key, saltedVerificationKey.salt);
      });

      test('authenticate with stored verifier key and salt', () async {
          // Verifier key and salt stored on server from 'prior' registration.
          final verifierKey = Uint8List.fromList([38, 173, 182, 68, 210, 122, 188, 207, 48, 253, 137, 75, 207, 161, 251, 108, 245, 255, 167, 202, 206, 107, 158, 251, 195, 6, 65, 137, 17, 179, 102, 100, 132, 48, 113, 113, 254, 245, 45, 219, 237, 31, 6, 151, 191, 168, 83, 66, 207, 8, 199, 134, 190, 75, 220, 9, 64, 121, 240, 52, 222, 188, 154, 105, 197, 164, 250, 30, 23, 49, 82, 177, 226, 142, 206, 13, 62, 99, 124, 227, 216, 71, 207, 125, 238, 243, 140, 229, 240, 97, 59, 147, 196, 207, 25, 45, 131, 40, 142, 179, 207, 120, 248, 12, 44, 30, 132, 18, 146, 181, 40, 228, 93, 61, 150, 122, 135, 109, 223, 183, 117, 30, 161, 177, 76, 29, 39, 62]);
          final salt = Uint8List.fromList([179, 213, 23, 45]);
          // Authentication.
          await authenticate(verifierKey, salt, safePrime: safePrime);
      });

      // Verifies exact compatibility with RFC5054.
      test('matches RFC5054 test vectors with SHA1', () async {
          // RFC5054 Appendix B test vector.
          const username = 'alice';
          const password = 'password123';
          // Salt from RFC5054 (hex: BEB25379 D1A8581E B5A72767 3A2441EE)
          final salt = Uint8List.fromList([190, 178, 83, 121, 209, 168, 88, 30, 181, 167, 39, 103, 58, 36, 65, 238]);

          // RFC5054 1024-bit group from Appendix A.
          final generator = BigInt.from(2);

          // Expected verifier from RFC5054.
          final expectedVerifier = Uint8List.fromList([
            0x7E, 0x27, 0x3D, 0xE8, 0x69, 0x6F, 0xFC, 0x4F, 0x4E, 0x33, 0x7D, 0x05, 0xB4, 0xB3, 0x75, 0xBE,
            0xB0, 0xDD, 0xE1, 0x56, 0x9E, 0x8F, 0xA0, 0x0A, 0x98, 0x86, 0xD8, 0x12, 0x9B, 0xAD, 0xA1, 0xF1,
            0x82, 0x22, 0x23, 0xCA, 0x1A, 0x60, 0x5B, 0x53, 0x0E, 0x37, 0x9B, 0xA4, 0x72, 0x9F, 0xDC, 0x59,
            0xF1, 0x05, 0xB4, 0x78, 0x7E, 0x51, 0x86, 0xF5, 0xC6, 0x71, 0x08, 0x5A, 0x14, 0x47, 0xB5, 0x2A,
            0x48, 0xCF, 0x19, 0x70, 0xB4, 0xFB, 0x6F, 0x84, 0x00, 0xBB, 0xF4, 0xCE, 0xBF, 0xBB, 0x16, 0x81,
            0x52, 0xE0, 0x8A, 0xB5, 0xEA, 0x53, 0xD1, 0x5C, 0x1A, 0xFF, 0x87, 0xB2, 0xB9, 0xDA, 0x6E, 0x04,
            0xE0, 0x58, 0xAD, 0x51, 0xCC, 0x72, 0xBF, 0xC9, 0x03, 0x3B, 0x56, 0x4E, 0x26, 0x48, 0x0D, 0x78,
            0xE9, 0x55, 0xA5, 0xE2, 0x9E, 0x7A, 0xB2, 0x45, 0xDB, 0x2B, 0xE3, 0x15, 0xE2, 0x09, 0x9A, 0xFB,
          ]);

          // Create verifier using SHA1 (as per RFC5054).
          final saltedVerificationKey = await User.createSaltedVerificationKey(
            userId: username,
            password: password,
            generator: generator,
            safePrime: safePrime,
            kdf: KdfChoice.sha1,
            salt: salt,
          );

          // Check that the verifier matches RFC5054.
          expect(saltedVerificationKey.key, expectedVerifier);

          // Verify full authentication workflow works.
          final server = Server(
            userId: username,
            salt: saltedVerificationKey.salt,
            verifierKey: saltedVerificationKey.key,
            generator: generator,
            safePrime: safePrime,
            hashFunction: HashFunctionChoice.sha1,
          );

          final challenge = await server.createChallenge();

          final user = await User.fromUserCredsAndChallenge(
            userId: username,
            password: password,
            challenge: challenge,
            kdf: KdfChoice.sha1,
          );

          final userSessionVerifiers = user.getUserSessionVerifiers();

          final serverSessionKeyVerifier = await server.verifySession(
            ephemeralUserPublicKey: userSessionVerifiers.ephemeralUserPublicKey,
            userSessionKeyVerifier: userSessionVerifiers.sessionKeyVerifier,
          );

          await user.verifySession(serverSessionKeyVerifier);

          expect(user.sessionKey, server.sessionKey);
      });

      test('full workflow works with useUserIdInPrivateKey = false', () async {
          // Registration without userId in private key.
          final saltedVerificationKey = await User.createSaltedVerificationKey(
            password: password,
            generator: generator,
            safePrime: safePrime,
            kdf: kdfChoice,
          );

          // Authentication without userId in private key.
          final server = Server(
            userId: username,
            salt: saltedVerificationKey.salt,
            verifierKey: saltedVerificationKey.key,
            generator: generator,
            safePrime: safePrime,
          );

          final challenge = await server.createChallenge();

          final user = await User.fromUserCredsAndChallenge(
            userId: username,
            password: password,
            challenge: challenge,
            kdf: kdfChoice,
            useUserIdInPrivateKey: false,
          );

          final userSessionVerifiers = user.getUserSessionVerifiers();

          final serverSessionKeyVerifier = await server.verifySession(
            ephemeralUserPublicKey: userSessionVerifiers.ephemeralUserPublicKey,
            userSessionKeyVerifier: userSessionVerifiers.sessionKeyVerifier,
          );

          await user.verifySession(serverSessionKeyVerifier);

          expect(user.sessionKey, server.sessionKey);
      });

      test('authentication fails when useUserIdInPrivateKey setting mismatches between registration and authentication', () async {
          // Registration WITH userId in private key.
          final saltedVerificationKey = await User.createSaltedVerificationKey(
            userId: username,
            password: password,
            generator: generator,
            safePrime: safePrime,
            kdf: kdfChoice,
          );

          final server = Server(
            userId: username,
            salt: saltedVerificationKey.salt,
            verifierKey: saltedVerificationKey.key,
            generator: generator,
            safePrime: safePrime,
          );

          final challenge = await server.createChallenge();

          // Authentication WITHOUT userId in private key (mismatch).
          final user = await User.fromUserCredsAndChallenge(
            userId: username,
            password: password,
            challenge: challenge,
            kdf: kdfChoice,
            useUserIdInPrivateKey: false,
          );

          final userSessionVerifiers = user.getUserSessionVerifiers();

          // Server should reject because private key was derived differently.
          expect(
            server.verifySession(
              ephemeralUserPublicKey: userSessionVerifiers.ephemeralUserPublicKey,
              userSessionKeyVerifier: userSessionVerifiers.sessionKeyVerifier,
            ),
            throwsA(isA<AuthenticationFailure>()),
          );
      });

      group('attack scenario tests', () {
          test('server rejects invalid user public key (A = 0 mod N)', () async {
              final saltedVerificationKey = await User.createSaltedVerificationKey(
                userId: username, password: password,
                generator: generator, safePrime: safePrime,
                kdf: kdfChoice,
              );

              final server = Server(
                userId: username,
                salt: saltedVerificationKey.salt,
                verifierKey: saltedVerificationKey.key,
                generator: generator,
                safePrime: safePrime,
              );

              await server.createChallenge();

              // Attack: Send A = N (which is 0 mod N).
              final invalidUserPublicKey = safePrime.toByteList();

              expect(
                server.deriveSessionKey(ephemeralUserPublicKey: invalidUserPublicKey),
                throwsA(isA<InvalidParameterException>()),
              );
          });

          test('user rejects invalid server public key (B = 0 mod N)', () async {
              final salt = Uint8List.fromList([1, 2, 3, 4]);

              // Create a challenge with invalid server public key.
              final challenge = Challenge.fromServer(
                generator: generator,
                safePrime: safePrime,
                ephemeralServerPublicKey: safePrime.toByteList(), // B = N (0 mod N)
                verifierKeySalt: salt,
                hashFunctionChoice: hashFunctionChoice,
              );

              // Attack: User tries to process challenge with invalid B.
              expect(
                User.fromUserCredsAndChallenge(
                  userId: username,
                  password: password,
                  challenge: challenge,
                  kdf: kdfChoice,
                ),
                throwsA(isA<InvalidParameterException>()),
              );
          });

          test('authentication fails with wrong password', () async {
              final saltedVerificationKey = await User.createSaltedVerificationKey(
                userId: username, password: password,
                generator: generator, safePrime: safePrime,
                kdf: kdfChoice,
              );

              final server = Server(
                userId: username,
                salt: saltedVerificationKey.salt,
                verifierKey: saltedVerificationKey.key,
                generator: generator,
                safePrime: safePrime,
              );

              final challenge = await server.createChallenge();

              // Attack: User uses wrong password.
              final user = await User.fromUserCredsAndChallenge(
                userId: username,
                password: 'wrongpassword',
                challenge: challenge,
                kdf: kdfChoice,
              );

              final userSessionVerifiers = user.getUserSessionVerifiers();

              // Server should reject the session key verifier.
              expect(
                server.verifySession(
                  ephemeralUserPublicKey: userSessionVerifiers.ephemeralUserPublicKey,
                  userSessionKeyVerifier: userSessionVerifiers.sessionKeyVerifier,
                ),
                throwsA(isA<AuthenticationFailure>()),
              );
          });

          test('user rejects tampered server session key verifier', () async {
              final saltedVerificationKey = await User.createSaltedVerificationKey(
                userId: username, password: password,
                generator: generator, safePrime: safePrime,
                kdf: kdfChoice,
              );

              final server = Server(
                userId: username,
                salt: saltedVerificationKey.salt,
                verifierKey: saltedVerificationKey.key,
                generator: generator,
                safePrime: safePrime,
              );

              final challenge = await server.createChallenge();

              final user = await User.fromUserCredsAndChallenge(
                userId: username,
                password: password,
                challenge: challenge,
                kdf: kdfChoice,
              );

              final userSessionVerifiers = user.getUserSessionVerifiers();

              final serverSessionKeyVerifier = await server.verifySession(
                ephemeralUserPublicKey: userSessionVerifiers.ephemeralUserPublicKey,
                userSessionKeyVerifier: userSessionVerifiers.sessionKeyVerifier,
              );

              // Attack: Tamper with server's session key verifier
              final tamperedVerifier = Uint8List.fromList([...serverSessionKeyVerifier, 1, 2, 3]);

              expect(
                user.verifySession(tamperedVerifier),
                throwsA(isA<AuthenticationFailure>()),
              );
          });

          test('server rejects tampered user session key verifier', () async {
              final saltedVerificationKey = await User.createSaltedVerificationKey(
                userId: username, password: password,
                generator: generator, safePrime: safePrime,
                kdf: kdfChoice,
              );

              final server = Server(
                userId: username,
                salt: saltedVerificationKey.salt,
                verifierKey: saltedVerificationKey.key,
                generator: generator,
                safePrime: safePrime,
              );

              final challenge = await server.createChallenge();

              final user = await User.fromUserCredsAndChallenge(
                userId: username,
                password: password,
                challenge: challenge,
              );

              final userSessionVerifiers = user.getUserSessionVerifiers();

              // Attack: Tamper with user's session key verifier
              final tamperedVerifier = Uint8List.fromList([...userSessionVerifiers.sessionKeyVerifier, 9, 9, 9]);

              expect(
                server.verifySession(
                  ephemeralUserPublicKey: userSessionVerifiers.ephemeralUserPublicKey,
                  userSessionKeyVerifier: tamperedVerifier,
                ),
                throwsA(isA<AuthenticationFailure>()),
              );
          });

          test('authentication fails with wrong username', () async {
              final saltedVerificationKey = await User.createSaltedVerificationKey(
                userId: username, password: password,
                generator: generator, safePrime: safePrime,
                kdf: kdfChoice,
              );

              final server = Server(
                userId: username,
                salt: saltedVerificationKey.salt,
                verifierKey: saltedVerificationKey.key,
                generator: generator,
                safePrime: safePrime,
              );

              final challenge = await server.createChallenge();

              // Attack: User claims different username.
              final user = await User.fromUserCredsAndChallenge(
                userId: 'wrong username',
                password: password,
                challenge: challenge,
              );

              final userSessionVerifiers = user.getUserSessionVerifiers();

              // Server should reject because username doesn't match.
              expect(
                server.verifySession(
                  ephemeralUserPublicKey: userSessionVerifiers.ephemeralUserPublicKey,
                  userSessionKeyVerifier: userSessionVerifiers.sessionKeyVerifier,
                ),
                throwsA(isA<AuthenticationFailure>()),
              );
          });
      });
  });


}
