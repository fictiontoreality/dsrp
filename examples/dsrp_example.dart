import 'package:dsrp/dsrp.dart';

void main() async {
  // Registration.
  final user = User(userId: "fakeuserid", password: "fakepassword");
  final saltedVerificationKey = await user.createSaltedVerificationKey();

  // Authentication.
  final startAuthData = user.startAuthentication();

  final server = Server(
    userId: startAuthData.userId,
    salt: saltedVerificationKey.salt,
    verifierKey: saltedVerificationKey.key,
    ephemeralUserPublicKey: startAuthData.ephemeralUserPublicKey,
  );
  final challenge = await server.createChallenge();

  final userSessionKeyVerifier =
      await user.processChallenge(challenge.salt, challenge.ephemeralServerPublicKey);

  // At this point all messages between user and server should be encrypted using the session key (e.g., user.getSessionKey(), server.getSessionKey()), in addition to TLS or other encryption.

  final serverSessionKeyVerifier = await server.verifySession(userSessionKeyVerifier);

  await user.verifySession(serverSessionKeyVerifier);
}
