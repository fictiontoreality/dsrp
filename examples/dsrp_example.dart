import 'package:dsrp/dsrp.dart';

void main() async {
  //////////////////////////////
  ///// Registration.
  //////////////////////////////
  // 0 (optional). User requests from server basic SRP primitives (e.g., ). Alternatively, user and server could hardcode them beforehand, or else user could dictate the primitives to the server.
  // User and/or server should verify SRP primitives received are secure.
  // FIXME: Provide methods for verifying primality, etc. See prime generation script.

  // 1. User generates a salted verification key based on user ID and password.
  final userId = "fakeuserid";
  final password = "fakepassword";
  final saltedVerificationKey = await User.createSaltedVerificationKey(
    userId: userId, password: password);

  // 2. The salted verification key is sent to the server, along with user ID,
  // to register the user for later authentication.

  //////////////////////////////
  ///// Authentication.
  //////////////////////////////
  // 1. To initiate login, the user requests a challenge from the server by
  // sending the user ID. The server retrieves the salted verification key in
  // order to create the challenge.
  final server = Server(
    userId: userId,
    salt: saltedVerificationKey.salt,
    verifierKey: saltedVerificationKey.key
  );
  final challenge = await server.createChallenge();

  // 2. The user processes the challenge to generate a session key and its
  // verifiers.
  final user = await User.fromUserCredsAndChallenge(
    userId: userId, password: password, challenge: challenge);
  final userSessionVerifiers = user.getUserSessionVerifiers();

  // 3. The user-derived verifiers are sent to the server.

  // 4. The server verifies the user session key and responds with a session-key
  // encrypted message containing its own verifier.
  // Throws an exception if verification fails.
  // At this point all message bodies between user and server should be
  // encrypted using the session key (e.g., user.sessionKey,
  // server.sessionKey). This supplements but does not replace TLS and
  // other transport layer encryption. If at any point a message body cannot be
  // decrypted, the message should be dropped.
  final serverSessionKeyVerifier = await server.verifySession(
    ephemeralUserPublicKey: userSessionVerifiers.ephemeralUserPublicKey,
    userSessionKeyVerifier: userSessionVerifiers.sessionKeyVerifier);

  // 5. The user verifies the server session key. Throws an exception if verification fails.
  await user.verifySession(serverSessionKeyVerifier);

  // 6. User and server are now mutually authenticated and can continue using
  // the shared SRP session key to encrypt messages for this user session.
}
