import 'package:dsrp/dsrp.dart';
import 'package:logging/logging.dart';

/// Demonstrates the major steps of SRP using dsrp.
void main() async {
  // Configure logging.
  Logger.root.level = Level.ALL;
  Logger.root.onRecord.listen((record) {
    print('${record.loggerName} ${record.level.name}: ${record.message}');
  });
  final log = Logger('srp.Example');

  //////////////////////////////
  ///// Registration.
  //////////////////////////////
  log.info('///// USER REGISTRATION BEGINS /////');

  // 0 (optional). User requests from server basic SRP primitives (e.g., safe
  // prime and generator).
  // 
  // Alternatively, user and server could hardcode them beforehand, or the user
  // could dictate the primitives to the server.
  //
  // User and/or server should verify SRP primitives received are secure.
  // 
  // In production, you should generate custom safe primes using
  // scripts/generate_safe_primes.py to reduce vulnerability to pre-computed
  // attacks on standard primes.
  log.info('(optional) User requested SRP primitives from server.');
  final safePrime = BigInt.parse('EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3', radix: 16);
  final generator = BigInt.from(2);
  final expectedSafePrimeBitLength = 1024;

  log.info('User is verifying safe prime and generator (this may take a few seconds)...');
  verifySafePrime(safePrime, expectedSafePrimeBitLength);
  log.info('✓ Safe prime is valid');

  verifyGenerator(generator, safePrime);
  log.info('✓ Generator is valid');

  // 1. User generates a salted verification key based on user ID and password.

  // SECURITY: Convert strings to bytes early for secure memory handling.
  final String userId = "fakeuserid";
  String password = "fakepassword";
  final userIdBytes = userId.utf8Bytes;
  final passwordBytes = password.utf8Bytes;
  // Setting sensitive string variables to null or empty string allows sensitive
  // string data to be garbage collected. Do the same for userId if it is
  // sensitive.
  password = ""; 

  final saltedVerificationKey = await User.createSaltedVerificationKeyFromBytes(
    userIdBytes: userIdBytes,
    passwordBytes: passwordBytes,
    generator: generator,
    safePrime: safePrime,
  );

  // SECURITY: Zero out credential bytes immediately after use.
  userIdBytes.overwriteWithZeros();
  passwordBytes.overwriteWithZeros();

  // 2. The salted verification key is sent to the server, along with user ID,
  // to register the user for later authentication.
  log.info('User began registration by creating a salted verification key and sending it to the server.');
  verifySalt(saltedVerificationKey.salt);
  log.info('Server stored salted verification key and its salt for future authentication.');

  // SECURITY: Erase the verification key after sending to server.
  // (In production, only erase after confirming successful transmission.)
  // saltedVerificationKey.erase();

  log.info('///// USER REGISTRATION COMPLETE /////');


  //////////////////////////////
  ///// Authentication.
  //////////////////////////////
  // 1. To initiate login, the user requests a challenge from the server by
  // sending the user ID. The server retrieves the salted verification key in
  // order to create the challenge.
  log.info('///// AUTHENTICATION BEGINS /////');
  log.info('User began authentication by requesting a challenge from the server.');
  final server = Server(
    userId: userId,
    salt: saltedVerificationKey.salt,
    verifierKey: saltedVerificationKey.key,
    generator: generator,
    safePrime: safePrime
  );
  final challenge = await server.createChallenge();
  log.info('Server created a challenge and sent it to the user.');

  // 2. The user processes the challenge to generate a session key and its
  // verifiers.

  // SECURITY: Re-create credential bytes for authentication (originals were zeroed
  // during registration).
  final userIdBytesForAuth = userId.utf8Bytes;
  String passwordForAuth = 'fakepassword';
  final passwordBytesForAuth = passwordForAuth.utf8Bytes;
  passwordForAuth = ''; // Allows for GC.

  final user = await User.fromUserCredsBytesAndChallenge(
    userIdBytes: userIdBytesForAuth,
    passwordBytes: passwordBytesForAuth,
    challenge: challenge,
  );

  // SECURITY: Zero out credentials and challenge after use.
  userIdBytesForAuth.overwriteWithZeros();
  passwordBytesForAuth.overwriteWithZeros();
  challenge.erase();

  final userSessionVerifiers = user.getUserSessionVerifiers();

  // 3. The user-derived verifiers are sent to the server.
  log.info('User generated a session key and sent its verifiers to the server.');

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
  log.info('Server verified session and generated a session verifier, sent it to the user.');
  userSessionVerifiers.erase();

  // 5. The user verifies the server session key. Throws an exception if
  // verification fails.
  try {
    await user.verifySession(serverSessionKeyVerifier);
    log.info('✓ Server verified successfully');
  } on AuthenticationFailure catch (e) {
    log.severe('❌ Server verification failed: $e');
    log.severe('Authentication aborted - possible man-in-the-middle attack');
    return;
  }

  // 6. User and server are now mutually authenticated and can continue using
  // the shared SRP session key to encrypt messages for this user session.
  log.info('User verified session and now SRP-encrypted communication can begin.');
  log.info('Session keys match: ${user.sessionKey.length} bytes');

  // NOTE: Keep user.sessionKey and server.sessionKey for encrypted
  // communication. Only zero them out when the session ends.

  log.info('///// AUTHENTICATION COMPLETE /////');
}
