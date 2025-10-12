import 'package:dsrp/dsrp.dart';
import 'package:dsrp/util/collections.dart' show ListComparisons;

/// Minimal example of SRP authentication flow using default parameters.
///
/// This example demonstrates the simplest possible SRP workflow:
/// 1. User registration (create verification key)
/// 2. User authentication (mutual verification)
///
/// WARNING: This uses default RFC5054 safe primes which may be vulnerable
/// to pre-computed attacks. For production, generate custom safe primes using
/// scripts/generate_safe_primes.
void main() async {
  print('=== SRP Minimal Authentication Example ===\n');

  // User credentials
  final username = 'alice';
  final password = 'secure-password-123';

  ///////////////////////////////////////////////////////////////////////////
  // REGISTRATION PHASE
  ///////////////////////////////////////////////////////////////////////////
  print('📝 Registration Phase:');

  // User creates a verification key from their password
  final saltedKey = await User.createSaltedVerificationKey(
    userId: username,
    password: password,
    // Using defaults: Argon2id KDF, SHA256 hash, RFC5054 safe prime
  );

  print('  ✓ Created verification key (${saltedKey.key.length} bytes)');
  print('  ✓ Salt: ${saltedKey.salt.length} bytes');

  // In a real application:
  // - Send saltedKey.key and saltedKey.salt to server via API
  // - Server stores in database associated with username
  // - saltedKey.erase() after successful transmission

  ///////////////////////////////////////////////////////////////////////////
  // AUTHENTICATION PHASE
  ///////////////////////////////////////////////////////////////////////////
  print('\n🔐 Authentication Phase:');

  // SERVER: Create challenge using stored verification key
  print('  Server: Creating challenge...');
  final server = Server(
    userId: username,
    salt: saltedKey.salt,
    verifierKey: saltedKey.key,
  );
  final challenge = await server.createChallenge();
  print('  ✓ Server challenge created');

  // USER: Process challenge with password
  print('  User: Processing challenge...');
  final user = await User.fromUserCredsAndChallenge(
    userId: username,
    password: password,
    challenge: challenge,
  );
  final userVerifiers = user.getUserSessionVerifiers();
  print('  ✓ User session key derived');

  // SERVER: Verify user's session key
  print('  Server: Verifying user...');
  final serverVerifier = await server.verifySession(
    ephemeralUserPublicKey: userVerifiers.ephemeralUserPublicKey,
    userSessionKeyVerifier: userVerifiers.sessionKeyVerifier,
  );
  print('  ✓ User authenticated');

  // USER: Verify server's identity
  print('  User: Verifying server...');
  await user.verifySession(serverVerifier);
  print('  ✓ Server authenticated');

  ///////////////////////////////////////////////////////////////////////////
  // SUCCESS
  ///////////////////////////////////////////////////////////////////////////
  print('\n✅ Mutual authentication successful!');
  print('   Shared session key: ${user.sessionKey.length} bytes');
  print('   User key matches server key: ${user.sessionKey.shallowEquals(server.sessionKey!)}');

  // The session keys can now be used for encrypted communication
  print('\n💡 Both parties can now use the session key for encryption');
}
