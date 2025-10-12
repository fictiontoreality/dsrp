import 'package:dsrp/dsrp.dart';

/// Example demonstrating SRP with custom cryptographic parameters.
///
/// This shows how to:
/// 1. Use custom safe primes and generators.
/// 2. Select different hash functions and KDFs.
/// 3. Verify cryptographic parameters for security.
///
/// PRODUCTION RECOMMENDATION: Generate your own safe primes using
/// scripts/generate_safe_primes to reduce vulnerability to pre-computed
/// attacks on standard RFC5054 primes.
void main() async {
  print('=== SRP with Custom Parameters Example ===\n');

  ///////////////////////////////////////////////////////////////////////////
  // CUSTOM CRYPTOGRAPHIC PARAMETERS
  ///////////////////////////////////////////////////////////////////////////
  print('🔧 Using Custom Parameters:');

  // Custom 1024-bit safe prime from RFC5054 Appendix A
  // In production, generate your own using scripts/generate_safe_primes.
  final customSafePrime = BigInt.parse(
    'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C'
    '9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4'
    '8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29'
    '7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A'
    'FD5138FE8376435B9FC61D2FC0EB06E3',
    radix: 16,
  );
  final customGenerator = BigInt.from(2);

  print('  Safe Prime: ${customSafePrime.bitLength} bits');
  print('  Generator: $customGenerator');

  // Verify parameters are cryptographically secure
  print('\n🔍 Verifying Parameters (this may take a few seconds)...');
  try {
    verifySafePrime(customSafePrime, 1024);
    print('  ✓ Safe prime is valid');

    verifyGenerator(customGenerator, customSafePrime);
    print('  ✓ Generator is valid');
  } catch (e) {
    print('  ❌ Parameter verification failed: $e');
    return;
  }

  ///////////////////////////////////////////////////////////////////////////
  // REGISTRATION WITH ALTERNATIVE KDF
  ///////////////////////////////////////////////////////////////////////////
  print('\n📝 Registration with SHA-512 KDF:');

  final username = 'bob';
  final password = 'my-strong-password';

  // Use SHA-512 KDF (faster but less secure than default Argon2id)
  // For production, prefer Argon2id (the default) for better security
  final saltedKey = await User.createSaltedVerificationKey(
    userId: username,
    password: password,
    generator: customGenerator,
    safePrime: customSafePrime,
    kdf: KdfChoice.sha512, // Custom KDF selection
  );

  print('  ✓ Verification key created with SHA-512 KDF');

  ///////////////////////////////////////////////////////////////////////////
  // AUTHENTICATION WITH ALTERNATIVE HASH FUNCTION
  ///////////////////////////////////////////////////////////////////////////
  print('\n🔐 Authentication with SHA-512 Hash:');

  // SERVER: Create challenge with custom parameters
  final server = Server(
    userId: username,
    salt: saltedKey.salt,
    verifierKey: saltedKey.key,
    generator: customGenerator,
    safePrime: customSafePrime,
    hashFunction: HashFunctionChoice.sha512, // Alternative hash selection
  );
  final challenge = await server.createChallenge();
  print('  ✓ Server challenge created');

  // USER: Process challenge with matching KDF
  final user = await User.fromUserCredsAndChallenge(
    userId: username,
    password: password,
    challenge: challenge,
    kdf: KdfChoice.sha512, // Must match registration KDF
  );
  final userVerifiers = user.getUserSessionVerifiers();
  print('  ✓ User session key derived');

  // Mutual verification
  final serverVerifier = await server.verifySession(
    ephemeralUserPublicKey: userVerifiers.ephemeralUserPublicKey,
    userSessionKeyVerifier: userVerifiers.sessionKeyVerifier,
  );
  print('  ✓ User authenticated');

  await user.verifySession(serverVerifier);
  print('  ✓ Server authenticated');

  ///////////////////////////////////////////////////////////////////////////
  // VERIFICATION
  ///////////////////////////////////////////////////////////////////////////
  print('\n✅ Authentication successful with custom parameters!');
  print('   Session key: ${user.sessionKey.length} bytes');
  print('   Hash function: SHA-512');
  print('   KDF: SHA-512');
  print('   Safe prime: ${customSafePrime.bitLength} bits');

  ///////////////////////////////////////////////////////////////////////////
  // PARAMETER RECOMMENDATIONS
  ///////////////////////////////////////////////////////////////////////////
  print('\n💡 Parameter Recommendations:');
  print('   • Safe Prime: ≥2048 bits (current: ${customSafePrime.bitLength} bits)');
  print('   • Generator: Usually 2 or 5');
  print('   • Hash Function: SHA-256 or SHA-512 (avoid SHA-1)');
  print('   • KDF: Argon2id (default) for best security');
  print('   • Salt: ≥16 bytes (current: ${saltedKey.salt.length} bytes)');
  print('\n⚠️  WARNING: Generate custom safe primes for production!');
  print('   Use: scripts/generate_safe_primes');
}
