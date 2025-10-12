import 'dart:typed_data';
import 'package:dsrp/dsrp.dart';

/// Example demonstrating secure memory handling with proper cleanup.
///
/// This shows best practices for:
/// 1. Using Uint8List instead of String for passwords
/// 2. Zeroing out sensitive data as soon as it's no longer needed
/// 3. Properly cleaning up SRP objects
///
/// WHY THIS MATTERS:
/// - Strings in Dart are immutable and persist in memory until garbage
///   collected.
/// - Uint8List can be overwritten to immediately remove sensitive data.
/// - Reduces window of vulnerability if memory is compromised.
void main() async {
  print('=== Secure Memory Cleanup Example ===\n');
  print('This example demonstrates secure handling of sensitive data.\n');

  ///////////////////////////////////////////////////////////////////////////
  // INSECURE APPROACH (for comparison)
  ///////////////////////////////////////////////////////////////////////////
  print('❌ INSECURE: Using String passwords');
  print('   Problem: Strings persist in memory until garbage collected');
  print('   Risk: Password may linger in memory for unknown duration\n');

  // Don't do this in production:
  // final password = 'my-password';
  // await User.createSaltedVerificationKey(userId: 'alice', password: password);
  // The string 'my-password' stays in memory until GC runs

  ///////////////////////////////////////////////////////////////////////////
  // SECURE APPROACH: Using Uint8List
  ///////////////////////////////////////////////////////////////////////////
  print('✅ SECURE: Using Uint8List with immediate zeroing\n');

  String username = 'alice';
  String password = 'my-secure-password-123';

  // Step 1: Convert to bytes immediately
  print('1️⃣  Convert password to Uint8List:');
  final passwordBytes = password.utf8Bytes; // Extension method
  password = ''; // Can now be GC.
  print('   ✓ Password as bytes: ${passwordBytes.length} bytes');
  print('   ✓ String reference can be garbage collected\n');

  // Step 2: Convert username to bytes for maximum security
  print('2️⃣  Convert username to Uint8List:');
  final userIdBytes = username.utf8Bytes;
  username = ''; // Can now be GC.
  print('   ✓ Username as bytes: ${userIdBytes.length} bytes\n');

  ///////////////////////////////////////////////////////////////////////////
  // REGISTRATION WITH SECURE CLEANUP
  ///////////////////////////////////////////////////////////////////////////
  print('3️⃣  Registration Phase:');

  final saltedKey = await User.createSaltedVerificationKeyFromBytes(
    userIdBytes: userIdBytes,
    passwordBytes: passwordBytes,
  );
  print('   ✓ Verification key created');

  // SECURITY: Zero out password immediately after use
  print('\n4️⃣  Zero out password from memory:');
  passwordBytes.overwriteWithZeros();
  print('   ✓ Password bytes overwritten with zeros');
  print('   ✓ Password no longer accessible in memory\n');

  // Simulate sending to server and storing (in production, save to database)
  print('5️⃣  Send verification key to server...');

  // IMPORTANT: In production, copy the data before erasing!
  // Here we keep references for the authentication demo
  final storedKey = Uint8List.fromList(saltedKey.key);
  final storedSalt = Uint8List.fromList(saltedKey.salt);

  final sentSuccessfully = await _simulateNetworkSend(saltedKey);

  if (sentSuccessfully) {
    print('   ✓ Verification key sent to server');
    print('   ✓ Server stored key and salt in database');

    // SECURITY: Erase verification key after successful transmission
    print('\n6️⃣  Erase verification key from client memory:');
    saltedKey.erase();
    print('   ✓ Verification key erased from client');
    print('   ✓ Salt erased from client');
    print('   ✓ Only server retains the stored copy\n');
  } else {
    print('   ❌ Network error - keeping key for retry\n');
  }

  ///////////////////////////////////////////////////////////////////////////
  // AUTHENTICATION WITH SECURE CLEANUP
  ///////////////////////////////////////////////////////////////////////////
  print('7️⃣  Authentication Phase:');
  print('   (Server retrieves stored key and salt from database)');

  // User needs to re-enter password (original was zeroed)
  final passwordForAuth = 'my-secure-password-123'.utf8Bytes;

  String usernameForAuth = 'alice';
  
  final server = Server(
    userId: usernameForAuth,
    salt: storedSalt,
    verifierKey: storedKey,
  );
  usernameForAuth = ''; // Can now be GC.
  final challenge = await server.createChallenge();
  print('   ✓ Challenge created');

  final user = await User.fromUserCredsBytesAndChallenge(
    userIdBytes: userIdBytes,
    passwordBytes: passwordForAuth,
    challenge: challenge,
  );
  print('   ✓ Session key derived');

  // SECURITY: Immediately erase sensitive data
  print('\n8️⃣  Erase sensitive data:');
  passwordForAuth.overwriteWithZeros();
  print('   ✓ Password erased');

  challenge.erase();
  print('   ✓ Challenge erased');

  final userVerifiers = user.getUserSessionVerifiers();

  final serverVerifier = await server.verifySession(
    ephemeralUserPublicKey: userVerifiers.ephemeralUserPublicKey,
    userSessionKeyVerifier: userVerifiers.sessionKeyVerifier,
  );

  // SECURITY: Erase verifiers after sending
  userVerifiers.erase();
  print('   ✓ User verifiers erased');

  await user.verifySession(serverVerifier);
  print('   ✓ Authentication complete\n');

  // SECURITY: Clean up user ID bytes when done
  userIdBytes.overwriteWithZeros();
  print('9️⃣  Final cleanup:');
  print('   ✓ User ID bytes erased');

  ///////////////////////////////////////////////////////////////////////////
  // SESSION KEY HANDLING
  ///////////////////////////////////////////////////////////////////////////
  print('\n🔑 Session Key Lifecycle:');
  print('   • Session keys are kept for encrypted communication');
  print('   • Zero them when session ends or user logs out');
  print('   • Current session key: ${user.sessionKey.length} bytes');

  // When session ends:
  print('\n🔚 When session ends:');
  print('   user.sessionKey.overwriteWithZeros()');
  print('   server.sessionKey.overwriteWithZeros()');

  ///////////////////////////////////////////////////////////////////////////
  // SUMMARY
  ///////////////////////////////////////////////////////////////////////////
  print('\n${"=" * 60}');
  print('📋 SECURITY BEST PRACTICES SUMMARY');
  print('=' * 60);
  print('✓ Convert Strings to Uint8List as early as possible');
  print('✓ Use *FromBytes() methods instead of String methods');
  print('✓ Call .overwriteWithZeros() on passwords immediately after use');
  print('✓ Call .erase() on SRP objects when no longer needed:');
  print('  • SaltedVerificationKey.erase()');
  print('  • Challenge.erase()');
  print('  • UserSessionVerifiers.erase()');
  print('✓ Keep session keys only as long as session is active');
  print('✓ Zero session keys when user logs out or session expires');
  print('=' * 60);
}

/// Simulates sending data over network.
Future<bool> _simulateNetworkSend(SaltedVerificationKey key) async {
  // Simulate network delay
  await Future.delayed(Duration(milliseconds: 100));
  // Simulate success
  return true;
}
