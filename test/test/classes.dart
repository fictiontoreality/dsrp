/// Test classes shared across unit / integration tests.
library;

import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:dsrp/crypto/hash.dart';
import 'package:dsrp/crypto/kdf.dart';

/// Custom KDF for tests.
class TestKdf implements Kdf {
  @override
  final String name;

  TestKdf({required this.name});

  @override
  Future<SecretKey> deriveKeyFromPasswordBytes({
      required Uint8List passwordBytes,
      required Uint8List salt,
      Uint8List? userIdBytes,
  }) async {
    // Delegate to actual Argon2id for testing
    return getKdf(KdfChoice.argon2id).deriveKeyFromPasswordBytes(
      passwordBytes: passwordBytes,
      salt: salt,
      userIdBytes: userIdBytes,
    );
  }
}

/// Custom HashFunction for tests.
class TestHashFunction implements HashFunction {
  @override
  final String name;

  TestHashFunction({required this.name});

  @override
  Future<Uint8List> hash(Uint8List input) async {
    // Delegate to actual SHA-256 for testing
    return getHashFunction(HashFunctionChoice.sha256).hash(input);
  }
}
