/// Key derivation function (KDF) algorithms.
library;

import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:dsrp/exceptions.dart';
import 'package:dsrp/rfc5054.dart';

/// Choice of key derivation function (KDF) used to derive user private key.
/// 
/// Prefer a slower algorithm like Argon2id to significantly reduce the
/// likelihood of a brute-force attempt to extract the password from
/// the verifier.
enum KdfChoice {
  argon2id,
  sha1,
  sha256,
  sha512,
}

final _kdfChoiceToAlgorithm = <KdfChoice, Kdf>{
  KdfChoice.argon2id: Argon2idKdf(
    argon2: Argon2id(
      parallelism: 4,
      memory: 65536, // 64 MB
      iterations: 3,
      hashLength: 32,
    ),
  ),
  KdfChoice.sha1: HashKdf(hashAlgorithm: Sha1()),
  KdfChoice.sha256: HashKdf(hashAlgorithm: Sha256()),
  KdfChoice.sha512: HashKdf(hashAlgorithm: Sha512()),
};

Kdf getKdf(final KdfChoice choice) {
  final kdfAlgorithm = _kdfChoiceToAlgorithm[choice];
  if (kdfAlgorithm == null) {
    throw UnsupportedAlgorithmException('KDF algorithm $choice is not supported.');
  }
  return kdfAlgorithm;
}

/// Key derivation function (KDF) interface.
///
/// This interface allows users to provide custom KDF implementations while
/// maintaining compatibility with the SRP protocol.
/// 
/// Used in SRP for private key derivation. Since this KDF creates password
/// equivalent data, it is critical to use an intentionally slow KDF to reduce
/// likelihood of brute force attacks succeeding in extracting the
/// password.
abstract class Kdf {
  /// Derives a key from password bytes and salt.
  ///
  /// [passwordBytes] should be UTF-8 encoded password bytes.
  /// [salt] is the cryptographic salt.
  /// [userIdBytes] is optional - when provided, will be prepended as
  /// "userId:password" per RFC 5054 specification.
  Future<SecretKey> deriveKeyFromPasswordBytes({
    required Uint8List passwordBytes,
    required Uint8List salt,
    Uint8List? userIdBytes,
  });
}

///  RFC 5054 compliant hash-based KDF.
///
/// Implements: x = H(s, H( I | ‘:’ | p ))
///
/// This is primarily offered for compatibility with other SRP
/// implementations using the non-standard KDF found in RFC 5054. It is fast to
/// compute, which improves performance, but decreases security since its speed
/// allows faster cracking, especially when using GPUs and other highly parallel
/// compute.
///
/// To reduce the chance of cracking attacks, generally a more secure (and hence
/// deliberately slower) KDF should be used in production, such as Argon2id,
/// scrypt, or high-iteration PBKDF2.
class HashKdf implements Kdf {
  final HashAlgorithm hashAlgorithm;

  HashKdf({required this.hashAlgorithm});

  @override
  Future<SecretKey> deriveKeyFromPasswordBytes({
    required Uint8List passwordBytes,
    required Uint8List salt,
    Uint8List? userIdBytes,
  }) async {
    // I | ':' | p if userId is provided, otherwise 
    final inputToHash = concatenateUserIdAndPassword(userIdBytes, passwordBytes);

    // First hash: H(I | ':' | p)
    final hashedPassword = await hashAlgorithm.hash(inputToHash);

    // RFC 5054: x = H(s, H(I | ':' | p))
    final combined = Uint8List.fromList([
      ...salt,
      ...hashedPassword.bytes,
    ]);
    final finalHash = await hashAlgorithm.hash(combined);

    return SecretKey(finalHash.bytes);
  }
}

/// Argon2id KDF wrapper that accepts password bytes.
///
/// Provides a secure, memory-hard KDF suitable for production use.
class Argon2idKdf implements Kdf {
  final Argon2id argon2;

  Argon2idKdf({required this.argon2});

  @override
  Future<SecretKey> deriveKeyFromPasswordBytes({
    required Uint8List passwordBytes,
    required Uint8List salt,
    Uint8List? userIdBytes,
  }) async {
    // I | ':' | p
    final input = concatenateUserIdAndPassword(userIdBytes, passwordBytes);
    return await argon2.deriveKey(
      secretKey: SecretKey(input),
      nonce: salt,
    );
  }
}
