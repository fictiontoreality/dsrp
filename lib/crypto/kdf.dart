/// Key derivation function (KDF) algorithms.
library;

import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:dsrp/crypto/hash.dart';
import 'package:dsrp/exceptions.dart';
import 'package:dsrp/rfc5054.dart';

/// Key derivation functions (KDFs) available for deriving user private keys.
///
/// The KDF is used during registration to derive a private key from the user's
/// password and salt. This private key is then used to generate the verification
/// key stored on the server.
///
/// **Security Considerations:**
///
/// The KDF choice is critical for security. A compromised server database
/// contains verification keys that can be subject to brute-force attacks to
/// recover passwords. Slower KDFs make such attacks computationally infeasible.
///
/// **Recommendations:**
/// - [argon2id] - **Strongly recommended** for production use (memory-hard, GPU-resistant)
/// - [sha256] / [sha512] - Fast hash-based KDFs suitable only for compatibility or low-resource environments
/// - [sha1] - **Not recommended** except for RFC5054 compatibility
///
/// The KDF choice must match between registration and authentication phases.
enum KdfChoice {
  /// Argon2id KDF - memory-hard password hashing algorithm.
  ///
  /// **Strongly recommended for production use.**
  ///
  /// Argon2id is the winner of the 2015 Password Hashing Competition and
  /// provides excellent resistance to both CPU and GPU-based brute-force
  /// attacks through its memory-hard design.
  ///
  /// Configuration:
  /// - Memory: 64 MB
  /// - Iterations: 3
  /// - Parallelism: 4
  /// - Output length: 32 bytes
  argon2id,

  /// SHA-1 hash-based KDF (RFC5054 style).
  ///
  /// Implements: x = H(s, H(I | ':' | p))
  ///
  /// **Warning:** Fast to compute, which makes it vulnerable to brute-force
  /// attacks. Only use for RFC5054 compatibility or extremely low-resource
  /// environments where Argon2id is not feasible.
  sha1,

  /// SHA-256 hash-based KDF (RFC5054 style).
  ///
  /// Implements: x = H(s, H(I | ':' | p))
  ///
  /// **Warning:** Fast to compute, which makes it vulnerable to brute-force
  /// attacks. Prefer [argon2id] for production use.
  sha256,

  /// SHA-512 hash-based KDF (RFC5054 style).
  ///
  /// Implements: x = H(s, H(I | ':' | p))
  ///
  /// **Warning:** Fast to compute, which makes it vulnerable to brute-force
  /// attacks. Prefer [argon2id] for production use.
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
  KdfChoice.sha1: HashKdf(hashFunction: CryptographyLibHashFunction(hashAlgorithm: Sha1())),
  KdfChoice.sha256: HashKdf(hashFunction: CryptographyLibHashFunction(hashAlgorithm: Sha256())),
  KdfChoice.sha512: HashKdf(hashFunction: CryptographyLibHashFunction(hashAlgorithm: Sha512())),
};

/// Returns a [Kdf] implementation for the given [choice].
///
/// Throws [UnsupportedAlgorithmException] if the KDF algorithm is not supported.
Kdf getKdf(final KdfChoice choice) {
  final kdf = _kdfChoiceToAlgorithm[choice];
  if (kdf == null) {
    throw UnsupportedAlgorithmException('KDF algorithm $choice is not supported.');
  }
  return kdf;
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

/// RFC 5054 compliant hash-based KDF.
///
/// Implements: x = H(s, H( I | ':' | p ))
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
  final HashFunction hashFunction;

  HashKdf({required this.hashFunction});

  @override
  Future<SecretKey> deriveKeyFromPasswordBytes({
    required Uint8List passwordBytes,
    required Uint8List salt,
    Uint8List? userIdBytes,
  }) async {
    // I | ':' | p if userId is provided, otherwise just p.
    final inputToHash = concatenateUserIdAndPassword(userIdBytes, passwordBytes);

    // First hash: H(I | ':' | p)
    final hashedPassword = await hashFunction.hash(inputToHash);

    // RFC 5054: x = H(s, H(I | ':' | p))
    final combined = Uint8List.fromList([
      ...salt,
      ...hashedPassword,
    ]);
    final finalHash = await hashFunction.hash(combined);

    return SecretKey(finalHash);
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
