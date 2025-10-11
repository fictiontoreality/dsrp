/// Hash algorithms.
library;

import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:dsrp/exceptions.dart';

/// Hash algorithms available for use in SRP operations.
///
/// These algorithms are used throughout the SRP protocol for:
/// - Hashing user IDs and safe primes
/// - Deriving session keys
/// - Computing verifiers
///
/// **Security Considerations:**
/// - [sha256] is recommended for most use cases (balance of security and performance)
/// - [sha512] provides stronger security but with performance penalty on 32-bit systems
/// - [sha1] is provided for RFC5054 compatibility and low-resource environments only
///
/// The hash function choice must match between client and server, and must be
/// the same during both registration and authentication phases.
enum HashFunctionChoice {
  /// SHA-1 hash algorithm (160-bit output).
  ///
  /// **Warning:** SHA-1 is cryptographically weak and provided only for
  /// compatibility with RFC5054 and legacy systems. Not recommended for
  /// production use unless required for interoperability.
  sha1,

  /// SHA-256 hash algorithm (256-bit output).
  ///
  /// Recommended default for most applications. Provides good security with
  /// excellent performance across all platforms.
  sha256,

  /// SHA-512 hash algorithm (512-bit output).
  ///
  /// Provides stronger security than SHA-256 but may have performance penalty
  /// on 32-bit systems. Use when maximum security is required.
  sha512,
}

final _hashChoiceToAlgorithm = <HashFunctionChoice, HashFunction>{
  HashFunctionChoice.sha1: CryptographyLibHashFunction(hashAlgorithm: Sha1()),
  HashFunctionChoice.sha256: CryptographyLibHashFunction(hashAlgorithm: Sha256()),
  HashFunctionChoice.sha512: CryptographyLibHashFunction(hashAlgorithm: Sha512()),
};

/// Returns a [HashFunction] implementation for the given [choice].
///
/// Throws [UnsupportedAlgorithmException] if the hash algorithm is not
/// supported.
HashFunction getHashFunction(final HashFunctionChoice choice) {
  final hashFunction = _hashChoiceToAlgorithm[choice];
  if (hashFunction == null) {
    throw UnsupportedAlgorithmException('Hash algorithm $choice is not supported.');
  }
  return hashFunction;
}

/// Hash function interface.
///
/// This interface allows users to provide custom hash function implementations
/// while maintaining compatibility with the SRP protocol.
///
/// Used throughout SRP for hashing operations including key derivation,
/// session key generation, and verifier calculation.
abstract class HashFunction {
  /// Computes hash of input bytes.
  ///
  /// [input] should be the data to hash as a Uint8List.
  /// Returns the hash output as a Uint8List.
  Future<Uint8List> hash(Uint8List input);
}

/// Wrapper for cryptography package's HashAlgorithm.
///
/// Provides a HashFunction interface for standard hash algorithms from the
/// cryptography package (SHA1, SHA256, SHA512, etc.).
class CryptographyLibHashFunction implements HashFunction {
  final HashAlgorithm hashAlgorithm;

  CryptographyLibHashFunction({required this.hashAlgorithm});

  @override
  Future<Uint8List> hash(Uint8List input) async {
    final result = await hashAlgorithm.hash(input);
    return Uint8List.fromList(result.bytes);
  }
}
