/// Hash algorithms.
library;

import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:dsrp/exceptions.dart';

enum HashFunctionChoice {
  sha1,
  sha256,
  sha512,
}

final _hashChoiceToAlgorithm = <HashFunctionChoice, HashFunction>{
  HashFunctionChoice.sha1: CryptographyLibHashFunction(hashAlgorithm: Sha1()),
  HashFunctionChoice.sha256: CryptographyLibHashFunction(hashAlgorithm: Sha256()),
  HashFunctionChoice.sha512: CryptographyLibHashFunction(hashAlgorithm: Sha512()),
};

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
