import 'dart:convert';

import 'package:cryptography/cryptography.dart';

enum KdfAlgorithmChoice {
  arg2id,
  sha1,
  sha256,
  sha512,
}

final _kdfChoiceToAlgorithm = <KdfAlgorithmChoice, KdfAlgorithm>{
  KdfAlgorithmChoice.arg2id: Argon2id(
    //TODO: Double check these values.
    parallelism: 1,
    memory: 65536, // 64 MB
    iterations: 3,
    hashLength: 32,
  ),
  KdfAlgorithmChoice.sha1: HashKdf(hashAlgorithm: Sha1()),
  KdfAlgorithmChoice.sha256: HashKdf(hashAlgorithm: Sha256()),
  KdfAlgorithmChoice.sha512: HashKdf(hashAlgorithm: Sha512()),
};

KdfAlgorithm getKdfAlgorithm(final KdfAlgorithmChoice choice) {
  final kdfAlgorithm = _kdfChoiceToAlgorithm[choice];
  if (kdfAlgorithm == null) {
    throw 'KDF choice not supported.';
  }
  return kdfAlgorithm;
}

/// A hash-based KDF specified in RFC 5054.
///
/// x = H(s, H( I | ‘:’ | p ))
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
class HashKdf extends KdfAlgorithm {
  final HashAlgorithm hashAlgorithm;
  
  HashKdf({
      required this.hashAlgorithm,
  });

  @override
  Future<SecretKey> deriveKey({
    required SecretKey secretKey,
    required List<int> nonce,
  }) async {
    final secretKeyBytes = await secretKey.extractBytes();
    final hash = await hashAlgorithm.hash(nonce + secretKeyBytes);
    return SecretKey(hash.bytes);
  }

  @override
  Future<SecretKey> deriveKeyFromPassword({
    required String password,
    required List<int> nonce,
  }) async {
    final hashedPassword = await hashAlgorithm.hash(utf8.encode(password));
    return deriveKey(
      secretKey: SecretKey(hashedPassword.bytes),
      nonce: nonce,
    );
  }
}
