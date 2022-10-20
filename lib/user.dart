import 'dart:convert' show utf8;
import 'dart:math' show Random;
import 'package:cryptography/cryptography.dart';

import './util.dart';

class SaltedVerificationKey {
  //OPTIMIZE: Use Uint8List, since int defaults 64-bit rather than a byte?
  final List<int> key;
  final List<int> salt;

  SaltedVerificationKey({required this.key, required this.salt});
}

class User {
  //TODO: Goal here is to mimic pysrp. So probably mimic its API until you get a
  // better sense.

  //TODO: Make these class fields.
  final defaultHashAlgorithm = Sha256();

  /// A large, safe prime.
  /// Typically denoted 'N'.
  /// By definition a safe prime N = 2q + 1, where q is a Sophie Germain prime.
  /// All arithmetic is performed in the field of integers modulo N.
  /// TODO: Generate N. Got this 1024 bit prime from RFC 5054 Appendix A section 1.
  final safePrime = BigInt.parse('EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3', radix: 16);
  /// A generator modulo N.
  /// Typically denoted 'g'.
  static const generator = 2;
  
  final random = Random.secure();

  Future<SaltedVerificationKey> createSaltedVerificationKey(
    String userId, String password, {
      HashAlgorithm? hashAlgorithm,
      List<int>? salt
  }) async {
    hashAlgorithm ??= defaultHashAlgorithm;
    //TODO: How big should the salt be?
    salt ??= List<int>.generate(128, (index) => random.nextInt(256));
    // Private key (as defined by RFC 5054)
    // x = H(s, H( I | ‘:’ | p ))
    var privateKey = await hashAlgorithm.hash(
        //TODO: How should this be formatted?
        utf8.encode('$userId:$password'));
    privateKey = await hashAlgorithm.hash(salt + privateKey.bytes);
    final privateKeyInt = convertByteListToBigInt(privateKey.bytes);
    // Verifier key
    // v = g^x
    final verifierKeyInt = BigInt.from(generator).modPow(privateKeyInt, safePrime);
    final verifierKeyBytes = convertBigIntToByteList(verifierKeyInt);
    return SaltedVerificationKey(
      key: verifierKeyBytes,
      salt: salt,
    );
  }

  // Future<SaltedVerificationKey> createSaltedVerificationKeyWithArgon2(String userId, String password) async {
  //   //TODO: How big should the salt be?
  //   final salt = List<int>.generate(128, (index) => random.nextInt(256));
  //   //TODO: Hash alg should be specifiable.
  //   final argon2id = Argon2id(
  //     //OPTIMIZE: What should these values be?
  //     parallelism: 3,
  //     memorySize: 10000000,
  //     iterations: 3,
  //     hashLength: 32,
  //   );
  //   // Private key (as defined by RFC 5054)
  //   // x = H(s, H( I | ‘:’ | p ))
  //   var privateKey = await argon2id.deriveKey(
  //     //TODO: How should this secret key be formatted?
  //     secretKey: SecretKey(utf8.encode('$userId:$password')),
  //     nonce: [],
  //   );
  //   privateKey = await argon2id.deriveKey(
  //     secretKey: privateKey,
  //     nonce: salt,
  //   );
  //   final privateKeyInt = convertByteListToInt(await privateKey.extractBytes());
  //   final verifierKey = generator.modPow(privateKeyInt, safePrime);
  //   final verifierKeyBytes = convertIntToByteList(verifierKey);
  //   return SaltedVerificationKey(
  //     key: verifierKeyBytes,
  //     salt: salt,
  //   );
  // }
}
