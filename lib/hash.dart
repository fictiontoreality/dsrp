import 'package:cryptography/cryptography.dart';

enum HashAlgorithmChoice {
  sha1,
  sha256,
  sha512,
}

final _hashChoiceToAlgorithm = <HashAlgorithmChoice, HashAlgorithm>{
  HashAlgorithmChoice.sha1: Sha1(),
  HashAlgorithmChoice.sha256: Sha256(),
  HashAlgorithmChoice.sha512: Sha512(),
};

HashAlgorithm getHashAlgorithm(final HashAlgorithmChoice choice) {
  final hashAlgorithm = _hashChoiceToAlgorithm[choice];
  if (hashAlgorithm == null) {
    throw 'Hash choice not supported.';
  }
  return hashAlgorithm;
}
