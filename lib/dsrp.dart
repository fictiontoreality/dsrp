library dsrp;

import 'dart:math' show Random;

//TODO: Goal here is to mimic pysrp. So probably mimic its API until you get a
// better sense.

final random = Random.secure();

class SaltedVerificationKey {
  final List<int> key;
  final List<int> salt;

  SaltedVerificationKey({
      required this.key,
      required this.salt
  });
}

SaltedVerificationKey createSaltedVerificationKey(String username, String password) {
  //TODO: How big should the salt be?
  final salt = List<int>.generate(128, (index) => random.nextInt(256));

  return SaltedVerificationKey(
    key: key,
    salt: salt,
  );
}


/// A Calculator.
class Calculator {
  /// Returns [value] plus 1.
  int addOne(int value) => value + 1;
}
