import 'package:cryptography/cryptography.dart';
import 'package:dsrp/dsrp.dart';
import 'package:test/test.dart';

import './constants.dart';

void main() {
  group('end to end inegration tests', () {
      test('full srp workflow', () async {
          final user = User();
          final saltedVerificationKey = user.createSaltedVerificationKey(
            USERNAME, PASSWORD);
      });
  });
}
