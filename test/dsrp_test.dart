import 'package:dsrp/dsrp.dart';
import 'package:test/test.dart';

import './constants.dart';

void main() {
  group('end to end inegration tests', () {
      test('full srp workflow', () async {
          final user = User(userId: username, password: password);
          final saltedVerificationKey = await user.createSaltedVerificationKey();
      });
  });
}
