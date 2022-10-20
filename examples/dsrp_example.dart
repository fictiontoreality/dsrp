import 'package:dsrp/dsrp.dart';

void main() {
  final user = User();
  final saltedVerificationKey = user.createSaltedVerificationKey("willy", "wonka");
}
