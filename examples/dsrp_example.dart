import 'package:dsrp/dsrp.dart';

void main() {
  final user = User(userId: "willy", password: "wonka");
  final saltedVerificationKey = user.createSaltedVerificationKey();
}
