/// Common methods required by agents (user, server) implementing RFC5054.
import 'package:cryptography/cryptography.dart';

/// Hashing procedure required by RFC5054 for certain variables.
///
/// RFC5054 requires left-padding pre-concatenated bytes with zeros if bytes
/// length less than that of the safe prime.
Future<List<int>> hashRfc5054({
    required List<List<int>> byteLists,
    required List<int> safePrime,
    required HashAlgorithm hashAlgorithm
}) async {
  var bytes = <int>[];
  for (var byteList in byteLists) {
    //OPTIMIZE: More efficient way to generate zeros?
    bytes += List<int>.generate(safePrime.length - byteList.length, (index) => 0);
    bytes += byteList;
  }
  final hash = await hashAlgorithm.hash(bytes);
  return hash.bytes;
}
