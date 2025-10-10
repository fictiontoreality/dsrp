/// Common methods required by agents (user, server) implementing RFC5054.
library;

import 'dart:typed_data';
import 'package:dsrp/crypto/hash.dart';

/// Hashing procedure required by RFC5054 for certain variables.
///
/// RFC5054 requires left-padding pre-concatenated bytes with zeros if bytes
/// length less than that of the safe prime.
Future<Uint8List> hashRfc5054({
    required List<List<int>> byteLists,
    required List<int> safePrime,
    required HashFunction hashFunction
}) async {
  var bytes = <int>[];
  for (var byteList in byteLists) {
    //OPTIMIZE: More efficient way to generate zeros?
    bytes += List<int>.generate(safePrime.length - byteList.length, (index) => 0);
    bytes += byteList;
  }
  final hash = await hashFunction.hash(Uint8List.fromList(bytes));
  return hash;
}

/// Returns `userId:password` if [userIdBytes] is non-null, else
/// [passwordBytes].
///
/// This is the input (I | ':' | p) of the first hash which RFC5054 uses to
/// derive the user private key using a hash-based KDF:
///
/// x = H(s, H(I | ':' | p))
///
/// More secure KDFs can also make use of this concatenation as input without
/// necessarily using the RFC5054 first or second hash.
Uint8List concatenateUserIdAndPassword(
  Uint8List? userIdBytes, Uint8List passwordBytes
) {
  if (userIdBytes != null) {
    const colonByte = 0x3A; // ASCII colon character
    return Uint8List.fromList([
        ...userIdBytes,
        colonByte,
        ...passwordBytes,
    ]);
  } else {
    return passwordBytes;
  }
}
