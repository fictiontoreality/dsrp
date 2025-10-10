/// Common methods required by agents (user, server) implementing RFC5054.
library;

import 'dart:typed_data';
import 'package:dsrp/crypto/hash.dart';

/// Hashing procedure required by RFC5054 for certain variables.
///
/// RFC5054 requires left-padding pre-concatenated bytes with zeros if bytes
/// length less than that of the safe prime.
Future<Uint8List> hashRfc5054({
    required List<Uint8List> byteLists,
    required Uint8List safePrime,
    required HashFunction hashFunction
}) async {
  // Build the padded byte array.
  int totalSize =  byteLists.length * safePrime.length;
  final bytes = Uint8List(totalSize);
  int offset = 0;
  for (var byteList in byteLists) {
    // Left-pad with zeros.
    final paddingLength = safePrime.length - byteList.length;
    // Since Uint8List is zero-initialized, just copy the actual bytes.
    bytes.setRange(offset + paddingLength, offset + safePrime.length, byteList);
    offset += safePrime.length;
  }

  final hash = await hashFunction.hash(bytes);
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
