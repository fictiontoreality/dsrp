import 'dart:math' show Random;
import 'dart:typed_data' show Endian, Uint8List;

//TODO: OK to reuse?
final random = Random.secure();

/// Convert byte list to int.
int convertByteListToInt(List<int> bytes) {
  return Uint8List.fromList(bytes).buffer.asByteData().getInt64(0);
}

/// Convert 64-bit int to byte list.
/// Source: https://stackoverflow.com/a/57536472/376497
List<int> convertIntToByteList(int number) {
  final byteList = Uint8List(8);
  // verifierKeyBytes.buffer.asInt64List()[0] = verifierKey;
  byteList.buffer.asByteData().setInt64(0, number, Endian.big);
  return byteList;
}

/// Convert a byte list to a BigInt.
/// Source: https://github.com/dart-lang/sdk/issues/32803#issuecomment-1228291047
BigInt convertByteListToBigInt(List<int> bytes) {
  BigInt result = BigInt.zero;

  for (final byte in bytes) {
    // reading in big-endian, so we essentially concat the new byte to the end
    result = (result << 8) | BigInt.from(byte & 0xff);
  }
  return result;
}

/// Convert a BigInt to a byte list.
/// Source: https://github.com/dart-lang/sdk/issues/32803#issuecomment-1228291047
List<int> convertBigIntToByteList(BigInt number) {
  // Not handling negative numbers. Decide how you want to do that.
  int bytes = (number.bitLength + 7) >> 3;
  var b256 = BigInt.from(256);
  var result = Uint8List(bytes);
  for (int i = 0; i < bytes; i++) {
    result[bytes - 1 - i] = number.remainder(b256).toInt();
    number = number >> 8;
  }
  return result;
}

/// Generate bytes with random values.
List<int> generateRandomBytes(int bytesCount) {
  return List<int>.generate(bytesCount, (index) => random.nextInt(256));
}
