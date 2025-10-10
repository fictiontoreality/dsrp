/// Bytes utilities: conversion, generation, etc.
library;

import 'dart:convert' show utf8;
import 'dart:math' show Random;
import 'dart:typed_data' show Endian, Uint8List;

/// Convert byte list to int.
int convertByteListToInt(List<int> bytes) {
  return Uint8List.fromList(bytes).buffer.asByteData().getInt64(0);
}

/// Convert 64-bit int to byte list.
/// Source: https://stackoverflow.com/a/57536472/376497
Uint8List convertIntToByteList(int number) {
  final byteList = Uint8List(8);
  byteList.buffer.asByteData().setInt64(0, number, Endian.big);
  return byteList;
}

/// Convert a byte list to a BigInt.
/// Source: https://github.com/dart-lang/sdk/issues/32803#issuecomment-1228291047
BigInt convertByteListToBigInt(List<int> bytes) {
  BigInt result = BigInt.zero;

  for (final byte in bytes) {
    // Reading in big-endian, so we essentially concat the new byte to the end.
    result = (result << 8) | BigInt.from(byte & 0xff);
  }
  return result;
}

/// Convert a BigInt to a byte list.
/// Source: https://github.com/dart-lang/sdk/issues/32803#issuecomment-1228291047
Uint8List convertBigIntToByteList(BigInt number) {
  // Not handling negative numbers. Decide how you want to do that.
  int byteCount = (number.bitLength + 7) >> 3;

  // Special case: zero should be represented as [0], not [].
  if (byteCount == 0) {
    return Uint8List.fromList([0]);
  }

  var b256 = BigInt.from(256);
  var result = Uint8List(byteCount);
  for (int i = 0; i < byteCount; i++) {
    result[byteCount - 1 - i] = number.remainder(b256).toInt();
    number = number >> 8;
  }
  return result;
}

/// Generate bytes with a cryptographically secure pseudorandom number
/// generator (CSPRNG).
Uint8List generateRandomBytes(int bytesCount) {
  final random = Random.secure();
  final result = Uint8List(bytesCount);
  for (int i = 0; i < bytesCount; i++) {
    result[i] = random.nextInt(256);
  }
  return result;
}

extension BigIntToByteList on BigInt {
  Uint8List toByteList() {
    return convertBigIntToByteList(this);
  }
}

extension ByteListToBigInt on List<int> {
  BigInt toBigInt() {
    return convertByteListToBigInt(this);
  }
}

/// Generates a random BigInt in the range [min, max].
BigInt generateRandomBigInt(BigInt min, BigInt max) {
  final range = max - min + BigInt.one;
  final bytesNeeded = (range.bitLength + 7) ~/ 8;

  BigInt result;
  do {
    final bytes = generateRandomBytes(bytesNeeded);
    result = bytes.toBigInt();
  } while (result >= range);

  return result + min;
}

/// Extension for converting strings to bytes for secure handling.
extension StringToBytes on String {
  /// This extension provides a convenient way to convert strings (such as
  /// passwords, user IDs, or other sensitive data) to [Uint8List] for use in
  /// cryptographic operations.
  ///
  /// The returned [Uint8List] can be zeroed out after use by calling
  /// [overwriteWithZeros()] to prevent sensitive data from lingering in memory.
  ///
  /// **Important**: The original string will remain in memory until garbage
  /// collected. For maximum security, obtain sensitive data directly as bytes
  /// when possible rather than as strings.
  /// 
  /// **Security Best Practices:**
  ///
  /// 1. **Use [Uint8List] for sensitive data**: Unlike [String], [Uint8List] can
  ///    be zeroed out after use to prevent sensitive data from lingering in
  ///    memory. Always call [overwriteWithZeros()] on the resulting bytes when
  ///    done.
  ///
  /// 2. **Minimize string lifetime**: Convert strings to bytes as early as
  ///    possible and zero them out as soon as they're no longer needed.
  ///
  /// 3. **Avoid string copies**: Strings are immutable in Dart and cannot be
  ///    securely erased from memory. The original string may persist in memory
  ///    until garbage collected.
  ///
  /// **Example usage:**
  /// ```dart
  /// // Convert password to bytes
  /// final passwordBytes = password.utf8Bytes;
  ///
  /// // Use the bytes for cryptographic operations
  /// final saltedKey = await User.createSaltedVerificationKey(
  ///   userId: 'alice',
  ///   password: passwordBytes,
  /// );
  ///
  /// // Zero out sensitive data when done
  /// passwordBytes.overwriteWithZeros();
  /// ```
  ///
  /// **When to use this:**
  /// - Passwords
  /// - Passphrases
  /// - Secret keys
  /// - User identifiers (if privacy-sensitive)
  /// - Any sensitive string data used in cryptographic operations
  Uint8List get utf8Bytes {
    return Uint8List.fromList(utf8.encode(this));
  }
}
