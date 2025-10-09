/// Exception thrown when SRP authentication fails.
///
/// This can occur during session key verification when the user or server
/// provides an invalid verifier, or when cryptographic parameters are invalid.
class AuthenticationFailure implements Exception {
  final String message;

  AuthenticationFailure(this.message);

  @override
  String toString() => 'AuthenticationFailure: $message';
}

/// Exception thrown when invalid cryptographic parameters are provided.
///
/// This includes invalid safe primes, generators, ephemeral keys, or other
/// SRP protocol parameters that fail validation.
class InvalidParameterException implements Exception {
  final String message;

  InvalidParameterException(this.message);

  @override
  String toString() => 'InvalidParameterException: $message';
}

/// Exception thrown when a cryptographic operation fails.
///
/// This includes failures during key derivation, random number generation,
/// or other cryptographic operations that are not authentication-specific.
class CryptographicException implements Exception {
  final String message;

  CryptographicException(this.message);

  @override
  String toString() => 'CryptographicException: $message';
}

/// Exception thrown when an unsupported algorithm is requested.
///
/// This occurs when an unknown hash algorithm or KDF algorithm choice is
/// provided.
class UnsupportedAlgorithmException implements Exception {
  final String message;

  UnsupportedAlgorithmException(this.message);

  @override
  String toString() => 'UnsupportedAlgorithmException: $message';
}
