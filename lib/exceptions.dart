class AuthenticationFailure implements Exception {
  final String cause;
  AuthenticationFailure(this.cause);
}
