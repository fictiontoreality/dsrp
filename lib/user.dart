import 'dart:convert' show utf8, base64;
import 'dart:typed_data';
import 'package:dsrp/defaults.dart' show defaultGenerator, defaultKdfChoice, defaultSafePrime, defaultSaltByteLengthForSaltedVerificationKey, deriveOptimalByteLengthForEphemeralKeys;
import 'package:dsrp/exceptions.dart' show AuthenticationFailure, CryptographicException, InvalidParameterException;
import 'package:dsrp/crypto/hash.dart';
import 'package:dsrp/crypto/kdf.dart';
import 'package:dsrp/rfc5054.dart';
import 'package:dsrp/server.dart' show Challenge;
import 'package:dsrp/util/bytes.dart';
import 'package:dsrp/util/collections.dart';
import 'package:dsrp/verify.dart' show verifyEphemeralKey;
import 'package:logging/logging.dart';

final _log = Logger('dsrp.User');

/// Salted verification key generated during user registration.
///
/// This data structure contains the verification key and salt that must be
/// stored on the server for future authentication. The verification key is
/// derived from the user's password using a KDF, but cannot be reversed to
/// recover the password.
///
/// **Usage:**
/// 1. User generates this during registration via [User.createSaltedVerificationKey].
/// 2. User sends [key] and [salt] to server (e.g., via JSON serialization).
/// 3. Server stores both values in its user database.
/// 4. During future logins, server uses these values to create authentication challenges.
///
/// **Security:**
/// - The verification key is password-equivalent data - protect it like a password hash.
/// - Never send the verification key back to the user after registration.
/// - Use [erase] to securely zero out the data when no longer needed.
class SaltedVerificationKey {
  /// Verification key derived from password and salt (password verifier 'v').
  ///
  /// This is calculated as v = g^x mod N, where x is the user's private key
  /// derived from their password and salt.
  final Uint8List key;

  /// Cryptographic salt used during key derivation.
  ///
  /// This random value ensures that two users with the same password will have
  /// different verification keys. Must be stored alongside the key and provided
  /// during authentication.
  final Uint8List salt;

  SaltedVerificationKey({required this.key, required this.salt});

  /// Converts this object to a JSON-serializable map.
  ///
  /// Binary data is encoded as base64 strings for safe transmission over JSON.
  ///
  /// Example:
  /// ```dart
  /// final json = saltedKey.toJson();
  /// final jsonString = jsonEncode(json); // Serialize to JSON string
  /// ```
  Map<String, dynamic> toJson() => {
    'key': base64.encode(key),
    'salt': base64.encode(salt),
  };

  /// Creates a [SaltedVerificationKey] from a JSON map.
  ///
  /// Binary data should be base64-encoded strings in the JSON.
  ///
  /// Example:
  /// ```dart
  /// final decoded = jsonDecode(jsonString);
  /// final saltedKey = SaltedVerificationKey.fromJson(decoded);
  /// ```
  static SaltedVerificationKey fromJson(Map<String, dynamic> json) {
    return SaltedVerificationKey(
      key: base64.decode(json['key'] as String),
      salt: base64.decode(json['salt'] as String),
    );
  }

  /// Securely overwrites all sensitive data with zeros.
  ///
  /// Call this method when the verification key data is no longer needed
  /// (e.g., after successfully sending it to the server) to prevent the
  /// password-derived data from lingering in memory.
  void erase() {
    key.overwriteWithZeros();
    salt.overwriteWithZeros();
  }
}

/// Session verifiers sent from user to server during authentication.
///
/// This data structure contains the information needed for the server to verify
/// the user's identity and session key. It is generated after the user processes
/// the server's challenge.
///
/// **Usage:**
/// 1. User creates this via [User.getUserSessionVerifiers] after processing challenge.
/// 2. User sends all three fields to server (e.g., via JSON serialization).
/// 3. Server uses these values to verify the user's identity and session key.
/// 4. If verification succeeds, server responds with a server session key verifier.
///
/// **Security:**
/// - The session key verifier (M1) proves the user knows the password without revealing it.
/// - The ephemeral public key (A) is safe to transmit over untrusted networks.
/// - Use [erase] to securely zero out the data when no longer needed.
class UserSessionVerifiers {
  /// User identifier (username, email, or unique ID).
  ///
  /// This must match the user ID used during registration and challenge creation.
  String userId;

  /// User's ephemeral public key (A) generated for this authentication session.
  ///
  /// This temporary public key is used in combination with the server's ephemeral
  /// public key to derive the shared session key.
  final Uint8List ephemeralUserPublicKey;

  /// User's session key verifier (M1).
  ///
  /// This proves to the server that the user has correctly derived the session
  /// key, which in turn proves they know the password, without revealing the
  /// password or session key.
  final Uint8List sessionKeyVerifier;

  UserSessionVerifiers({
      required this.userId,
      required this.ephemeralUserPublicKey,
      required this.sessionKeyVerifier
  });

  /// Converts this object to a JSON-serializable map.
  ///
  /// Binary data is encoded as base64 strings for safe transmission over JSON.
  ///
  /// Example:
  /// ```dart
  /// final json = verifiers.toJson();
  /// final jsonString = jsonEncode(json); // Serialize to JSON string
  /// ```
  Map<String, dynamic> toJson() => {
    'userId': userId,
    'ephemeralUserPublicKey': base64.encode(ephemeralUserPublicKey),
    'sessionKeyVerifier': base64.encode(sessionKeyVerifier),
  };

  /// Creates a [UserSessionVerifiers] from a JSON map.
  ///
  /// Binary data should be base64-encoded strings in the JSON.
  ///
  /// Example:
  /// ```dart
  /// final decoded = jsonDecode(jsonString);
  /// final verifiers = UserSessionVerifiers.fromJson(decoded);
  /// ```
  static UserSessionVerifiers fromJson(Map<String, dynamic> json) {
    return UserSessionVerifiers(
      userId: json['userId'] as String,
      ephemeralUserPublicKey: base64.decode(json['ephemeralUserPublicKey'] as String),
      sessionKeyVerifier: base64.decode(json['sessionKeyVerifier'] as String),
    );
  }

  /// Securely overwrites all sensitive data with zeros.
  ///
  /// Call this method after successfully sending the verifiers to the server
  /// to prevent the ephemeral key and session verifier from lingering in memory.
  void erase() {
    userId = ''; // Allows string to be GC.
    ephemeralUserPublicKey.overwriteWithZeros();
    sessionKeyVerifier.overwriteWithZeros();
  }
}

/// Operations the user / client performs to register and authenticate with a
/// server via SRP.
///
/// Once authentication is complete, store the session key somewhere, then
/// ensure sensitive information in the [User] object is erased by allowing the
/// garbage collector to delete the object (i.e., allow all references to the
/// object to go out of scope and/or be set to null). The object internally
/// attempts to delete data as soon as it is no longer needed.
///
/// Designed to mimic the API of Python's pysrp library.
class User {

  /// User identifier (UTF-8 encoded bytes).
  ///
  /// Used to derive the session key verifier, and optionally the user private
  /// key.
  ///
  /// If the user ID is used to derive the private key, it is recommended to use
  /// a unique ID which does not change when the user-selected username changes.
  /// This avoids having to re-perform SRP user registration when the username
  /// changes.
  Uint8List? _userIdBytes;
  /// User password (UTF-8 encoded bytes).
  ///
  /// Used to derive the user private key.
  ///
  /// To increase the difficulty of attacks on SRP, follow standard secure
  /// password requirements such as those suggested by NIST (e.g., long
  /// passwords that are difficult to guess).
  ///
  /// Stored as Uint8List to allow secure erasure from memory.
  Uint8List? _passwordBytes;
  /// Hash algorithm used during SRP ephemeral key and verifier calculations (e.g., SHA256).
  final HashFunction _hashFunction;
  /// Secure KDF algorithm used to derive user private key.
  final Kdf _kdf;
  /// A generator modulo N (the safe prime).
  /// Typically denoted 'g'.
  final BigInt generator;
  /// A large, safe prime.
  /// Typically denoted 'N'.
  /// By definition a safe prime N = 2q + 1, where q is a Sophie Germain prime.
  /// All arithmetic is performed in the field of integers modulo N.
  final BigInt safePrime;
  /// See [safePrime].
  final Uint8List _safePrimeBytes;

  /// If true, use user ID along with password in KDF to generate user private
  /// key. Otherwise only the password is used.
  ///
  /// Only using the password avoids the need to regenerate the user private key
  /// if the user ID changes. Alternatively, a unique user ID,
  /// which does not change when the username changes, can be used.
  final bool useUserIdInPrivateKey;

  /// Salt used to generate the user private key when deriving the session key
  /// verifier.
  final Uint8List _verifierKeySalt;

  /// See [sessionKey].
  late final Uint8List _sessionKey;
  /// To be sent to the server so it can verify the user and the user's derived
  /// session key.
  late final Uint8List _userSessionKeyVerifier;

  /// Shared symmetric session key derived during authentication.
  ///
  /// This key can be used for encrypting messages between user and server,
  /// supplementing TLS encryption. Consider deriving separate keys from this
  /// master key using HKDF for different purposes (authentication, encryption, integrity).
  ///
  /// Note that SRP can be used purely for authentication and generating a
  /// session token / cookie, and need not be used to encrypt messages.
  Uint8List get sessionKey => Uint8List.fromList(_sessionKey);

  /// Ephemeral asymmetric private key generated by user during authentication and then discarded.
  BigInt? _ephemeralUserPrivateKey;
  /// Ephemeral asymmetric public key generated by user during authentication and then discarded.
  Uint8List? _ephemeralUserPublicKeyBytes;

  /// As part of initial user authentication handshake, create a [User] from a
  /// [challenge] provided by the server.
  ///
  /// WARNING: If the server provides the core SRP parameters (safe prime,
  /// generator, hash algorithm) it is highly recommended for the client to
  /// verify they are cryptographically secure. This could include checking the
  /// hash algorithm is one of those expected, and that the safe prime and
  /// generator and secure (see [verifySafePrime] and [verifyGenerator]).
  ///
  /// Enable [useUserIdInPrivateKey] if the user ID was used for key generation
  /// during user registration. See [createSaltedVerificationKey] for details.
  /// If [useUserIdInPrivateKey] is false, the user ID is only used to generate
  /// the user-side verifier.
  ///
  /// If [kdf] is not provided, Argon2id is used since it is slow and
  /// hence relatively secure. Be sure this KDF matches the one used during
  /// registration. Alternatively, provide [customKdf] to use a custom KDF
  /// implementation (cannot provide both [kdf] and [customKdf]).
  ///
  /// If a [ephemeralUserPrivateKey] is not provided, one is generated.
  ///
  /// For improved security, use [fromUserCredsBytesAndChallenge] to pass
  /// credentials as Uint8List instead of String.
  static Future<User> fromUserCredsAndChallenge({
    required String userId,
    required String password,
    required Challenge challenge,
    final bool useUserIdInPrivateKey = true,
    KdfChoice? kdf,
    Kdf? customKdf,
    final Uint8List? ephemeralUserPrivateKey,
  }) async {
    return fromUserCredsBytesAndChallenge(
      userIdBytes: userId.utf8Bytes,
      passwordBytes: password.utf8Bytes,
      challenge: challenge,
      useUserIdInPrivateKey: useUserIdInPrivateKey,
      kdf: kdf,
      customKdf: customKdf,
      ephemeralUserPrivateKey: ephemeralUserPrivateKey,
    );
  }

  /// As part of initial user authentication handshake, create a [User] from a
  /// [challenge] provided by the server.
  ///
  /// WARNING: If the server provides the core SRP parameters (safe prime,
  /// generator, hash algorithm) it is highly recommended for the client to
  /// verify they are cryptographically secure. This could include checking the
  /// hash algorithm is one of those expected, and that the safe prime and
  /// generator and secure (see [verifySafePrime] and [verifyGenerator]).
  ///
  /// Enable [useUserIdInPrivateKey] if the user ID was used for key generation
  /// during user registration. See [createSaltedVerificationKey] for details.
  /// If [useUserIdInPrivateKey] is false, the user ID is only used to generate
  /// the user-side verifier.
  ///
  /// If [kdf] is not provided, Argon2id is used since it is slow and
  /// hence relatively secure. Be sure this KDF matches the one used during
  /// registration. Alternatively, provide [customKdf] to use a custom KDF
  /// implementation (cannot provide both [kdf] and [customKdf]).
  ///
  /// If a [ephemeralUserPrivateKey] is not provided, one is generated.
  ///
  /// This method is preferred over [fromUserCredsAndChallenge] for security
  /// reasons, as it avoids storing passwords as Strings in memory.
  ///
  /// [userIdBytes] and [passwordBytes] should be UTF-8 encoded credentials.
  static Future<User> fromUserCredsBytesAndChallenge({
    required Uint8List userIdBytes,
    required Uint8List passwordBytes,
    required Challenge challenge,
    final bool useUserIdInPrivateKey = true,
    HashFunction? customHashFunction,
    KdfChoice? kdf,
    Kdf? customKdf,
    final Uint8List? ephemeralUserPrivateKey,
  }) async {
    final resolvedKdf = _resolveKdf(kdf, customKdf);
    final resolvedHashFunction = _resolveHashFunction(
      challenge, customHashFunction);

    final user = User._(
      userIdBytes: userIdBytes,
      passwordBytes: passwordBytes,
      generator: challenge.generator,
      safePrime: challenge.safePrime,
      verifierKeySalt: challenge.verifierKeySalt,
      useUserIdInPrivateKey: useUserIdInPrivateKey,
      hashFunction: resolvedHashFunction,
      kdf: resolvedKdf,
    );
    user._generateEphemeralUserAsymmetricKeys(
      ephemeralUserPrivateKeyBytes: ephemeralUserPrivateKey);
    // Derives session key and its user-side verifier M1.
    await user._processChallenge(challenge);
    return user;
  }

  User._({
    required Uint8List userIdBytes,
    required Uint8List passwordBytes,
    required this.generator,
    required this.safePrime,
    required Uint8List verifierKeySalt,
    required this.useUserIdInPrivateKey,
    required HashFunction hashFunction,
    required Kdf kdf,
  }): _userIdBytes = Uint8List.fromList(userIdBytes),
      _passwordBytes = Uint8List.fromList(passwordBytes),
      _safePrimeBytes = safePrime.toByteList(),
      _verifierKeySalt = Uint8List.fromList(verifierKeySalt),
      _hashFunction = hashFunction,
      _kdf = kdf;

  /// Creates a salted verification key.
  ///
  /// Pass this key to server as part of user registration request.
  ///
  /// WARNING: If [safePrime] is not provided, the default safe prime provided
  /// by dsrp is used. This should NOT be done in production. You are encouraged
  /// to generate your own safe prime instead to reduce the chance of a
  /// pre-computed attack on common safe primes impacting your users.
  ///
  /// If [kdf] is not provided, Argon2id is used since it is slow and
  /// hence relatively secure. Alternatively, provide [customKdf] to use a
  /// custom KDF implementation (cannot provide both [kdf] and [customKdf]).
  ///
  /// If [salt] is not provided then a 32-byte random salt is generated.
  ///
  /// Only provide [userId] if you want derivation of the user private key to
  /// include it, as is done in the RFC5054 standard. Not including the user ID
  /// means if the ID changes, the user private key will need to be regenerated
  /// and the user registration process repeated. When key derivation excludes
  /// the user ID, re-registration is only needed if the password changes.
  ///
  /// Another option is to provide a unique, fixed [userId] (e.g., a UUID, user
  /// database index, etc.) that is different from the user-chosen ID. That
  /// allows the user to change their login ID while their internal user ID
  /// remains constant.
  ///
  /// For improved security, use [createSaltedVerificationKeyFromBytes] to pass
  /// credentials as Uint8List instead of String.
  static Future<SaltedVerificationKey> createSaltedVerificationKey({
      required String password,
      String? userId,
      BigInt? generator, BigInt? safePrime,
      KdfChoice? kdf,
      Kdf? customKdf,
      Uint8List? salt
  }) async {
    return createSaltedVerificationKeyFromBytes(
      passwordBytes: password.utf8Bytes,
      userIdBytes: userId?.utf8Bytes,
      generator: generator,
      safePrime: safePrime,
      kdf: kdf,
      customKdf: customKdf,
      salt: salt,
    );
  }

  /// Creates a salted verification key from byte arrays.
  ///
  /// Pass this key to server as part of user registration request.
  ///
  /// WARNING: If [safePrime] is not provided, the default safe prime provided
  /// by dsrp is used. This should NOT be done in production. You are encouraged
  /// to generate your own safe prime instead to reduce the chance of a
  /// pre-computed attack on common safe primes impacting your users.
  ///
  /// If [kdf] is not provided, Argon2id is used since it is slow and
  /// hence relatively secure. Alternatively, provide [customKdf] to use a
  /// custom KDF implementation (cannot provide both [kdf] and [customKdf]).
  ///
  /// If [salt] is not provided then a 32-byte random salt is generated.
  ///
  /// Only provide [userIdBytes] if you want derivation of the user private key
  /// to include it, as is done in the RFC5054 standard. Not including the user
  /// ID means if the ID changes, the user private key will need to be
  /// regenerated and the user registration process repeated. When key
  /// derivation excludes the user ID, re-registration is only needed if the
  /// password changes.
  ///
  /// Another option is to provide a unique, fixed [userIdBytes] (e.g., a UUID,
  /// user database index, etc.) that is different from the user-chosen ID. That
  /// allows the user to change their login ID while their internal user ID
  /// remains constant.
  ///
  /// For improved security, use [createSaltedVerificationKeyFromBytes] to pass
  /// credentials as Uint8List instead of String.
  ///
  /// This method is preferred over [createSaltedVerificationKey] for security
  /// reasons, as it avoids storing passwords as Strings in memory.
  ///
  /// [passwordBytes] and [userIdBytes] should be UTF-8 encoded credentials.
  static Future<SaltedVerificationKey> createSaltedVerificationKeyFromBytes({
      required Uint8List passwordBytes,
      Uint8List? userIdBytes,
      BigInt? generator, BigInt? safePrime,
      KdfChoice? kdf,
      Kdf? customKdf,
      Uint8List? salt
  }) async {
    if (kdf != null && customKdf != null) {
      throw InvalidParameterException(
        'Cannot provide both kdf and customKdf. Please provide only one.'
      );
    }
    if (safePrime == null) {
      _log.warning('Using default safe prime. For production use, generate a custom safe prime using scripts/generate_safe_primes to reduce risk of pre-computed attacks.');
    }
    final generatorBigInt = generator ?? defaultGenerator;
    final safePrimeBigInt = safePrime ?? defaultSafePrime;

    final resolvedKdf = customKdf ?? getKdf(kdf ?? defaultKdfChoice);
    salt ??= generateRandomBytes(defaultSaltByteLengthForSaltedVerificationKey);
    final privateKey = await _derivePrivateKey(
      userIdBytes: userIdBytes,
      passwordBytes: passwordBytes,
      salt: salt,
      kdf: resolvedKdf
    );

    final verifierKey = _deriveVerificationKey(privateKey: privateKey,
      generator: generatorBigInt, safePrime: safePrimeBigInt);
    final verifierKeyBytes = verifierKey.toByteList();
    return SaltedVerificationKey(
      key: verifierKeyBytes,
      salt: salt,
    );
  }

  /// Generates ephemeral user public and private keys which are used only
  /// during SRP login and then discarded.
  void _generateEphemeralUserAsymmetricKeys({Uint8List? ephemeralUserPrivateKeyBytes}) {
    ephemeralUserPrivateKeyBytes ??= generateRandomBytes(
      deriveOptimalByteLengthForEphemeralKeys(safePrime.bitLength)
    );
    _ephemeralUserPrivateKey = ephemeralUserPrivateKeyBytes.toBigInt();
    // A = g^a
    final publicKey = generator.modPow(_ephemeralUserPrivateKey!, safePrime);
    _ephemeralUserPublicKeyBytes = publicKey.toByteList();
  }

  /// Processes challenge from server, deriving session key and its verifier.
  ///
  /// Session key verifier is often denoted 'M' or 'M1'.
  Future<void> _processChallenge(Challenge challenge) async {
    _sessionKey = await _deriveSessionKey(
      challenge.verifierKeySalt,
      challenge.ephemeralServerPublicKey
    );
    // H(N)
    final hashedSafePrime = (
      await _hashFunction.hash(safePrime.toByteList())
    ).toBigInt();
    // H(g)
    final hashedGenerator = (
      await _hashRfc5054([generator.toByteList()])
    ).toBigInt();
    // H(I)
    final hashedUserId = await _hashFunction.hash(_userIdBytes!);
    // H(N) xor H(g)
    final hashedSafePrimeAndGenerator = (hashedSafePrime ^ hashedGenerator).toByteList();
    // M1 = H(H(N) xor H(g), H(I), s, A, B, K)
    final combined = Uint8List.fromList(
        hashedSafePrimeAndGenerator +
        hashedUserId +
        challenge.verifierKeySalt +
        _ephemeralUserPublicKeyBytes! +
        challenge.ephemeralServerPublicKey +
        _sessionKey
    );
    _userSessionKeyVerifier = await _hashFunction.hash(combined);
  }

  /// Retrieves user session verifiers to send to server for authentication.
  ///
  /// This method should be called after creating a [User] from a challenge via
  /// [fromUserCredsAndChallenge] or [fromUserCredsBytesAndChallenge]. The
  /// returned verifiers must be sent to the server to complete the
  /// authentication handshake.
  ///
  /// **Side effects:** Securely erases the internal user ID bytes after they
  /// are no longer needed.
  UserSessionVerifiers getUserSessionVerifiers() {
    final verifiers = UserSessionVerifiers(
      userId: utf8.decode(_userIdBytes!),
      ephemeralUserPublicKey: Uint8List.fromList(_ephemeralUserPublicKeyBytes!),
      sessionKeyVerifier: Uint8List.fromList(_userSessionKeyVerifier),
    );
    // Securely erase userId bytes now that they're no longer needed.
    _userIdBytes!.overwriteWithZeros();
    _userIdBytes = null;
    return verifiers;
  }

  /// Verifies the server's identity by checking the server session key verifier.
  ///
  /// This is the final step in the mutual authentication process. The server
  /// computes a verifier (M2) from its view of the session, and the user must
  /// verify it matches the expected value to confirm the server's identity.
  ///
  /// **Parameters:**
  /// - [serverSessionKeyVerifier]: The server's session key verifier (M2) received
  ///   from the server after it verified the user.
  ///
  /// **Throws:**
  /// - [AuthenticationFailure] if the server's verifier doesn't match the expected
  ///   value, indicating either a compromised server or network attack. Authentication
  ///   should be abandoned in this case.
  ///
  /// **Side effects:** Securely erases ephemeral keys and user session verifier
  /// after verification completes.
  Future<void> verifySession(Uint8List serverSessionKeyVerifier) async {
    // M2 = H(A, M, K)
    final combined = Uint8List.fromList(
        _ephemeralUserPublicKeyBytes! + _userSessionKeyVerifier + _sessionKey
    );
    final expectedServerSessionKeyVerifier = await _hashFunction.hash(combined);
    if (!serverSessionKeyVerifier.shallowEquals(expectedServerSessionKeyVerifier)) {
      throw AuthenticationFailure('Server session key failed verification.');
    }

    // Securely delete items no longer needed.
    _ephemeralUserPublicKeyBytes?.overwriteWithZeros();
    _ephemeralUserPublicKeyBytes = null;
    _userSessionKeyVerifier.overwriteWithZeros();
  }

  /// Derives the user private key.
  ///
  /// RFC 5054 defines an unusual hash-based KDF:
  ///
  /// x = H(s, H( I | ':' | p ))
  ///
  /// While fast, this KDF is not secure against brute-force extraction of the
  /// password from the verifier, and a stronger (i.e., slower) KDF is
  /// recommended.
  static Future<BigInt> _derivePrivateKey({
      required Uint8List passwordBytes,
      required Uint8List salt,
      required Kdf kdf,
      Uint8List? userIdBytes,
  }) async {
    final privateKey = await kdf.deriveKeyFromPasswordBytes(
      passwordBytes: passwordBytes,
      salt: salt,
      userIdBytes: userIdBytes,
    );
    return privateKey.toBigInt();
  }

  /// Password verifier, a.k.a. verification key.
  /// 
  /// v = g^x
  static BigInt _deriveVerificationKey({
      required BigInt privateKey,
      required BigInt generator, required BigInt safePrime,
  }) {
    final saltedVerificationKey = generator.modPow(privateKey, safePrime);
    return saltedVerificationKey;
  }

  /// Calculates the session key which will later be used for encrypted
  /// communication with server.
  ///
  /// K = H( (B - kg^x) ^ (a + ux) ) = H( (B - kv) ^ (a + ux) )
  Future<Uint8List> _deriveSessionKey(
      Uint8List salt, Uint8List serverPublicKeyBytes) async {
    // x
    final privateKey = await _derivePrivateKey(
      userIdBytes: useUserIdInPrivateKey ? _userIdBytes : null,
      passwordBytes: _passwordBytes!,
      salt: _verifierKeySalt,
      kdf: _kdf,
    );
    // Erase no longer needed verifier key and user credentials.
    _verifierKeySalt.overwriteWithZeros();
    _passwordBytes!.overwriteWithZeros();
    _passwordBytes = null;
    // v = g^x
    final verifierKey = _deriveVerificationKey(
      privateKey: privateKey,
      generator: generator, safePrime: safePrime
    );
    // u = H(A,B)
    final randomScramblingParameter = (await _hashRfc5054(
        [_ephemeralUserPublicKeyBytes!, serverPublicKeyBytes]
    )).toBigInt();
    if (randomScramblingParameter == BigInt.zero) {
      throw CryptographicException('Random scrambling parameter (u = H(A,B)) is zero.');
    }
    // k = H(N,g)
    final multiplierParameter = (await _hashRfc5054(
        [safePrime.toByteList(), generator.toByteList()]
    )).toBigInt();
    // Notated 'B'.
    final serverPublicKey = serverPublicKeyBytes.toBigInt();
    verifyEphemeralKey(serverPublicKey, safePrime, 'B (server)');
    // B - k(g^x) = B - kv
    final firstTerm = serverPublicKey - multiplierParameter * verifierKey;
    // a + ux
    final secondTerm = _ephemeralUserPrivateKey! + randomScramblingParameter * privateKey;
    // No longer needed, let GC clean up.
    //
    // TODO: Consider finding a BigInt alternative that allows bypassing GC to
    // zero out value, while still being cross-platform performant.
    _ephemeralUserPrivateKey = null;
    // S = (B - kv) ^ (a + ux)
    final secret = firstTerm.modPow(secondTerm, safePrime);
    // K = H( (B - kg^x) ^ (a + ux) ) = H( (B - kv) ^ (a + ux) ) = H(S)
    final sessionKey = await _hashFunction.hash(secret.toByteList());
    return sessionKey;
  }

  /// Utility method to perform a RFC 5054 compliant hash with appropriate
  /// padding and concatenation.
  Future<Uint8List> _hashRfc5054(List<Uint8List> byteLists) async {
    return hashRfc5054(
      byteLists: byteLists,
      safePrime: _safePrimeBytes,
      hashFunction: _hashFunction
    );
  }

  /// Resolve the KDF to use based on user parameters.
  static Kdf _resolveKdf(KdfChoice? kdf, Kdf? customKdf) {
    if (kdf != null && customKdf != null) {
      throw InvalidParameterException(
        'Cannot provide both a KDF choice and a custom KDF. Please provide only one.'
      );
    }
    return customKdf ?? getKdf(kdf ?? defaultKdfChoice);
  }

  /// Resolve the hash function to use based on user parameters.
  static HashFunction _resolveHashFunction(
    Challenge challenge,
    HashFunction? customHashFunction,
  ) {
    if (challenge.isCustomHashFunction) {
      if (customHashFunction == null) {
        throw InvalidParameterException(
          'Server requires custom hash function, but none provided.'
        );
      } else if (customHashFunction.name != challenge.hashFunctionName) {
        throw InvalidParameterException(
          'Custom hash function name ${customHashFunction.name} does not match server requested hash function ${challenge.hashFunctionName}.'
        );
      }
      return customHashFunction;
    } else {
      final hashFunctionChoice = HashFunctionChoice.values.asNameMap()[
        challenge.hashFunctionName
      ];
      if (hashFunctionChoice == null) {
        throw InvalidParameterException(
          'Hash function in server challenge is not supported by this client, possibly due to client / server version mismatch.',
        );
      }
      return getHashFunction(hashFunctionChoice);
    }
  }
}
