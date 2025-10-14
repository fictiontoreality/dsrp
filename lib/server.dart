/// Server-side operations for SRP.
library;

import 'dart:convert' show base64;
import 'dart:typed_data';
import 'package:dsrp/defaults.dart' show defaultGenerator, defaultHashFunctionChoice, defaultSafePrime, deriveOptimalByteLengthForEphemeralKeys;
import 'package:dsrp/exceptions.dart' show AuthenticationFailure, InvalidParameterException;
import 'package:dsrp/crypto/hash.dart';
import 'package:dsrp/rfc5054.dart';
import 'package:dsrp/util/bytes.dart';
import 'package:dsrp/util/collections.dart';
import 'package:dsrp/verify.dart' show verifyEphemeralKey;
import 'package:logging/logging.dart';

final _log = Logger('dsrp.Server');

/// Challenge server offers to the user to verify their identity.
///
/// This provides the user the minimum data needed from the server to generate
/// the session key and its verifier.
///
/// **Note:** Custom hash functions must be passed in along with this
/// challenge to [User.fromUserCredsAndChallenge]. Otherwise a runtime
/// exception may occur, or if there is a built-in hash function with the same
/// name it may be used instead of the custom hash function.
///
/// **WARNING:** If the server provides the core SRP parameters (safe prime,
/// generator, hash algorithm) it is highly recommended for the client to verify
/// they are cryptographically secure. This could include checking the hash
/// algorithm is one of those permitted, and that the safe prime, generator and
/// salt are secure (see [verifySafePrime], [verifyGenerator], [verifySalt]).
class Challenge {
  final BigInt generator;
  final BigInt safePrime;
  final Uint8List ephemeralServerPublicKey;
  final Uint8List verifierKeySalt;
  final String hashFunctionName;
  final bool isCustomHashFunction;

  Challenge.fromServer({
      required this.generator,
      required this.safePrime,
      required this.ephemeralServerPublicKey,
      required this.verifierKeySalt,
      HashFunctionChoice? hashFunctionChoice,
      HashFunction? customHashFunction,
  }): hashFunctionName = customHashFunction?.name ?? hashFunctionChoice?.name ?? '',
      isCustomHashFunction = customHashFunction != null {
    if (hashFunctionChoice == null && customHashFunction == null) {
      throw InvalidParameterException('Either a hash function choice or custom hash function must be provided.');
    }
  }

  Challenge._({
      required this.generator,
      required this.safePrime,
      required this.ephemeralServerPublicKey,
      required this.verifierKeySalt,
      required this.hashFunctionName,
      required this.isCustomHashFunction,
  });

  /// Converts this object to a JSON-serializable map.
  ///
  /// Binary data is encoded as base64 strings, and BigInt values are encoded
  /// as decimal strings for safe transmission over JSON.
  ///
  /// Example:
  /// ```dart
  /// final json = challenge.toJson();
  /// final jsonString = jsonEncode(json); // Serialize to JSON string
  /// ```
  Map<String, dynamic> toJson() => {
    'generator': generator.toString(),
    'safePrime': safePrime.toString(),
    'ephemeralServerPublicKey': base64.encode(ephemeralServerPublicKey),
    'verifierKeySalt': base64.encode(verifierKeySalt),
    'hashFunctionName': hashFunctionName,
    'isCustomHashFunction': isCustomHashFunction,
  };

  /// Creates a [Challenge] from a JSON map.
  ///
  /// Binary data should be base64-encoded strings, and BigInt values should be
  /// decimal strings in the JSON.
  ///
  /// Example:
  /// ```dart
  /// final decoded = jsonDecode(jsonString);
  /// final challenge = Challenge.fromJson(decoded);
  /// ```
  static Challenge fromJson(Map<String, dynamic> json) {
    return Challenge._(
      generator: BigInt.parse(json['generator'] as String),
      safePrime: BigInt.parse(json['safePrime'] as String),
      ephemeralServerPublicKey: base64.decode(json['ephemeralServerPublicKey'] as String),
      verifierKeySalt: base64.decode(json['verifierKeySalt'] as String),
      hashFunctionName: json['hashFunctionName'],
      isCustomHashFunction: json['isCustomHashFunction'],
    );
  }

  /// Securely overwrites all sensitive data with zeros.
  ///
  /// Call this method after successfully sending the challenge to the user
  /// to prevent the ephemeral server public key and salt from lingering in
  /// memory longer than necessary.
  void erase() {
    ephemeralServerPublicKey.overwriteWithZeros();
    verifierKeySalt.overwriteWithZeros();
  }
}

/// Operations the server / host performs to authenticate a user via SRP.
///
/// Designed to mimic the API of Python's pysrp library.
class Server {
  /// User identifier (UTF-8 encoded bytes).
  ///
  /// Stored as Uint8List to allow secure erasure from memory after hashing.
  final Uint8List _userIdBytes;
  /// Salt provided by user during registration.
  final Uint8List _salt;
  /// Verifier key provided by user during registration.
  BigInt _verifierKey;
  /// A generator modulo N.
  /// Typically denoted 'g'.
  final BigInt generator;
  /// Hash algorithm choice used during SRP key and verifier calculations (e.g., SHA256).
  /// Null if using a custom hash function.
  late final HashFunctionChoice? hashFunctionChoice;
  /// Hash algorithm used during SRP key and verifier calculations (e.g., SHA256).
  late final HashFunction _hashFunction;
  /// A large, safe prime.
  ///
  /// Typically denoted 'N'.
  /// By definition a safe prime N = 2q + 1, where q is a Sophie Germain prime.
  /// All arithmetic is performed in the field of integers modulo N.
  final BigInt safePrime;
  /// See [safePrime].
  final Uint8List _safePrimeBytes;

  /// Ephemeral asymmetric private key generated by server during authentication
  /// and then discarded.
  BigInt? _ephemeralServerPrivateKey;
  /// Ephemeral asymmetric public key generated by server during authentication
  /// and then discarded.
  Uint8List? _ephemeralServerPublicKey;
  /// See [sessionKey].
  Uint8List? _sessionKey;

  /// Shared symmetric session key derived during authentication.
  ///
  /// Returns `null` if session key has not been derived yet (call [deriveSessionKey]
  /// or [verifySession] first).
  ///
  /// This key can be used for encrypting messages between user and server,
  /// supplementing TLS encryption. Consider deriving separate keys from this
  /// master key using HKDF for different purposes (authentication, encryption, integrity).
  ///
  /// Note that SRP can be used purely for authentication and generating a
  /// session token / cookie, and need not be used to encrypt messages.
  Uint8List? get sessionKey => _sessionKey != null ? Uint8List.fromList(_sessionKey!) : null;

  /// Creates a Server instance for SRP authentication.
  Server({
      required final String userId,
      required final Uint8List salt,
      required final Uint8List verifierKey,
      final BigInt? generator,
      final BigInt? safePrime,
      final HashFunctionChoice? hashFunction,
      final HashFunction? customHashFunction,
  }): _userIdBytes = userId.utf8Bytes,
       _salt = Uint8List.fromList(salt),
       _verifierKey = verifierKey.toBigInt(),
       generator = generator ?? defaultGenerator,
       _safePrimeBytes = safePrime?.toByteList() ?? defaultSafePrime.toByteList(),
       safePrime = safePrime ?? defaultSafePrime {
    _resolveHashFunction(hashFunction, customHashFunction);
    
    if (safePrime == null) {
      _log.warning('Using default safe prime. For production use, generate a custom safe prime using scripts/generate_safe_primes to reduce risk of pre-computed attacks.');
    }
  }

  /// Creates an authentication challenge to send to the user.
  ///
  /// This is the first step in the SRP authentication flow. The server generates
  /// an ephemeral key pair and creates a challenge containing the public key,
  /// salt, and SRP parameters.
  ///
  /// **Parameters:**
  /// - [ephemeralServerPrivateKeyBytes]: Optional custom ephemeral private key.
  ///   If not provided, a random key of optimal length is generated automatically.
  ///
  /// **Returns:** [Challenge] object containing the server's ephemeral public key (B),
  /// salt, generator, safe prime, and hash function choice. Send this to the user
  /// to begin authentication.
  ///
  /// **Security note:** The ephemeral private key is stored internally and used
  /// later during session key derivation. It is automatically erased after use.
  Future<Challenge> createChallenge({Uint8List? ephemeralServerPrivateKeyBytes}) async {
    ephemeralServerPrivateKeyBytes ??= generateRandomBytes(
      deriveOptimalByteLengthForEphemeralKeys(safePrime.bitLength)
    );
    _ephemeralServerPrivateKey = ephemeralServerPrivateKeyBytes.toBigInt();
    // k = H(N,g)
    final multiplierParameter = (await _hashRfc5054(
        [safePrime.toByteList(), generator.toByteList()]
    )).toBigInt();
    // B = kv + g^b
    final ephemeralServerPublicKeyInt = (multiplierParameter * _verifierKey + generator.modPow(_ephemeralServerPrivateKey!, safePrime)) % safePrime;
    _ephemeralServerPublicKey = ephemeralServerPublicKeyInt.toByteList();
    final customHashFunction = hashFunctionChoice != null ? null : _hashFunction;
    return Challenge.fromServer(
      generator: generator,
      safePrime: safePrime,
      ephemeralServerPublicKey: Uint8List.fromList(_ephemeralServerPublicKey!),
      verifierKeySalt: Uint8List.fromList(_salt),
      hashFunctionChoice: hashFunctionChoice,
      customHashFunction: customHashFunction,
    );
  }

  /// Derives the session key from the user's ephemeral public key.
  ///
  /// **Note:** This method is optional and should only be called if your SRP usage
  /// requires early access to the session key (e.g., if the user's session verifier
  /// is encrypted with the session key). In most cases, call [verifySession] instead,
  /// which derives the session key automatically as part of verification.
  ///
  /// **Parameters:**
  /// - [ephemeralUserPublicKey]: The user's ephemeral public key (A) received from
  ///   the user during authentication
  ///
  /// **Returns:** The derived session key (K) as a byte array
  ///
  /// **Throws:**
  /// - [InvalidParameterException] if the ephemeral user public key is invalid
  ///   (A % N == 0), which may indicate an attack attempt
  ///
  /// **Side effects:** Securely erases the verification key and ephemeral private
  /// key after deriving the session key.
  ///
  /// **Important:** Even after calling this method, you must still call [verifySession]
  /// to complete authentication and verify the user's identity.
  Future<Uint8List> deriveSessionKey({required Uint8List ephemeralUserPublicKey}) async {
    verifyEphemeralKey(ephemeralUserPublicKey.toBigInt(), safePrime, 'A (user)');
    // u = H(A,B)
    final randomScramblingParameter = (await _hashRfc5054(
        [ephemeralUserPublicKey, _ephemeralServerPublicKey!]
    )).toBigInt();
    // Av^u
    final base = ephemeralUserPublicKey.toBigInt() * _verifierKey.modPow(randomScramblingParameter, safePrime);
    // (Av^u) ^ b
    final power = base.modPow(_ephemeralServerPrivateKey!, safePrime).toByteList();
    // K = H((Av^u) ^ b)
    _sessionKey = await _hashFunction.hash(power);
    // Delete items that are no longer needed.
    _verifierKey = BigInt.zero;
    _ephemeralServerPrivateKey = BigInt.zero;
    return Uint8List.fromList(_sessionKey!);
  }

  /// Verifies the user's session and returns a server verifier for mutual authentication.
  ///
  /// This method performs three critical steps:
  /// 1. Derives the session key from the user's ephemeral public key (if not already derived)
  /// 2. Verifies the user's session key verifier (M1) matches the expected value
  /// 3. Generates a server session key verifier (M2) for the user to verify
  ///
  /// **Parameters:**
  /// - [userSessionKeyVerifier]: The user's session key verifier (M1) received
  ///   from the user
  /// - [ephemeralUserPublicKey]: The user's ephemeral public key (A) received
  ///   from the user
  ///
  /// **Returns:** Server session key verifier (M2) that should be sent back to
  /// the user so they can verify the server's identity
  ///
  /// **Throws:**
  /// - [AuthenticationFailure] if the user's session key verifier doesn't match
  ///   the expected value, indicating invalid credentials or a potential attack
  /// - [InvalidParameterException] if the ephemeral user public key is invalid
  ///
  /// **Side effects:** Securely erases ephemeral keys, user ID, salt, and safe
  /// prime bytes after verification completes.
  ///
  /// After this method succeeds, the [sessionKey] property contains the shared
  /// session key that can be used for encrypted communication.
  Future<Uint8List> verifySession({
      required Uint8List userSessionKeyVerifier, required Uint8List ephemeralUserPublicKey
  }) async {
    if (_sessionKey == null) {
      await deriveSessionKey(ephemeralUserPublicKey: ephemeralUserPublicKey);
    }
    // Verify user session key.
    final expectedUserSessionKeyVerifier = await _deriveUserSessionKeyVerifier(
      ephemeralUserPublicKey);
    if (!expectedUserSessionKeyVerifier.shallowEquals(userSessionKeyVerifier)) {
      throw AuthenticationFailure('User session key failed verification.');
    }
    // Create server verifier key.
    // M2 = H(A, M, K)
    final combined = Uint8List.fromList(
        ephemeralUserPublicKey + userSessionKeyVerifier + _sessionKey!
    );
    final serverSessionKeyVerifier = await _hashFunction.hash(combined);
    return serverSessionKeyVerifier;
  }

  /// M1 = H(H(N) xor H(g), H(I), s, A, B, K)
  Future<Uint8List> _deriveUserSessionKeyVerifier(Uint8List ephemeralUserPublicKey) async {
    // H(N)
    final hashedSafePrime = (await _hashFunction.hash(safePrime.toByteList())).toBigInt();
    // H(g)
    final hashedGenerator = (await _hashRfc5054([generator.toByteList()])).toBigInt();
    // H(I)
    final hashedUserId = await _hashFunction.hash(_userIdBytes);
    // SECURITY: Erase user ID bytes immediately after hashing
    _userIdBytes.overwriteWithZeros();
    // H(N) xor H(g)
    final hashedSafePrimeAndGenerator = (hashedSafePrime ^ hashedGenerator).toByteList();
    // M1 = H(H(N) xor H(g), H(I), s, A, B, K)
    final combined = Uint8List.fromList(
        hashedSafePrimeAndGenerator +
        hashedUserId +
        _salt +
        ephemeralUserPublicKey +
        _ephemeralServerPublicKey! +
        _sessionKey!
    );
    final sessionKeyVerifier = await _hashFunction.hash(combined);
    // Delete items that are no longer needed.
    _ephemeralServerPublicKey?.overwriteWithZeros();
    _ephemeralServerPublicKey = null;
    _safePrimeBytes.overwriteWithZeros();
    _salt.overwriteWithZeros();
    return sessionKeyVerifier;
  }

  Future<Uint8List> _hashRfc5054(List<Uint8List> byteLists) async {
    return hashRfc5054(
      byteLists: byteLists,
      safePrime: _safePrimeBytes,
      hashFunction: _hashFunction
    );
  }

  /// Resolves the hash function to use based on user parameters.
  void _resolveHashFunction(
    HashFunctionChoice? hashFunction, HashFunction? customHashFunction
  ) {
    if (hashFunction != null && customHashFunction != null) {
      throw InvalidParameterException(
        'Cannot provide both hashFunction and customHashFunction. Please provide only one.'
      );
    }
    if (customHashFunction != null) {
      hashFunctionChoice = null;
      _hashFunction = customHashFunction;
    } else {
      hashFunctionChoice = hashFunction ?? defaultHashFunctionChoice;
      _hashFunction = getHashFunction(hashFunctionChoice!);
    }
  }
}
