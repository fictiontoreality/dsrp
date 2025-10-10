import 'dart:convert' show utf8;
import 'dart:typed_data';
import 'package:dsrp/defaults.dart' show defaultGenerator, defaultHashFunctionChoice, defaultSafePrime, deriveOptimalByteLengthForEphemeralKeys;
import 'package:dsrp/exceptions.dart' show AuthenticationFailure;
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
/// WARNING: If the server provides the core SRP parameters (safe prime,
/// generator, hash algorithm) it is highly recommended for the client to verify
/// they are cryptographically secure. This could include checking the hash
/// algorithm is one of those expected, and that the safe prime, generator and
/// salt are secure (see [verifySafePrime], [verifyGenerator], [verifySalt]).
class Challenge {
  final int generator;
  final Uint8List safePrime;
  final Uint8List ephemeralServerPublicKey;
  final Uint8List verifierKeySalt;
  final HashFunctionChoice hashFunction;

  Challenge({
      required this.generator,
      required this.safePrime,
      required this.ephemeralServerPublicKey,
      required this.verifierKeySalt,
      required this.hashFunction
  });

  /// Overwrites sensitive data with zeros.
  void erase() {
    safePrime.overwriteWithZeros();
    ephemeralServerPublicKey.overwriteWithZeros();
    verifierKeySalt.overwriteWithZeros();
  }
}

/// Operations the server / host performs to authenticate a user via SRP.
///
/// Designed to mimic the API of Python's pysrp library.
class Server {
  /// User identifier.
  String? _userId;
  /// Salt provided by user during registration.
  final Uint8List _salt;
  /// Verifier key provided by user during registration.
  BigInt _verifierKey;
  /// A generator modulo N.
  /// Typically denoted 'g'.
  final BigInt generator;
  /// Hash algorithm used during SRP key and verifier calculations (e.g., SHA256).
  final HashFunctionChoice hashFunctionChoice;
  /// Hash algorithm used during SRP key and verifier calculations (e.g., SHA256).
  final HashFunction hashFunction;
  /// A large, safe prime.
  /// Typically denoted 'N'.
  /// By definition a safe prime N = 2q + 1, where q is a Sophie Germain prime.
  /// All arithmetic is performed in the field of integers modulo N.
  final BigInt safePrime;

  BigInt? _ephemeralServerPrivateKey;
  Uint8List? _ephemeralServerPublicKey;
  Uint8List? sessionKey;

  Server({
      required String userId,
      required Uint8List salt,
      required Uint8List verifierKey,
      BigInt? generator,
      Uint8List? safePrime,
      HashFunctionChoice? hashFunction,
  }) : _salt = salt, _userId = userId,
       _verifierKey = verifierKey.toBigInt(),
       generator = generator ?? defaultGenerator,
       safePrime = safePrime?.toBigInt() ?? defaultSafePrime,
       hashFunctionChoice = hashFunction ?? defaultHashFunctionChoice,
       hashFunction = getHashFunction(hashFunction ?? defaultHashFunctionChoice) {
    if (safePrime == null) {
      _log.warning('Using default safe prime. For production use, generate a custom safe prime using scripts/generate_safe_primes to reduce risk of pre-computed attacks.');
    }
  }

  /// Create verification challenge to send to user.
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
    return Challenge(
      generator: generator.toInt(),
      safePrime: safePrime.toByteList(),
      ephemeralServerPublicKey: Uint8List.fromList(_ephemeralServerPublicKey!),
      verifierKeySalt: Uint8List.fromList(_salt),
      hashFunction: hashFunctionChoice
    );
  }

  /// Derive session key from user public key.
  ///
  /// NOTE: This should only be called if your SRP usage involves decrypting the
  /// user session key verifier using the session key. Regardless, you still
  /// need to verify the session key before considering the session verified.
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
    sessionKey = await hashFunction.hash(power);
    // Delete items that are no longer needed.
    _verifierKey = BigInt.zero;
    _ephemeralServerPrivateKey = BigInt.zero;
    return Uint8List.fromList(sessionKey!);
  }

  /// Verify that session key generated by user is the same as the one generated by server.
  ///
  /// Returns a server-generated session key verifier the user can use to verify
  /// the server's identity.
  Future<Uint8List> verifySession({
      required Uint8List userSessionKeyVerifier, required Uint8List ephemeralUserPublicKey
  }) async {
    if (sessionKey == null) {
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
        ephemeralUserPublicKey + userSessionKeyVerifier + sessionKey!
    );
    final serverSessionKeyVerifier = await hashFunction.hash(combined);
    return serverSessionKeyVerifier;
  }

  /// M1 = H(H(N) xor H(g), H(I), s, A, B, K)
  Future<Uint8List> _deriveUserSessionKeyVerifier(Uint8List ephemeralUserPublicKey) async {
    // H(N)
    final hashedSafePrime = (await hashFunction.hash(safePrime.toByteList())).toBigInt();
    // H(g)
    final hashedGenerator = (await _hashRfc5054([generator.toByteList()])).toBigInt();
    // H(I)
    final hashedUserId = await hashFunction.hash(Uint8List.fromList(utf8.encode(_userId!)));
    _userId = null; // No longer needed, delete immediately.
    // H(N) xor H(g)
    final hashedSafePrimeAndGenerator = (hashedSafePrime ^ hashedGenerator).toByteList();
    // M1 = H(H(N) xor H(g), H(I), s, A, B, K)
    final combined = Uint8List.fromList(
        hashedSafePrimeAndGenerator +
        hashedUserId +
        _salt +
        ephemeralUserPublicKey +
        _ephemeralServerPublicKey! +
        sessionKey!
    );
    final sessionKeyVerifier = await hashFunction.hash(combined);
    //TODO: Delete items that are no longer needed. After Uint8List conversion.
    // _salt.overwriteWithZeros();
    _ephemeralServerPublicKey?.overwriteWithZeros();
    _ephemeralServerPublicKey = null;
    return sessionKeyVerifier;
  }

  Future<Uint8List> _hashRfc5054(List<Uint8List> byteLists) async {
    //OPTIMIZE: Make this a class field.
    final safePrimeBytes = safePrime.toByteList();
    return hashRfc5054(
      byteLists: byteLists,
      safePrime: safePrimeBytes,
      hashFunction: hashFunction
    );
  }
}
