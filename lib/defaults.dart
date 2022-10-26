import 'hash.dart';

/// Balance between compatibility, speed and security.
/// FIXME: Should this be bumped up?
final defaultHashAlgorithmChoice = HashAlgorithmChoice.sha256;

/// TODO: Are there better (performance, security) generators?
final defaultGenerator = BigInt.from(2);

/// 2048-bit safe prime generated using scripts/generate_safe_primes.py.
///
/// IT IS RECOMMENDED TO GENERATE YOUR OWN SAFE PRIMES FOR ADDED SECURITY.
///
/// By not reusing a published safe prime (such as one from RFC5054), odds are
/// reduced that the prime has been integrated into pre-computed attack methods.
final defaultSafePrime = BigInt.parse(
    'ef0e3dc9ba1d254350c23c3d13dc91d6243d3701dcd1fd7ec084b3bebc0e0eb9b3bd795e7fc0b30b606a6ee5a8482eee75843fc63c1a5f309d40f6b4b544b6a69b3d778949dd16d857c29b3803e0538972427d95c59d74a147777aaff3ef9b397c64423bbdbc039e57960ecc9079ec14f5bbfe455baf7a8edb6cc7ce85973379941d81221601171add5c2a7292b5e03c97d2f1a08345c182843372ecd6072ebdac0dc64b5bcdae93bca495a67454ad38ecc0b9fc2fab3a2723bf2ebdb9418b92684152caba282159c0d20f4514ea8b6c7613f4d3ac3cef1ee4046283cd4003088d928dd8337c7c5391c75a26e1ab49c372ddf2f702f7f9a7226cad4572e39d53',
    radix: 16);
