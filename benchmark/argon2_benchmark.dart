import 'dart:io';
import 'package:dsrp/dsrp.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dsrp/crypto/kdf.dart';
import 'package:dsrp/util/bytes.dart';

/// Benchmark for Argon2id performance to diagnose non-deterministic slowdowns.
///
/// This benchmark tests:
/// 1. Impact of different parallelism values (1, 2, 4, 8)
/// 2. Single vs multiple concurrent operations
/// 3. Consistency across multiple runs
///
/// Usage:
///   dart benchmark/argon2_benchmark.dart
void main() async {
  print('=== Argon2id Performance Benchmark ===\n');
  print('System: ${Platform.numberOfProcessors} CPU cores\n');

  final testPassword = 'test-password-123'.utf8Bytes;
  final testSalt = generateRandomBytes(32);
  final testUserId = 'testuser'.utf8Bytes;

  // Test different parallelism values
  final parallelismValues = [1, 2, 4, 8];

  for (final parallelism in parallelismValues) {
    print('--- Parallelism: $parallelism ---');

    final kdf = Argon2idKdf(
      name: 'argon2id-p$parallelism',
      argon2: Argon2id(
        parallelism: parallelism,
        memory: 65536, // 64 MB (same as default)
        iterations: 3,
        hashLength: 32,
      ),
    );

    // Run 5 iterations to measure consistency
    final times = <int>[];
    for (var i = 0; i < 5; i++) {
      final stopwatch = Stopwatch()..start();
      await kdf.deriveKeyFromPasswordBytes(
        passwordBytes: testPassword,
        salt: testSalt,
        userIdBytes: testUserId,
      );
      stopwatch.stop();
      times.add(stopwatch.elapsedMilliseconds);
      print('  Run ${i + 1}: ${stopwatch.elapsedMilliseconds}ms');
    }

    final avg = times.reduce((a, b) => a + b) / times.length;
    final min = times.reduce((a, b) => a < b ? a : b);
    final max = times.reduce((a, b) => a > b ? a : b);
    final variance = max - min;

    print('  Average: ${avg.toStringAsFixed(1)}ms');
    print('  Min: ${min}ms, Max: ${max}ms');
    print('  Variance: ${variance}ms (${(variance / avg * 100).toStringAsFixed(1)}%)\n');
  }

  // Test concurrent operations (simulating multiple users)
  print('--- Concurrent Operations Test ---');
  print('Running 3 concurrent Argon2id operations (parallelism=4 each)...\n');

  final concurrentKdf = Argon2idKdf(
    name: 'argon2id-concurrent',
    argon2: Argon2id(
      parallelism: 4,
      memory: 65536,
      iterations: 3,
      hashLength: 32,
    ),
  );

  for (var run = 0; run < 3; run++) {
    final stopwatch = Stopwatch()..start();

    await Future.wait([
      concurrentKdf.deriveKeyFromPasswordBytes(
        passwordBytes: testPassword,
        salt: testSalt,
        userIdBytes: testUserId,
      ),
      concurrentKdf.deriveKeyFromPasswordBytes(
        passwordBytes: testPassword,
        salt: testSalt,
        userIdBytes: testUserId,
      ),
      concurrentKdf.deriveKeyFromPasswordBytes(
        passwordBytes: testPassword,
        salt: testSalt,
        userIdBytes: testUserId,
      ),
    ]);

    stopwatch.stop();
    print('  Concurrent run ${run + 1}: ${stopwatch.elapsedMilliseconds}ms');
  }

  print('\n--- Benchmark Complete ---');
  print('If you see large variance (>50%) or times >1000ms, this indicates:');
  print('1. System under load (other processes competing for CPU)');
  print('2. Isolate spawning overhead (Dart VM state)');
  print('3. Memory pressure causing GC pauses');
  print('\nRecommendations:');
  print('- Use parallelism=1 for tests to reduce variance');
  print('- Use parallelism=2-4 for production (balance security/performance)');
  print('- Consider reducing memory parameter on constrained systems');

  // Clean up
  testPassword.overwriteWithZeros();
  testSalt.overwriteWithZeros();
  testUserId.overwriteWithZeros();
}
