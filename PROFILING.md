# Performance Profiling Guide

This guide helps diagnose performance issues in dsrp, particularly non-deterministic slowdowns with Argon2id.

## Quick Diagnosis

If you're experiencing slow or inconsistent performance (operations taking >10 seconds instead of 2-6 seconds), run the benchmark:

```bash
dart benchmark/argon2_benchmark.dart
```

This will test different Argon2id configurations and identify whether the issue is related to parallelism, system load, or memory pressure.

## Common Performance Issues

### Argon2id Non-Deterministic Slowdowns

**Symptoms:**
- Usually: `User.createSaltedVerificationKeyFromBytes()` takes 2-6 seconds
- Sometimes: Same operation takes 60+ seconds with high CPU usage
- Inconsistent behavior across test runs

**Root Causes:**
1. **Isolate spawning overhead**: Argon2id uses Dart isolates for parallelism (default: 4). Spawning isolates has variable overhead
2. **Thread contention**: Multiple concurrent operations × parallelism = many isolates competing for CPU
3. **Memory pressure**: 64 MB per operation × parallelism can trigger GC pauses
4. **System load**: Performance depends on other processes running

**Solutions:**

1. **For Tests** - Use parallelism=1 for deterministic performance:
```dart
final kdf = Argon2idKdf(
  name: 'argon2id-test',
  argon2: Argon2id(
    parallelism: 1,  // Single-threaded, no isolates
    memory: 65536,   // 64 MB
    iterations: 3,
    hashLength: 32,
  ),
);

final saltedKey = await User.createSaltedVerificationKeyFromBytes(
  userIdBytes: userIdBytes,
  passwordBytes: passwordBytes,
  customKdf: kdf,
);
```

2. **For Production** - Tune based on your environment:
```dart
// Low-resource server (1-2 cores)
parallelism: 1, memory: 32768  // 32 MB

// Standard server (4-8 cores, moderate load)
parallelism: 2, memory: 65536  // 64 MB

// High-performance server (8+ cores, dedicated)
parallelism: 4, memory: 65536  // 64 MB (current default)
```

## Profiling with Dart DevTools

### 1. Start Application with VM Service

```bash
# For examples
dart --observe --profiler example/srp.dart

# For tests
dart --observe --profiler test

# You'll see output like:
# Observatory listening on http://127.0.0.1:8181/...
```

### 2. Open Dart DevTools

```bash
# In another terminal
dart devtools
```

Then open the URL shown (usually http://127.0.0.1:9100) and paste the Observatory URL.

### 3. Use CPU Profiler

1. Go to **CPU Profiler** tab
2. Click **Record** before the slow operation starts
3. Let the operation complete
4. Click **Stop**
5. Examine the flame graph:
   - Look for `Argon2id.deriveKey` and its duration
   - Check for isolate spawning overhead
   - Identify unexpected bottlenecks

**Key metrics:**
- **Total time**: How long did the operation take?
- **Self time**: Time spent in the function itself (not children)
- **Isolate activity**: Are isolates spawning/dying repeatedly?

### 4. Use Timeline View

1. Go to **Timeline** tab
2. Click **Record** and perform the operation
3. Click **Stop**
4. Look for:
   - **Long GC pauses** (indicates memory pressure)
   - **Isolate spawning events** (shows overhead)
   - **CPU utilization gaps** (thread scheduling issues)

### 5. Use Memory Profiler

1. Go to **Memory** tab
2. Take a snapshot before and after the operation
3. Look for:
   - Large allocations (64 MB+ for Argon2id memory parameter)
   - Objects not being garbage collected
   - Memory leaks in test suites

## Profiling Command-Line Examples

### Profile a Specific Test

```bash
# Run with Observatory
dart --observe --profiler test/user_test.dart

# In DevTools, filter CPU profiler to:
# - Function: "createSaltedVerificationKeyFromBytes"
# - Call tree view to see what's slow
```

### Profile the Example

```bash
# Run with CPU profiling
dart --observe --profiler example/srp.dart

# Or get a simple timeline without DevTools:
dart --timeline_streams=Compiler,Dart,Debugger,Embedder,GC,Isolate,VM \
     --timeline_recorder=file:timeline.json \
     example/srp.dart

# Open timeline.json in chrome://tracing
```

### Quick Performance Check

```bash
# Simple timing without profiler
time dart example/srp.dart

# Run multiple times to check consistency
for i in {1..5}; do time dart example/srp.dart; done
```

## Interpreting Results

### Good Performance
```
Run 1: 2341ms
Run 2: 2298ms
Run 3: 2415ms
Variance: ~5%
```

### Problematic Performance
```
Run 1: 2341ms
Run 2: 45231ms  ← Isolate spawning issue or system load
Run 3: 2298ms
Variance: >90%
```

### Memory Pressure
```
Timeline shows:
- Frequent GC pauses during Argon2id
- GC taking >100ms
- Memory usage spikes to >256 MB

Solution: Reduce memory parameter or parallelism
```

## Optimization Recommendations

### For Library Development
- **Tests**: Use `parallelism: 1` to avoid flaky tests
- **CI/CD**: Consider reducing Argon2id parameters for faster builds
- **Benchmarks**: Always run on idle system for consistent results

### For Library Users
- **Development**: Use SHA-256 KDF (fast) during development, Argon2id in production
- **Testing**: Override default KDF in test environments
- **Production**: Tune Argon2id based on server specs and expected load

### Quick Test Configuration

Create a test helper to use fast KDF:

```dart
// test/test_helpers.dart
import 'package:dsrp/dsrp.dart';
import 'package:dsrp/crypto/kdf.dart';

final testKdf = getKdf(KdfChoice.sha256);  // Fast for testing

// Use in tests
final saltedKey = await User.createSaltedVerificationKeyFromBytes(
  userIdBytes: userIdBytes,
  passwordBytes: passwordBytes,
  customKdf: testKdf,  // Fast, deterministic
);
```

## Further Resources

- [Dart DevTools Documentation](https://dart.dev/tools/dart-devtools)
- [CPU Profiler Guide](https://docs.flutter.dev/tools/devtools/cpu-profiler)
- [Argon2 Performance Tuning](https://www.rfc-editor.org/rfc/rfc9106.html#section-4)
- [Dart Isolates](https://dart.dev/language/isolates)

## Reporting Performance Issues

When reporting performance issues, please include:

1. **Benchmark results**: Output from `dart benchmark/argon2_benchmark.dart`
2. **System info**: CPU cores, RAM, OS
3. **Dart version**: `dart --version`
4. **Reproduction**: Minimal code example
5. **Profiler data**: DevTools screenshot or timeline.json (if available)
6. **Consistency**: How often does it occur? (always, 1/10 times, etc.)
