# Contributing to dsrp

Thank you for your interest in contributing to dsrp! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)

## Code of Conduct

This project follows the principles of respect, collaboration, and professionalism. We expect all contributors to:

- Be respectful and inclusive in all interactions.
- Provide constructive feedback.
- Focus on what is best for the community.
- Show empathy towards other community members.

## Getting Started

1. Fork the repository on your preferred Git hosting platform
2. Clone your fork locally:
   ```bash
   git clone https://codeberg.org/YOUR_USERNAME/dsrp.git
   cd dsrp
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://codeberg.org/fictiontoreality/dsrp.git
   ```

## Development Setup

### Prerequisites

- Dart SDK ≥ 2.19.0
- Git

### Installation

1. Install dependencies:
   ```bash
   dart pub get
   ```

2. Verify your setup by running tests:
   ```bash
   dart test
   ```

3. Run static analysis:
   ```bash
   dart analyze
   ```

## How to Contribute

### Types of Contributions

We welcome various types of contributions:

- **Bug fixes**: Fix issues found in the codebase.
- **New features**: Add new functionality (discuss in an issue first).
- **Documentation**: Improve docs, examples, or code comments.
- **Tests**: Add or improve test coverage.
- **Performance improvements**: Optimize existing code.
- **Security improvements**: Enhance cryptographic security.

### Before You Start

1. Check existing [issues](https://codeberg.org/fictiontoreality/dsrp/issues) to see if your idea is already being discussed.
2. For major changes, open an issue first to discuss your approach.
3. For security vulnerabilities, see [SECURITY.md](SECURITY.md) - do NOT open a public issue.

## Code Style Guidelines

### General Principles

- Write clear, readable, and maintainable code.
- Follow the existing code style in the project.
- Add comments for complex logic.
- Use meaningful variable and function names.

### Dart Style

We mostly follow the official [Dart style guide](https://dart.dev/guides/language/effective-dart/style). Key points:

- DO NOT use `dart format` to format all code - uniformity is not worth reduced
  readibility and noisy diffs. Instead format similarly to the rest of the code.
- Run `dart analyze` and ensure zero issues.
- Maximum line length: 80 characters (recommended, not a hard rule).
- Use trailing commas for better diffs.

### Documentation

- Use full sentences and end comments with punctuation.
- Every public API must have dartdoc comments.
- Include usage examples for main classes and methods.
- Document all parameters, either in prose with square brackes `[]` or the more
  formal `@param` style comments.
- Document return values and exceptions thrown.
- Add security notes where relevant.

Example:

```dart
/// Verifies that a safe prime meets security requirements.
///
/// A safe prime N is a prime number of the form N = 2q + 1, where q is also
/// prime (q is called a Sophie Germain prime).
///
/// **Parameters:**
/// - [safePrime]: The number to verify as a safe prime
/// - [minimumBitLength]: Minimum required bit length (recommended: ≥ 2048)
///
/// **Throws:**
/// - [InvalidParameterException] if the number is not a valid safe prime
///
/// **Example:**
/// ```dart
/// verifySafePrime(myPrime, 2048);
/// ```
void verifySafePrime(BigInt safePrime, int minimumBitLength) {
  // Implementation...
}
```

### Security Considerations

When contributing to cryptographic code:

- Use `Uint8List` for sensitive data (passwords, keys).
- Call `.overwriteWithZeros()` on sensitive data when no longer needed.
- Avoid using `String` for passwords (cannot be securely erased).
- Return defensive copies from public APIs.
- Validate all cryptographic parameters.
- Document security implications in code comments.

## Testing

### Running Tests

Run all tests:
```bash
dart test
```

Run specific test file:
```bash
dart test test/user_test.dart
```

Run with coverage (requires `coverage` package):
```bash
dart pub global activate coverage
dart run coverage:test_with_coverage
```

### Writing Tests

- Write tests for all new functionality.
- Ensure tests are deterministic and repeatable.
- Use descriptive test names that explain what is being tested.
- Group related tests with `group()`.
- Aim for >90% code coverage.

Example test structure:

```dart
group('SaltedVerificationKey', () {
  test('creates valid verification key with default parameters', () {
    // Test implementation
  });

  test('throws exception when safe prime is invalid', () {
    expect(
      () => /* code that should throw */,
      throwsA(isA<InvalidParameterException>()),
    );
  });
});
```

### Test Coverage Goals

- Minimum: 90% line coverage
- Test all public APIs
- Test error conditions and edge cases
- Include integration tests for full SRP workflows

## Submitting Changes

### Workflow

1. Create a new branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes, following the code style guidelines

3. Add tests for your changes

4. Run the full test suite and ensure it passes:
   ```bash
   dart test
   dart analyze
   ```

5. Commit your changes with clear, descriptive messages:
   ```bash
   git commit -m "Add feature: brief description

   More detailed explanation of what changed and why.
   Fixes #123"
   ```

6. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

7. Open a Pull Request (PR) with:
   - Clear title describing the change.
   - Description of what changed and why.
   - Reference to any related issues.
   - Confirmation that tests pass.

### Commit Message Guidelines

- Use present tense ("Add feature" not "Added feature").
- Use imperative mood ("Move cursor to..." not "Moves cursor to...").
- Limit first line to 72 characters.
- Reference issues and PRs when applicable.
- Explain *what* and *why*, not *how* (code shows how).

Examples:
```
Add JSON serialization to Challenge class

Implements toJson() and fromJson() methods to allow easy serialization
for network transmission. Uses base64 encoding for binary data.

Fixes #42
```

### Pull Request Review Process

1. Maintainers will review your PR.
2. Address any requested changes.
3. Once approved, a maintainer will merge your PR.
4. Your contribution will be included in the next release.

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

- Clear, descriptive title
- Dart SDK version (`dart --version`)
- Operating system and version
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Code samples (minimal reproducible example)
- Error messages or stack traces

### Feature Requests

When requesting features:

- Explain the use case and problem it solves.
- Describe your proposed solution.
- Consider alternatives.
- Be open to discussion and feedback.

### Questions

For questions about usage:

- Check existing documentation and examples first.
- Search existing issues for similar questions.
- Provide context about what you're trying to achieve.

## Security Vulnerabilities

**Do NOT report security vulnerabilities through public GitHub issues.**

Please see [SECURITY.md](SECURITY.md) for instructions on responsibly disclosing security issues.

## License

By contributing to dsrp, you agree that your contributions will be licensed under the Apache License 2.0.

---

Thank you for contributing to dsrp! Your efforts help make secure authentication more accessible to the Dart community.
