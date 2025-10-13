#! /usr/bin/env python3
"""Release package to pub.dev, including all pre-checks."""

import subprocess
import sys
import re
import yaml
from pathlib import Path
from typing import Tuple, List

PACKAGE_NAME = 'dsrp'
TOTAL_STEPS = 8
MINIMUM_COVERAGE_PERCENTAGE = 85

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_step(step_num: int, message: str):
    """Print a formatted step message."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}[{step_num}/{TOTAL_STEPS}] {message}{Colors.ENDC}")


def print_success(message: str):
    """Print a success message."""
    print(f"{Colors.GREEN}✓ {message}{Colors.ENDC}")


def print_error(message: str):
    """Print an error message."""
    print(f"{Colors.RED}✗ {message}{Colors.ENDC}")


def print_warning(message: str):
    """Print a warning message."""
    print(f"{Colors.YELLOW}⚠ {message}{Colors.ENDC}")


def run_command(cmd: List[str], description: str, cwd: str | None = None) -> Tuple[bool, str]:
    """
    Run a command and return success status and output.

    Args:
        cmd: Command and arguments as list
        description: Human-readable description of what's being run
        cwd: Working directory (defaults to project root)

    Returns:
        Tuple of (success: bool, output: str)
    """
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        if result.returncode != 0:
            return False, result.stderr or result.stdout

        return True, result.stdout

    except subprocess.TimeoutExpired:
        return False, f"{description} timed out after 5 minutes"
    except Exception as e:
        return False, str(e)


def get_project_root() -> Path:
    """Get the project root directory."""
    script_dir = Path(__file__).parent.parent
    return script_dir.parent


def get_version() -> str:
    """Get the current version from pubspec.yaml."""
    project_root = get_project_root()
    pubspec_path = project_root / "pubspec.yaml"

    with open(pubspec_path, 'r') as f:
        pubspec = yaml.safe_load(f)

    return pubspec['version']


def check_tests() -> bool:
    """Run unit tests."""
    print_step(1, "Running unit tests...")

    success, output = run_command(
        ['dart', 'test'],
        'Unit tests',
        cwd=str(get_project_root())
    )

    if not success:
        print_error("Unit tests failed!")
        print(output)
        return False

    print_success("All unit tests passed")
    return True


def check_examples() -> bool:
    """Run all examples and verify they don't throw exceptions."""
    print_step(2, "Running examples...")

    project_root = get_project_root()
    example_dir = project_root / "example"

    if not example_dir.exists():
        print_warning("No example directory found.")
        return False

    # Find all .dart files in example directory
    examples = list(example_dir.glob("*.dart"))

    if not examples:
        print_warning("No example files found.")
        return False

    failed_examples = []

    for example in examples:
        print(f"  Running {example.name}...", end=" ")

        success, output = run_command(
            ['dart', 'run', str(example)],
            f'Example {example.name}',
            cwd=str(project_root)
        )

        if not success:
            print(f"{Colors.RED}✗{Colors.ENDC}")
            failed_examples.append((example.name, output))
        else:
            print(f"{Colors.GREEN}✓{Colors.ENDC}")

    if failed_examples:
        print_error(f"{len(failed_examples)} example(s) failed:")
        for name, output in failed_examples:
            print(f"\n{Colors.RED}{name}:{Colors.ENDC}")
            print(output[:500])  # Print first 500 chars of error
        return False

    print_success(f"All {len(examples)} examples ran successfully")
    return True


def check_analyze() -> bool:
    """Run dart analyze."""
    print_step(3, "Running static analysis...")

    success, output = run_command(
        ['dart', 'analyze'],
        'Static analysis',
        cwd=str(get_project_root())
    )

    if not success:
        print_error("Static analysis failed!")
        print(output)
        return False

    print_success("Static analysis passed")
    return True


def check_coverage() -> bool:
    """Check code coverage satisfies minimum threshold."""
    print_step(4, "Checking code coverage...")

    project_root = get_project_root()
    coverage_dir = project_root / "coverage"

    # Run tests with coverage
    print("  Generating coverage report...")
    success, output = run_command(
        ['dart', 'test', '--coverage=coverage'],
        'Test coverage generation',
        cwd=str(project_root)
    )

    if not success:
        print_error("Failed to generate coverage!")
        print(output)
        return False

    # Format coverage to lcov
    success, output = run_command(
        [
            'dart', 'pub', 'global', 'run', 'coverage:format_coverage',
            '--lcov',
            '--in=coverage',
            '--out=coverage/lcov.info',
            '--packages=.dart_tool/package_config.json',
            '--report-on=lib'
        ],
        'Coverage formatting',
        cwd=str(project_root)
    )

    if not success:
        print_error("Failed to format coverage!")
        print(output)
        return False

    # Check if lcov is installed for summary
    lcov_info = coverage_dir / "lcov.info"
    if not lcov_info.exists():
        print_warning("Coverage file failed to generate.")
        return False

    # Try to use lcov to get percentage
    success, output = run_command(
        ['lcov', '--summary', str(lcov_info)],
        'Coverage summary',
        cwd=str(project_root)
    )

    if success:
        # Parse lcov output: "lines......: 87.5% (175 of 200 lines)"
        match = re.search(r'lines[.\s]+:\s+([\d.]+)%', output)
        if match:
            coverage_pct = float(match.group(1))

            if coverage_pct < MINIMUM_COVERAGE_PERCENTAGE:
                print_error(f"Coverage is {coverage_pct}% (minimum: {MINIMUM_COVERAGE_PERCENTAGE}%)")
                return False

            print_success(f"Coverage is {coverage_pct}% (minimum: {MINIMUM_COVERAGE_PERCENTAGE}%)")
            return True

    # Fallback: Parse lcov.info manually
    print_warning("lcov not installed, attempting manual parsing...")

    with open(lcov_info, 'r') as f:
        lines = f.readlines()

    lines_found = 0
    lines_hit = 0

    for line in lines:
        if line.startswith('LF:'):
            lines_found += int(line.split(':')[1].strip())
        elif line.startswith('LH:'):
            lines_hit += int(line.split(':')[1].strip())

    if lines_found == 0:
        print_warning("Could not determine coverage; lcov.info file may be malformed.")
        return False

    coverage_pct = (lines_hit / lines_found) * 100

    if coverage_pct < MINIMUM_COVERAGE_PERCENTAGE:
        print_error(f"Coverage is {coverage_pct:.1f}% (minimum: {MINIMUM_COVERAGE_PERCENTAGE}%)")
        return False

    print_success(f"Coverage is {coverage_pct:.1f}% (minimum: {MINIMUM_COVERAGE_PERCENTAGE}%)")
    return True


def check_todos() -> bool:
    """Check for unresolved TODO/OPTIMIZE/FIXME comments."""
    print_step(5, "Checking for unresolved TODO/OPTIMIZE/FIXME comments...")

    project_root = get_project_root()
    lib_dir = project_root / "lib"

    patterns = ['TODO', 'FIXME', 'OPTIMIZE']
    found_items = []

    # Search in lib directory
    for dart_file in lib_dir.rglob("*.dart"):
        with open(dart_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                for pattern in patterns:
                    if pattern in line:
                        # Extract the comment
                        comment = line.strip()
                        rel_path = dart_file.relative_to(project_root)
                        found_items.append(f"{rel_path}:{line_num}: {comment}")

    if found_items:
        print_warning(f"Found {len(found_items)} unresolved items:")
        for item in found_items[:10]:  # Show first 10
            print(f"  {item}")

        if len(found_items) > 10:
            print(f"  ... and {len(found_items) - 10} more")

        response = input(f"\n{Colors.YELLOW}Continue with release anyway? (y/N): {Colors.ENDC}")
        if response.lower() != 'y':
            print_error("Release cancelled")
            return False

        print_success("Continuing with release despite unresolved items")
    else:
        print_success("No unresolved TODO/OPTIMIZE/FIXME comments found")

    return True


def check_changelog() -> bool:
    """Verify CHANGELOG has been updated for current version."""
    print_step(6, "Checking CHANGELOG...")

    project_root = get_project_root()
    changelog_path = project_root / "CHANGELOG.md"

    if not changelog_path.exists():
        print_error("CHANGELOG.md not found!")
        return False

    version = get_version()

    with open(changelog_path, 'r') as f:
        changelog_content = f.read()

    # Look for version heading (e.g., "## 0.5.1" or "## [0.5.1]")
    version_pattern = rf'^##\s+\[?{re.escape(version)}\]?'

    if not re.search(version_pattern, changelog_content, re.MULTILINE):
        print_error(f"CHANGELOG.md does not contain entry for version {version}")
        print(f"Expected to find: ## {version}")
        return False

    print_success(f"CHANGELOG.md contains entry for version {version}")
    return True


def check_dry_run() -> bool:
    """Run dart pub publish --dry-run."""
    print_step(7, "Running publish dry-run...")

    success, output = run_command(
        ['dart', 'pub', 'publish', '--dry-run'],
        'Publish dry-run',
        cwd=str(get_project_root())
    )

    if not success:
        print_error("Dry-run failed!")
        print(output)
        return False

    print_success("Dry-run passed")
    print(output)
    return True


def publish_package() -> bool:
    """Publish the package to pub.dev."""
    print_step(8, "Publishing to pub.dev...")

    version = get_version()

    print(f"\n{Colors.BOLD}Ready to publish version {version} to pub.dev{Colors.ENDC}")
    print(f"{Colors.YELLOW}This action cannot be undone!{Colors.ENDC}")

    response = input(f"\n{Colors.BOLD}Proceed with publish? (yes/no): {Colors.ENDC}")

    if response.lower() != 'yes':
        print_warning("Publish cancelled by user")
        return False

    # Run publish
    try:
        # Don't capture output - let user see the interactive prompts
        result = subprocess.run(
            ['dart', 'pub', 'publish'],
            cwd=str(get_project_root()),
            timeout=300
        )
        if result.returncode != 0:
            print_error("Publish failed!")
            return False
        print_success(f"Successfully published version {version} to pub.dev!")
        return True
    except subprocess.TimeoutExpired:
        print_error("Publish timed out")
        return False
    except Exception as e:
        print_error(f"Publish failed: {e}")
        return False


def main():
    """Main release flow."""
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}  {PACKAGE_NAME} Package Release Script{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.ENDC}\n")

    version = get_version()
    print(f"{Colors.BOLD}Current version: {version}{Colors.ENDC}\n")

    # Run all checks in order
    checks = [
        check_tests,
        check_examples,
        check_analyze,
        check_coverage,
        check_todos,
        check_changelog,
        check_dry_run,
    ]

    for check in checks:
        if not check():
            print(f"\n{Colors.RED}{Colors.BOLD}Release aborted due to failed check{Colors.ENDC}")
            sys.exit(1)

    # All checks passed, proceed to publish
    print(f"\n{Colors.GREEN}{Colors.BOLD}All checks passed!{Colors.ENDC}")

    if not publish_package():
        print(f"\n{Colors.RED}{Colors.BOLD}Release aborted{Colors.ENDC}")
        sys.exit(1)

    print(f"\n{Colors.GREEN}{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.GREEN}{Colors.BOLD}  Release Complete!{Colors.ENDC}")
    print(f"{Colors.GREEN}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
    print(f"Version {version} is now live on pub.dev")
    print(f"View at: https://pub.dev/packages/{PACKAGE_NAME}/versions/{version}\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Release cancelled by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Unexpected error: {e}{Colors.ENDC}")
        sys.exit(1)
