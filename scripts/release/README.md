# Release Script

Python 3 script to release package to pub.dev, including all pre-release checks.

## Features

The script has a number of checks before release:

- all tests pass
- all examples complete without error
- `dart analyze` passes
- code coverage meets minimum threshold
- verify all TODO/OPTIMIZE/FIXME lines are resolved
- changelog has been updated for release
- verifies dry run publishing succeeds
- confirms with user before publishing to pub.dev

## Usage

Run from the script directory, using [uv](https://github.com/astral-sh/uv) for reproduceable Python:

```bash
uv run release.py
```
