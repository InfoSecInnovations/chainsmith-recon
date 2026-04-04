# Drop Python 3.11 Support

## Summary

Consider raising the minimum Python version from 3.11 to 3.12 and removing the 3.11 CI matrix entry.

## Rationale

- Halves CI test matrix (one fewer Python version to build/cache/test)
- Reduces dependency build issues (e.g., pycairo needing system libs varies by Python version)
- Python 3.12 is the current stable release; 3.11 EOL is Oct 2027
- No 3.11-specific syntax constraints are being used in the codebase today

## Changes Required

- `pyproject.toml`: update `requires-python` from `>=3.11` to `>=3.12`
- `pyproject.toml`: remove `Programming Language :: Python :: 3.11` classifier
- `.github/workflows/ci.yml`: remove `"3.11"` from the matrix
- Update any documentation referencing 3.11 as a minimum

## Considerations

- Enterprise or distro users pinned to 3.11 would be locked out
- Should be announced in a release note if adopted
