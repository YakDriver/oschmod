## Changelog

### Unreleased

**Summary**:

*   Invalid symbolic modes now raise a new `oschmod.ModeError` (a subclass of both `ValueError` and `AttributeError`) instead of a surprising `AttributeError`, and non-string modes raise `TypeError` instead of `AttributeError` ([#191](https://github.com/YakDriver/oschmod/issues/191)). Thanks @hamid-digitalmarketer.

### 0.4.0

**Commit Delta**: [Change from 0.3.12 release](https://github.com/YakDriver/oschmod/compare/0.3.12...0.4.0)

**Summary**:

*   **Breaking:** Requires Python 3.11 or newer. Python 2 and Python 3.5–3.10 are no longer supported.
*   Fix `pathlib.Path` (and any `os.PathLike`) paths failing on Windows with `TypeError` ([#111](https://github.com/YakDriver/oschmod/issues/111)). Thanks @zapplecat for the original fix in [#112](https://github.com/YakDriver/oschmod/pull/112).
*   Fix exception on domain-joined Windows machines that cannot reach a domain controller. The SYSTEM account is now detected by its well-known SID instead of an account lookup ([#73](https://github.com/YakDriver/oschmod/issues/73)).
*   Add `other_sid` to `set_mode()`/`set_mode_recursive()` and `--other-sid` to the CLI to choose which Windows account receives "other" permissions; defaults to the built-in Users group ([#8](https://github.com/YakDriver/oschmod/issues/8)).
*   Add `-v`/`-vv` verbose output and `--version` to the CLI ([#36](https://github.com/YakDriver/oschmod/issues/36)). The CLI now prints an error and exits with status 1 instead of a traceback.
*   Add `python -m oschmod`, `oschmod.mode_to_symbolic()` (ls-style, including `s`/`t`), type hints, and a `py.typed` marker. Type hints and CodeQL setup inspired by @joelvaneenwyk's fork.
*   Fix `set_mode_recursive()` ignoring `dir_mode=0`.
*   Fix symbolic modes (e.g., `g+w`) clearing set-user-ID, set-group-ID, and sticky bits on macOS and Linux; they are now preserved. Add `get_full_mode()` to read them.
*   On Windows, the DACL written by `set_mode()` is now marked protected, so later changes to the parent folder's permissions are no longer inherited.
*   `set_mode()` now raises `TypeError` for unsupported mode types instead of silently applying mode `0`, and `ValueError` for numeric modes outside `0`–`0o7777`.
*   On Windows, an explicit `other_sid` that matches the object's owner, primary group, or SYSTEM SID raises `ValueError`, because the resulting mode could not be read back correctly.
*   Packaging moved to `pyproject.toml` (hatchling). CI moved from Travis CI and Azure Pipelines to GitHub Actions on Linux, macOS, and Windows, including a job that tests the minimum supported pywin32 (311). Releases publish to PyPI with Trusted Publishing.

### 0.3.1–0.3.12

*   Maintenance releases (dependency updates).

### 0.3.0

**Commit Delta**: [Change from 0.2.4 release](https://github.com/YakDriver/oschmod/compare/0.2.4...0.3.0)

**Released**: 2020.05.27

**Summary**:

*   Adds symbolic representation for mode changes (e.g., `+x`, `u+rwx`, `ugo-x`).

### 0.2.4

**Commit Delta**: [Change from 0.2.2 release](https://github.com/YakDriver/oschmod/compare/0.2.2...0.2.4)

**Released**: 2020.04.21

**Summary**:

*   Add command line interface (CLI).

### 0.2.2

**Commit Delta**: [Change from 0.2.0 release](https://github.com/YakDriver/oschmod/compare/0.2.0...0.2.2)

**Released**: 2020.04.21

**Summary**:

*   Fix issue with account lookup failing with error (`No mapping between account names and security IDs was done.`).

### 0.2.0

**Commit Delta**: [Change from 0.1.5 release](https://github.com/YakDriver/oschmod/compare/0.1.5...0.2.0)

**Released**: 2020.04.20

**Summary**:

*   Add recursive version of `oschmod.set_mode()`: `oschmod.set_mode_recursive()`

### 0.1.5

**Commit Delta**: [Change from 0.1.4 release](https://github.com/YakDriver/oschmod/compare/0.1.4...0.1.5)

**Released**: 2020.04.17

**Summary**:

*   Create Linux version of permissions test (`oschmod.perm_test()`)

### 0.1.4

**Commit Delta**: [Change from 0.1.0 release](https://github.com/YakDriver/oschmod/compare/0.1.0...0.1.4)

**Released**: 2020.04.17

**Summary**:

*   Revise Windows to keep permissions an object already has for SYSTEM/NT AUTHORITY and don't include those permissions in mode calculation.
*   Fix various minor cosmetic issues.

### 0.1.0

**Commit Delta**: [Change from 0.0.0 release](https://github.com/YakDriver/oschmod/compare/0.0.0...0.1.0)

**Released**: 2020.04.15

**Summary**:

*   Initial release
