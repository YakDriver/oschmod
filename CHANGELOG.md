## Changelog

### Unreleased

**Security**:

*   Recursive mode changes (`-R` and `set_mode_recursive()`) no longer follow symlinks found inside the tree, which could change files outside it (#183). On Windows, directory junctions are skipped as well. Use `-L` or `follow_symlinks=True` to follow them. This also holds if someone replaces a file or directory with a link while the walk is running: on macOS and Linux, oschmod works relative to already-open directories and never follows the last path component; on Windows, it changes each object through a handle and refuses any that resolves outside the tree.
*   Windows: reading a mode no longer counts access for unrelated accounts, such as *Administrators*, as "other" access. Before, a symbolic change like `u+x` on a typical file could give all Users full access (#185). Inherit-only entries are ignored too. `get_mode()` and `get_full_mode()` accept `other_sid`.
*   Windows: "write" no longer grants `WRITE_DAC` or `WRITE_OWNER`, so `oschmod 666` no longer lets Users change a file's permissions or take ownership (#184). Files previously set by oschmod read back the same. Explorer's *Modify* permission now reads as `rwx`.

**Fixes**:

*   Windows: when one account is both owner and group, or the group is Users, its bits are no longer merged across roles (#189). The first role applies, in the order owner, group, other, as on POSIX.
*   `-R` reports each error, keeps going, and exits 1 at the end instead of stopping partway through (#187). `set_mode_recursive()` accepts `on_error=` for the same behavior, including when the path is a single file. On Windows, an `other_sid` that matches an object's owner or group now raises `SidConflictError` (a `ValueError` subclass), which `on_error` receives so the walk can continue.
*   `-R` no longer silently skips the contents of directories it can't list. It applies the directory's new mode first and tries again (#186).
*   On Windows, `set_mode()` and `get_mode()` on a symlink or junction now act on its target, as they do on macOS and Linux. Previously they changed or read the link itself.
*   `-R` and `set_mode_recursive()` on a FIFO or other non-directory set its mode instead of failing with "Not a directory".
*   `-R -P` leaves a symlink to a file, or a dangling symlink, alone (exit 0), like GNU chmod.

**Features**:

*   Add `-H` (default), `-L`, and `-P` to control symlink handling with `-R`, like GNU chmod.

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
