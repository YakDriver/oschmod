"""oschmod module.

Module for working with file permissions that are consistent across Windows,
macOS, and Linux.

These bitwise permissions from the stat module can be used with this module:
    stat.S_IRWXU   # Mask for file owner permissions
    stat.S_IREAD   # Owner has read permission
    stat.S_IRUSR   # Owner has read permission
    stat.S_IWRITE  # Owner has write permission
    stat.S_IWUSR   # Owner has write permission
    stat.S_IEXEC   # Owner has execute permission
    stat.S_IXUSR   # Owner has execute permission

    stat.S_IRWXG   # Mask for group permissions
    stat.S_IRGRP   # Group has read permission
    stat.S_IWGRP   # Group has write permission
    stat.S_IXGRP   # Group has execute permission

    stat.S_IRWXO   # Mask for permissions for others (not in group)
    stat.S_IROTH   # Others have read permission
    stat.S_IWOTH   # Others have write permission
    stat.S_IXOTH   # Others have execute permission

Paths may be given as ``str`` or any ``os.PathLike`` (e.g., ``pathlib.Path``).
"""

from __future__ import annotations

import codecs
import contextlib
import errno
import functools
import os
import platform
import random
import re
import stat
import string
import sys
from collections.abc import Callable
from typing import IO, Any, Final

__version__ = "0.7.0"

PathType = str | os.PathLike[str]
"""Accepted path input: a string or any path-like object."""

ModeType = int | str
"""Accepted mode input: an int (e.g., 0o755), octal string ("755"), or symbolic ("u+x")."""


class ModeError(ValueError, AttributeError):
    """Invalid mode string, e.g. ``"u+q"`` or ``"9"``.

    Also an ``AttributeError``, which earlier versions raised for invalid
    symbolic modes, so existing ``except AttributeError`` code keeps working.
    """


class _ModeTypeError(TypeError, AttributeError):
    """Non-string symbolic mode; an ``AttributeError`` for backward compatibility."""


IS_WINDOWS: Final = platform.system() == "Windows"
HAS_PYWIN32 = False
try:
    import ntsecuritycon
    import win32file
    import win32security
    from pywintypes import error as pywinerror

    HAS_PYWIN32 = True
except ImportError:
    # Expected on macOS/Linux; on Windows the check below raises instead.
    HAS_PYWIN32 = False

HAS_PWD = False
try:
    import grp
    import pwd

    HAS_PWD = True
except ImportError:
    # Expected on Windows, which has no pwd/grp modules.
    HAS_PWD = False

if IS_WINDOWS and not HAS_PYWIN32:
    raise ImportError("win32security and ntsecuritycon required on Windows")

# Well-known SIDs. Comparing SIDs directly avoids LookupAccountSid(), which
# needs a domain controller for domain SIDs and fails on domain-joined
# machines that are offline (issue #73).
SYSTEM_SID: Final = "S-1-5-18"
"""Well-known SID for the local SYSTEM account (NT AUTHORITY\\SYSTEM)."""

USERS_SID: Final = "S-1-5-32-545"
"""Well-known SID for the built-in Users group (default for "others")."""

EVERYONE_SID: Final = "S-1-1-0"
AUTHENTICATED_USERS_SID: Final = "S-1-5-11"
# For each "other" SID, groups known to include all of its members: access
# granted to them is also "other" access when reading a mode. Everyone includes
# every account. Authenticated Users includes Users, but not everyone (e.g.,
# Guest), so it only counts when "other" is Users (#185).
_BROADER_THAN: Final = {
    USERS_SID: (EVERYONE_SID, AUTHENTICATED_USERS_SID),
    AUTHENTICATED_USERS_SID: (EVERYONE_SID,),
    EVERYONE_SID: (),
}
_BROADER_THAN_ANY: Final = (EVERYONE_SID,)

if HAS_PYWIN32:
    W_FLDIR = ntsecuritycon.FILE_LIST_DIRECTORY  # =                        1
    W_FADFL = ntsecuritycon.FILE_ADD_FILE  # =                             10
    W_FADSD = ntsecuritycon.FILE_ADD_SUBDIRECTORY  # =                    100
    W_FRDEA = ntsecuritycon.FILE_READ_EA  # =                            1000
    W_FWREA = ntsecuritycon.FILE_WRITE_EA  # =                          10000
    W_FTRAV = ntsecuritycon.FILE_TRAVERSE  # =                         100000
    W_FDLCH = ntsecuritycon.FILE_DELETE_CHILD  # =                    1000000
    W_FRDAT = ntsecuritycon.FILE_READ_ATTRIBUTES  # =                10000000
    W_FWRAT = ntsecuritycon.FILE_WRITE_ATTRIBUTES  # =              100000000
    W_DELET = ntsecuritycon.DELETE  # =                     10000000000000000
    W_RDCON = ntsecuritycon.READ_CONTROL  # =              100000000000000000
    W_WRDAC = ntsecuritycon.WRITE_DAC  # =                1000000000000000000
    W_WROWN = ntsecuritycon.WRITE_OWNER  # =             10000000000000000000
    W_SYNCH = ntsecuritycon.SYNCHRONIZE  # =            100000000000000000000
    W_FGNEX = ntsecuritycon.FILE_GENERIC_EXECUTE  # =   100100000000010100000
    W_FGNRD = ntsecuritycon.FILE_GENERIC_READ  # =      100100000000010001001
    W_FGNWR = ntsecuritycon.FILE_GENERIC_WRITE  # =     100100000000100010110
    W_GENAL = ntsecuritycon.GENERIC_ALL  # =    10000000000000000000000000000
    W_GENEX = ntsecuritycon.GENERIC_EXECUTE  # 100000000000000000000000000000
    W_GENWR = ntsecuritycon.GENERIC_WRITE  # 1000000000000000000000000000000
    W_GENRD = ntsecuritycon.GENERIC_READ  # -10000000000000000000000000000000

    W_DIRRD = W_FLDIR | W_FRDEA | W_FRDAT | W_RDCON | W_SYNCH
    # "w" never includes WRITE_DAC or WRITE_OWNER: on POSIX, write permission
    # doesn't let anyone chmod or chown (#184). The owner can always change the
    # DACL anyway (Windows grants an object's owner READ_CONTROL and WRITE_DAC).
    W_DIRWR = W_FADFL | W_FADSD | W_FWREA | W_FDLCH | W_FWRAT | W_DELET | W_RDCON | W_SYNCH
    W_DIREX = W_FTRAV | W_RDCON | W_SYNCH

    W_FILRD = W_FGNRD
    W_FILWR = W_FGNWR | W_DELET  # Explorer's "Modify" includes these, so it reads as rwx
    W_FILEX = W_FGNEX

    WIN_RWX_PERMS = [[W_FILRD, W_FILWR, W_FILEX], [W_DIRRD, W_DIRWR, W_DIREX]]

    WIN_FILE_PERMISSIONS = (
        "DELETE",
        "READ_CONTROL",
        "WRITE_DAC",
        "WRITE_OWNER",
        "SYNCHRONIZE",
        "FILE_GENERIC_READ",
        "FILE_GENERIC_WRITE",
        "FILE_GENERIC_EXECUTE",
        "FILE_DELETE_CHILD",
    )

    WIN_DIR_PERMISSIONS = (
        "DELETE",
        "READ_CONTROL",
        "WRITE_DAC",
        "WRITE_OWNER",
        "SYNCHRONIZE",
        "FILE_ADD_SUBDIRECTORY",
        "FILE_ADD_FILE",
        "FILE_DELETE_CHILD",
        "FILE_LIST_DIRECTORY",
        "FILE_TRAVERSE",
        "FILE_READ_ATTRIBUTES",
        "FILE_WRITE_ATTRIBUTES",
        "FILE_READ_EA",
        "FILE_WRITE_EA",
    )

    WIN_DIR_INHERIT_PERMISSIONS = (
        "DELETE",
        "READ_CONTROL",
        "WRITE_DAC",
        "WRITE_OWNER",
        "SYNCHRONIZE",
        "GENERIC_READ",
        "GENERIC_WRITE",
        "GENERIC_EXECUTE",
        "GENERIC_ALL",
    )

    WIN_ACE_TYPES = (
        "ACCESS_ALLOWED_ACE_TYPE",
        "ACCESS_DENIED_ACE_TYPE",
        "SYSTEM_AUDIT_ACE_TYPE",
        "SYSTEM_ALARM_ACE_TYPE",
    )

    WIN_INHERITANCE_TYPES = (
        "OBJECT_INHERIT_ACE",
        "CONTAINER_INHERIT_ACE",
        "NO_PROPAGATE_INHERIT_ACE",
        "INHERIT_ONLY_ACE",
        "INHERITED_ACE",
        "SUCCESSFUL_ACCESS_ACE_FLAG",
        "FAILED_ACCESS_ACE_FLAG",
    )

    # Kept for backward compatibility; SYSTEM is now detected by SID.
    SECURITY_NT_AUTHORITY = ("SYSTEM", "NT AUTHORITY", 5)

FILE: Final = 0
DIRECTORY: Final = 1

OBJECT_TYPES: Final = [FILE, DIRECTORY]

OWNER: Final = 0
GROUP: Final = 1
OTHER: Final = 2

OWNER_TYPES: Final = [OWNER, GROUP, OTHER]

READ: Final = 0
WRITE: Final = 1
EXECUTE: Final = 2

OPER_TYPES: Final = [READ, WRITE, EXECUTE]

STAT_MODES: Final = [
    [stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR],
    [stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP],
    [stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH],
]

STAT_KEYS: Final = (
    "S_IRUSR",
    "S_IWUSR",
    "S_IXUSR",
    "S_IRGRP",
    "S_IWGRP",
    "S_IXGRP",
    "S_IROTH",
    "S_IWOTH",
    "S_IXOTH",
)

_PERM_MASK: Final = stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO
_SPECIAL_MASK: Final = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
_FULL_MASK: Final = _PERM_MASK | _SPECIAL_MASK


def _fspath(path: PathType) -> str:
    """Normalize str or path-like input to str (pywin32 rejects PathLike, #111)."""
    result = os.fspath(path)
    if not isinstance(result, str):
        raise TypeError(f"path must be str or os.PathLike[str], not {type(result).__name__}")
    return result


def _not_found(path: str) -> FileNotFoundError:
    return FileNotFoundError(f"Path {path} could not be found.")


def get_mode(path: PathType, other_sid: Any = None) -> int:
    """Get bitwise mode (stat) of object (dir or file).

    On Windows, ``other_sid`` is the account whose access counts as "other"
    (default: Users), as in :func:`set_mode`. It is ignored on other platforms.
    """
    path = _fspath(path)
    if IS_WINDOWS:
        return win_get_permissions(path, other_sid)
    return os.stat(path).st_mode & _PERM_MASK


def get_full_mode(path: PathType, other_sid: Any = None) -> int:
    """Get mode including set-user-ID, set-group-ID, and sticky bits (up to 0o7777).

    Same as :func:`get_mode` on Windows, which has no equivalent of these bits.
    """
    path = _fspath(path)
    if IS_WINDOWS:
        return win_get_permissions(path, other_sid)
    return os.stat(path).st_mode & _FULL_MASK


def copy_mode(src: PathType, dst: PathType, other_sid: Any = None) -> None:
    """Give ``dst`` the same mode as ``src``, like ``chmod --reference=src dst``.

    Includes set-user-ID, set-group-ID, and sticky bits on macOS and Linux. On
    Windows, ``src``'s permissions are read and written as a mode (see
    :func:`get_mode`), which, unlike ``shutil.copymode``, sets the ACL.
    Symlinks are followed.
    """
    set_mode(dst, get_full_mode(src, other_sid), other_sid)


_OPEN_NEW_MODE_RE: Final = re.compile(r"[wxa]\+?[bt]?|[wxa][bt]\+")


def open_new(  # noqa: PLR0913 (mirrors open())
    path: PathType,
    mode: str = "w",
    perms: ModeType = 0o600,
    *,
    other_sid: Any = None,
    buffering: int = -1,
    encoding: str | None = None,
    errors: str | None = None,
    newline: str | None = None,
) -> IO[Any]:
    """Create a new file that has ``perms`` from the moment it exists, and open it.

    Use this instead of ``open()`` followed by :func:`set_mode` for secrets, so
    no one else can open the file in between (#196). The file must not exist:
    like ``open(path, "x")``, this raises ``FileExistsError`` otherwise, including
    when ``path`` is a symlink.

    ``mode`` is ``"w"``, ``"x"``, or ``"a"`` (all create the file), optionally with
    ``"b"`` or ``"t"`` and ``"+"`` to also read. ``perms`` is a mode such as
    ``0o600``, ``"600"``, or ``"u=rw"`` (applied to no permissions). The umask
    doesn't apply. Other arguments are as in ``open()``.

    On Windows, the file is created with the protected DACL that ``set_mode``
    would write; ``other_sid`` is as in :func:`set_mode`.
    """
    path = _fspath(path)
    if not isinstance(mode, str) or not _OPEN_NEW_MODE_RE.fullmatch(mode):
        raise ValueError(f"invalid mode {mode!r}: use 'w', 'x', or 'a', with optional 'b'/'t'/'+'")
    _check_open_args("b" in mode, buffering, encoding, errors, newline)
    new_mode = _resolve_mode_with(perms, lambda: 0, lambda: False)
    read = "+" in mode
    append = mode[0] == "a"

    created: list[tuple[int, int]] = []  # (st_dev, st_ino) of the file this call made

    def opener(name: str, _flags: int) -> int:
        if IS_WINDOWS:
            fd = _win_create_file(name, new_mode, other_sid, read, append)
        else:
            fd = _posix_create_file(name, new_mode, read, append)
        st = os.fstat(fd)
        created.append((st.st_dev, st.st_ino))
        return fd

    # open() owns the descriptor from here: if wrapping fails, it closes it once.
    # "x" makes open() itself require a new file; the opener does the creating.
    open_mode = "x" + mode[1:] if mode[0] != "a" else mode
    try:
        return open(  # returned to the caller, like open()
            path,
            open_mode,
            buffering,
            encoding=encoding,
            errors=errors,
            newline=newline,
            opener=opener,
        )
    except BaseException:
        # open() failed after creating the file (rare: arguments were checked
        # first). Remove it only if it is still the file this call created.
        if created:
            with contextlib.suppress(OSError):
                st = os.lstat(path)
                if (st.st_dev, st.st_ino) == created[0]:
                    os.remove(path)
        raise


def _check_open_args(
    binary: bool, buffering: int, encoding: str | None, errors: str | None, newline: str | None
) -> None:
    """Reject arguments open() would reject, before the file is created."""
    if binary:
        for name, value in (("encoding", encoding), ("errors", errors), ("newline", newline)):
            if value is not None:
                raise ValueError(f"binary mode doesn't take an {name} argument")
        return
    if buffering == 0:
        raise ValueError("can't have unbuffered text I/O")
    # "locale" is open()'s name for the locale encoding, not a codec
    if encoding is not None and encoding != "locale":
        codecs.lookup(encoding)  # LookupError for unknown encodings
    if newline not in (None, "", "\n", "\r", "\r\n"):
        raise ValueError(f"illegal newline value: {newline!r}")


def mkdir(path: PathType, perms: ModeType = 0o700, *, other_sid: Any = None) -> None:
    """Create a directory that has ``perms`` from the moment it exists.

    Like ``os.mkdir``, raises ``FileExistsError`` if ``path`` exists. The umask
    doesn't apply. ``perms`` and ``other_sid`` are as in :func:`open_new`.
    """
    path = _fspath(path)
    new_mode = _resolve_mode_with(perms, lambda: 0, lambda: True)
    if IS_WINDOWS:
        sa = _win_new_object_attributes(new_mode, DIRECTORY, other_sid)
        try:
            win32file.CreateDirectory(path, sa)
        except pywinerror as exc:
            raise OSError(0, exc.strerror, path, exc.winerror) from exc
        return
    # Pin the parent, then create and chmod relative to it, so swapping the
    # parent between the two calls can't redirect the chmod. The name has no
    # trailing slash, so a symlink that replaces the new directory isn't
    # followed. Nothing is opened for reading: an unreadable parent works, as
    # with os.mkdir. ".." isn't collapsed, since that could change the parent.
    parent, name = os.path.split(path.rstrip("/") or path)
    dir_fd = _open_search_dir(parent or ".")
    try:
        # The umask can only remove bits, so the directory is never more open
        # than new_mode; the chmod then sets it exactly.
        os.mkdir(name, new_mode & _PERM_MASK, dir_fd=dir_fd)
        _PosixObj(path, DIRECTORY, dir_fd=dir_fd, name=name, nofollow=True).set_mode(new_mode)
    finally:
        os.close(dir_fd)


# Flags to open a directory for use as dir_fd without read permission: O_PATH on
# Linux, O_SEARCH on macOS and the BSDs. The python.org macOS builds of 3.11 and
# 3.12 don't define os.O_SEARCH although the kernel supports it, so use XNU's
# value (O_EXEC | O_DIRECTORY) there.
_XNU_O_SEARCH = 0x40100000
_SEARCH_FLAGS = (
    getattr(os, "O_PATH", 0)
    or getattr(os, "O_SEARCH", 0)
    or (_XNU_O_SEARCH if sys.platform == "darwin" else 0)
)


def _open_search_dir(path: str) -> int:
    """Open a directory as a dir_fd, needing only search permission if possible."""
    base = os.O_DIRECTORY | os.O_CLOEXEC
    if _SEARCH_FLAGS:
        try:
            return os.open(path, _SEARCH_FLAGS | base)
        except OSError as exc:
            if exc.errno != errno.EINVAL:  # EINVAL: a kernel without the flag
                raise
    return os.open(path, os.O_RDONLY | base)


def _posix_create_file(path: str, mode: int, read: bool, append: bool) -> int:
    flags = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    flags |= os.O_RDWR if read else os.O_WRONLY
    if append:
        flags |= os.O_APPEND
    # O_EXCL fails if anything, even a dangling symlink, is at path. The umask can
    # only remove bits, so the file is never more open than mode; fchmod then sets
    # the exact mode (including bits the umask removed and special bits).
    fd = os.open(path, flags, mode & _PERM_MASK)
    try:
        os.chmod(fd, mode)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _win_new_object_attributes(mode: int, object_type: int, other_sid: Any) -> Any:
    """SECURITY_ATTRIBUTES for a new file or directory with exactly ``mode``."""
    import win32api  # noqa: PLC0415

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    try:
        owner = win32security.GetTokenInformation(token, win32security.TokenOwner)
        group = win32security.GetTokenInformation(token, win32security.TokenPrimaryGroup)
    finally:
        token.Close()
    sec_des = win32security.SECURITY_DESCRIPTOR()
    sec_des.SetSecurityDescriptorOwner(owner, False)
    sec_des.SetSecurityDescriptorGroup(group, False)
    _win_update_sd(sec_des, mode, object_type, other_sid)
    sa = win32security.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR = sec_des
    sa.bInheritHandle = False  # pywin32 defaults to True
    return sa


def _win_create_file(path: str, mode: int, other_sid: Any, read: bool, append: bool) -> int:
    """Create a new file with its final DACL in one step; return a C runtime fd."""
    if sys.platform != "win32":  # pragma: no cover - for type checkers
        raise NotImplementedError
    import msvcrt  # noqa: PLC0415

    sa = _win_new_object_attributes(mode, FILE, other_sid)
    access = ntsecuritycon.GENERIC_WRITE | (ntsecuritycon.GENERIC_READ if read else 0)
    try:
        handle = win32file.CreateFile(
            path,
            access,
            # Same sharing as open(): the C runtime's _wopen shares read and write.
            # CREATE_NEW, not the share mode, is what makes creation exclusive.
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            sa,
            win32file.CREATE_NEW,  # fails if path exists
            # Without this, CREATE_NEW follows a dangling symlink and creates its
            # target; with it, the link itself counts as an existing file.
            win32file.FILE_ATTRIBUTE_NORMAL | win32file.FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    except pywinerror as exc:
        raise OSError(0, exc.strerror, path, exc.winerror) from exc
    flags = (os.O_RDWR if read else os.O_WRONLY) | (os.O_APPEND if append else 0)
    raw = handle.Detach()
    try:
        return msvcrt.open_osfhandle(raw, flags)
    except BaseException:
        import win32api  # noqa: PLC0415

        win32api.CloseHandle(raw)
        raise


def set_mode(path: PathType, mode: ModeType, other_sid: Any = None) -> None:
    """Set bitwise mode (stat) of object (dir or file).

    Three types of modes can be used:
    1. Decimal mode - an integer representation of set bits (eg, 512)
    2. Octal mode - a string expressing an octal number (eg, "777")
    3. Symbolic representation - a string with modifier symbols (eg, "+x")

    On Windows, ``other_sid`` selects the account that receives "other"
    permissions. It may be a string SID (e.g., ``"S-1-5-11"`` for
    Authenticated Users) or a PySID. Defaults to the built-in Users group.
    It is ignored on other platforms.
    """
    path = _fspath(path)
    new_mode = _resolve_mode(path, mode, other_sid)

    if IS_WINDOWS:
        win_set_permissions(path, new_mode, other_sid)
        return
    os.chmod(path, new_mode)


def _resolve_mode(path: str, mode: ModeType, other_sid: Any = None) -> int:
    """Convert int, octal-string, or symbolic mode into an int mode for path."""
    return _resolve_mode_with(
        mode, lambda: get_full_mode(path, other_sid), lambda: os.path.isdir(path)
    )


def _resolve_mode_with(
    mode: ModeType, current_mode: Callable[[], int], is_dir: Callable[[], bool]
) -> int:
    """Like :func:`_resolve_mode`; the callables are used only for symbolic modes."""
    if isinstance(mode, bool) or not isinstance(mode, int | str):
        raise TypeError(f"mode must be int or str, not {type(mode).__name__}")
    if isinstance(mode, str):
        if "+" in mode or "-" in mode or "=" in mode:
            return get_effective_mode(current_mode(), mode, is_dir=is_dir())
        try:
            octal = int(mode, 8)
        except ValueError:
            raise ModeError(f"invalid mode {mode!r}") from None
        if not 0 <= octal <= 0o7777:
            raise ModeError(f"mode {mode!r} is out of range (0 to 7777)")
        return octal
    if not 0 <= mode <= 0o7777:
        raise ValueError(f"mode {mode:#o} is out of range (0 to 0o7777)")
    return mode


class SidConflictError(ValueError):
    """An explicit ``other_sid`` is the object's owner, group, or SYSTEM SID (Windows).

    This depends on the object, so recursive operations report it per object
    (see ``on_error``) and continue.
    """


# Junctions are directory reparse points that os.DirEntry.is_symlink() doesn't
# report (os.path.isjunction needs Python 3.12+).
_IO_REPARSE_TAG_MOUNT_POINT: Final = 0xA0000003

# Per-object errors that recursive operations report and skip past. Invalid
# modes (ValueError, TypeError, AttributeError) are not included: they would
# fail for every object.
_OBJECT_ERRORS: tuple[type[Exception], ...] = (OSError, SidConflictError)
if HAS_PYWIN32:
    _OBJECT_ERRORS += (pywinerror,)

ErrorHandler = Callable[[str, Exception], None]
"""Callback for recursive operations: called with the path and the error."""


def _is_junction(path: str) -> bool:
    if not IS_WINDOWS:
        return False
    try:
        return getattr(os.lstat(path), "st_reparse_tag", 0) == _IO_REPARSE_TAG_MOUNT_POINT
    except OSError:
        return False


def _is_link(path: str) -> bool:
    """Return True for a symlink (even dangling) or, on Windows, a junction."""
    return os.path.islink(path) or _is_junction(path)


def _not_followed(path: str, why: str = "is a symlink") -> OSError:
    return OSError(errno.ELOOP, f"{why}; not followed", path)


class _PathObj:
    """An object addressed by path (follows symlinks, like os.chmod)."""

    def __init__(self, path: str, obj_type: int) -> None:
        self.path = path
        self.type = obj_type

    def get_full_mode(self, other_sid: Any = None) -> int:
        return get_full_mode(self.path, other_sid)

    def set_mode(self, mode: ModeType, other_sid: Any = None) -> None:
        set_mode(self.path, mode, other_sid)


class _PosixObj:
    """An object reached during a walk, addressed by fd or by (dir_fd, name).

    With ``nofollow``, a symlink is never followed, even if one replaces the
    object after it was listed: the stat and chmod are relative to the
    already-open parent directory and don't follow the final component.
    """

    def __init__(  # noqa: PLR0913 (keyword-only addressing options)
        self,
        path: str,
        obj_type: int,
        *,
        fd: int | None = None,
        dir_fd: int | None = None,
        name: str = "",
        nofollow: bool = False,
    ) -> None:
        self.path = path
        self.type = obj_type
        self._fd = fd
        self._dir_fd = dir_fd
        self._name = name
        self._nofollow = nofollow

    def get_full_mode(self, other_sid: Any = None) -> int:  # other_sid: Windows only
        if self._fd is not None:
            st = os.fstat(self._fd)
        else:
            st = os.stat(self._name, dir_fd=self._dir_fd, follow_symlinks=not self._nofollow)
            if stat.S_ISLNK(st.st_mode):
                raise _not_followed(self.path)
        return st.st_mode & _FULL_MASK

    def set_mode(self, mode: ModeType, other_sid: Any = None) -> None:
        new_mode = _resolve_mode_with(mode, self.get_full_mode, lambda: self.type == DIRECTORY)
        if self._fd is not None:
            os.chmod(self._fd, new_mode)
        elif not self._nofollow:
            os.chmod(self._name, new_mode, dir_fd=self._dir_fd)
        else:
            try:
                os.chmod(self._name, new_mode, dir_fd=self._dir_fd, follow_symlinks=False)
            except (NotImplementedError, ValueError):
                # Linux can't do this for symlinks (Python raises ValueError when
                # dir_fd is used) or without fchmodat2/glibc emulation. Use an
                # O_PATH fd, which can't follow a link, and report links.
                self._chmod_o_path(new_mode)

    def _chmod_o_path(self, mode: int) -> None:
        o_path = getattr(os, "O_PATH", None)
        if o_path is None:  # pragma: no cover - lchmod exists where O_PATH doesn't
            raise NotImplementedError("no way to change mode without following symlinks")
        fd = os.open(self._name, o_path | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._dir_fd)
        try:
            if stat.S_ISLNK(os.fstat(fd).st_mode):
                raise _not_followed(self.path)
            os.chmod(f"/proc/self/fd/{fd}", mode)
        finally:
            os.close(fd)


class _PosixWalker:
    """Directory access for the walk on macOS/Linux, using directory fds."""

    def __init__(self, follow_symlinks: bool) -> None:
        self.follow = follow_symlinks

    def open_dir(self, parent: int | None, name: str) -> tuple[int, list[os.DirEntry[str]]]:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if parent is not None and not self.follow:
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(name, flags, dir_fd=parent)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise _not_followed(name) from exc
            raise
        try:
            with os.scandir(fd) as it:
                return fd, list(it)
        except BaseException:
            os.close(fd)
            raise

    def close(self, ref: int) -> None:
        os.close(ref)

    def key(self, ref: int) -> tuple[int, int]:
        st = os.fstat(ref)
        return st.st_dev, st.st_ino

    def dir_obj(self, ref: int, path: str) -> _PosixObj:
        return _PosixObj(path, DIRECTORY, fd=ref)

    def named_obj(self, parent: int | None, name: str, path: str, obj_type: int) -> _PosixObj:
        nofollow = parent is not None and not self.follow
        return _PosixObj(path, obj_type, dir_fd=parent, name=name, nofollow=nofollow)

    def is_link(self, entry: os.DirEntry[str]) -> bool:
        return entry.is_symlink()


_WIN_SECURITY_INFO: Final = 0x7  # OWNER | GROUP | DACL _SECURITY_INFORMATION


def _win_open(path: str, access: int) -> Any:
    """Open a file or directory handle (following links) for security operations."""
    try:
        return win32file.CreateFile(
            path,
            access,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    except pywinerror as exc:
        # OSError picks the subclass (FileNotFoundError, PermissionError, ...)
        # from the Windows error code.
        raise OSError(0, exc.strerror, path, exc.winerror) from exc


def _win_final_path(path: str) -> str:
    handle = _win_open(path, ntsecuritycon.READ_CONTROL)
    try:
        return str(os.path.normcase(win32file.GetFinalPathNameByHandle(handle, 0)))
    finally:
        handle.Close()


class _WinObj:
    """An object reached during a walk on Windows, changed through a handle.

    Unless links are followed, the handle's final path must be inside the tree.
    That check and the change use the same handle, so replacing the object or a
    parent with a symlink or junction after it was listed can't redirect the
    change outside the tree.
    """

    def __init__(self, path: str, obj_type: int, root_final: str | None) -> None:
        self.path = path
        self.type = obj_type
        self._root_final = root_final

    def _open(self, access: int) -> Any:
        handle = _win_open(self.path, access)
        if self._root_final is not None:
            final = os.path.normcase(win32file.GetFinalPathNameByHandle(handle, 0))
            root = self._root_final.rstrip("\\")
            if final != root and not final.startswith(root + "\\"):
                handle.Close()
                raise _not_followed(self.path, "resolves outside the tree")
        return handle

    def get_full_mode(self, other_sid: Any = None) -> int:
        handle = self._open(ntsecuritycon.READ_CONTROL)
        try:
            sec_des = win32security.GetKernelObjectSecurity(handle, _WIN_SECURITY_INFO)
        finally:
            handle.Close()
        return _win_mode_from_sd(sec_des, self.type, other_sid)

    def set_mode(self, mode: ModeType, other_sid: Any = None) -> None:
        handle = self._open(ntsecuritycon.READ_CONTROL | ntsecuritycon.WRITE_DAC)
        try:
            sec_des = win32security.GetKernelObjectSecurity(handle, _WIN_SECURITY_INFO)
            new_mode = _resolve_mode_with(
                mode,
                lambda: _win_mode_from_sd(sec_des, self.type, other_sid),
                lambda: self.type == DIRECTORY,
            )
            _win_update_sd(sec_des, new_mode, self.type, other_sid)
            # Like SetFileSecurity, this doesn't re-propagate inheritance to children.
            win32security.SetKernelObjectSecurity(
                handle, win32security.DACL_SECURITY_INFORMATION, sec_des
            )
        finally:
            handle.Close()


class _WinWalker:
    """Directory access for the walk on Windows (lists by path; see _WinObj)."""

    def __init__(self, follow_symlinks: bool, root: str) -> None:
        self.follow = follow_symlinks
        self.root_final = None if follow_symlinks else _win_final_path(root)

    def open_dir(self, parent: str | None, name: str) -> tuple[str, list[os.DirEntry[str]]]:
        path = name if parent is None else os.path.join(parent, name)
        with os.scandir(path) as it:
            return path, list(it)

    def close(self, ref: str) -> None:
        pass

    def key(self, ref: str) -> tuple[int, int]:
        st = os.stat(ref)
        return st.st_dev, st.st_ino

    def dir_obj(self, ref: str, path: str) -> _WinObj:
        return _WinObj(path, DIRECTORY, self.root_final)

    def named_obj(self, parent: str | None, name: str, path: str, obj_type: int) -> _WinObj:
        return _WinObj(path, obj_type, self.root_final)

    def is_link(self, entry: os.DirEntry[str]) -> bool:
        return entry.is_symlink() or _is_junction(entry.path)


def _open_dir_or_repair(
    walker: Any, apply: Callable[[Any], None], parent: Any, name: str, path: str
) -> tuple[Any, list[os.DirEntry[str]], bool]:
    """List a directory; if denied, apply its mode first and retry (#186).

    Returns (dir ref, entries, whether the mode was applied).
    """
    try:
        dir_ref, entries = walker.open_dir(parent, name)
    except PermissionError:
        apply(walker.named_obj(parent, name, path, DIRECTORY))
        dir_ref, entries = walker.open_dir(parent, name)
        return dir_ref, entries, True
    return dir_ref, entries, False


def _visit_entry(
    walker: Any, apply: Callable[[Any], None], dir_ref: Any, entry: os.DirEntry[str], path: str
) -> bool:
    """Apply to a non-directory entry; return True if it's a directory to descend into."""
    if not walker.follow and walker.is_link(entry):
        return False
    if entry.is_dir():  # follows links only when following is enabled
        return True
    apply(walker.named_obj(dir_ref, entry.name, path, FILE))
    return False


def _handle_error(on_error: ErrorHandler | None, path: str, exc: Exception) -> None:
    if on_error is None:
        raise exc
    on_error(path, exc)


def _make_walker(root: str, follow_symlinks: bool, fail: ErrorHandler) -> Any:
    try:
        if IS_WINDOWS:
            return _WinWalker(follow_symlinks, root)
        return _PosixWalker(follow_symlinks)
    except _OBJECT_ERRORS as exc:
        fail(root, exc)
        return None


def _call(fail: ErrorHandler, path: str, apply: Callable[[Any], None], obj: Any) -> None:
    try:
        apply(obj)
    except _OBJECT_ERRORS as exc:
        fail(path, exc)


def _first_visit(
    walker: Any, dir_ref: Any, visited: set[tuple[int, int]], path: str, fail: ErrorHandler
) -> bool:
    """Record a directory when following links.

    Returns False if it was already seen (a cycle) or can't be identified (e.g.,
    it was removed after listing); the latter is reported through ``fail``.
    """
    try:
        key = walker.key(dir_ref)
    except _OBJECT_ERRORS as exc:
        fail(path, exc)
        return False
    if key in visited:
        return False
    visited.add(key)
    return True


def _close_pending(walker: Any, stack: list[tuple[bool, Any, str, str, bool]]) -> None:
    """Close directories still open after the walk stopped early."""
    for done, ref, *_ in stack:
        if done:
            walker.close(ref)


def _walk_apply(
    root: str,
    apply: Callable[[Any], None],
    follow_symlinks: bool = False,
    on_error: ErrorHandler | None = None,
) -> None:
    """Call ``apply(obj)`` for root (a directory) and everything under it.

    ``obj`` has ``path``, ``type`` (FILE or DIRECTORY), ``get_full_mode()``,
    and ``set_mode(mode, other_sid)``.

    Contents are handled before their directory (root last), so removing a
    directory's own read or search permission doesn't stop traversal. If a
    directory can't be listed, its mode is applied first and listing is retried,
    so modes like ``u+rwx`` can repair unreadable directories.

    Symlinks and junctions below root are skipped unless ``follow_symlinks``,
    including ones swapped in during the walk (see _PosixObj and _WinObj).
    When following, directories already visited are skipped to avoid cycles.

    Errors for individual objects go to ``on_error(path, exc)`` and traversal
    continues; without a handler, the first error is raised.
    """
    fail = functools.partial(_handle_error, on_error)
    walker = _make_walker(root, follow_symlinks, fail)
    if walker is None:
        return

    visited: set[tuple[int, int]] = set()
    # (finished listing?, dir ref or parent ref, name, display path, mode applied?)
    stack: list[tuple[bool, Any, str, str, bool]] = [(False, None, root, root, False)]
    try:
        while stack:
            done, ref, name, path, applied = stack.pop()
            if done:
                try:
                    if not applied:
                        _call(fail, path, apply, walker.dir_obj(ref, path))
                finally:
                    walker.close(ref)
                continue

            try:
                dir_ref, entries, applied = _open_dir_or_repair(walker, apply, ref, name, path)
            except _OBJECT_ERRORS as exc:
                fail(path, exc)
                continue

            if follow_symlinks and not _first_visit(walker, dir_ref, visited, path, fail):
                walker.close(dir_ref)
                continue

            stack.append((True, dir_ref, name, path, applied))
            for entry in entries:
                entry_path = os.path.join(path, entry.name)
                try:
                    if _visit_entry(walker, apply, dir_ref, entry, entry_path):
                        stack.append((False, dir_ref, entry.name, entry_path, False))
                except _OBJECT_ERRORS as exc:
                    fail(entry_path, exc)
    finally:
        _close_pending(walker, stack)


def set_mode_recursive(  # noqa: PLR0913 (last two are keyword-only)
    path: PathType,
    mode: ModeType,
    dir_mode: ModeType | None = None,
    other_sid: Any = None,
    *,
    follow_symlinks: bool = False,
    on_error: ErrorHandler | None = None,
) -> None:
    r"""Set all file and directory permissions at or under path to modes.

    Args:
    path: (:obj:`str` or :obj:`os.PathLike`)
        Object which will have its mode set. If path is not a directory (e.g.,
        a file or FIFO), only its mode is set - no recursion occurs. If path is
        a directory, its mode and the mode of all files and subdirectories
        below it are set. If path itself is a symlink, it is followed.

    mode: (`int` or `str`)
        Mode to be applied to object(s).

    dir_mode: (`int` or `str`)
        If provided, this mode is given to all directories only.

    other_sid:
        Windows only. See :func:`set_mode`.

    follow_symlinks: (`bool`)
        Follow symlinks (and Windows junctions) found below path, changing
        their targets and descending into linked directories. Off by default:
        links are skipped, so nothing outside path is changed, even if links
        are created while the walk is running.

    on_error: (`callable`)
        Called as ``on_error(path, exc)`` when an object can't be read or
        changed (``OSError``, or :class:`SidConflictError` on Windows); the walk
        then continues. By default the error is raised and the walk stops.
        Invalid modes always raise.

    """
    path = _fspath(path)
    if not os.path.isdir(path):
        try:
            set_mode(path, mode, other_sid)
        except _OBJECT_ERRORS as exc:
            if on_error is None:
                raise
            on_error(path, exc)
        return

    if dir_mode is None:
        dir_mode = mode

    def apply(obj: Any) -> None:
        obj.set_mode(mode if obj.type == FILE else dir_mode, other_sid)

    _walk_apply(path, apply, follow_symlinks=follow_symlinks, on_error=on_error)


# GNU chmod symbolic mode grammar:
#   clause = [ugoa]* action+        action = [-+=] ([ugo] | [rwxXst]*)
# [ugo] comes first: [rwxXst]* also matches the empty string.
_CLAUSE_RE: Final = re.compile(r"([ugoa]*)((?:[-+=](?:[ugo]|[rwxXst]*))+)")
_ACTION_RE: Final = re.compile(r"([-+=])([ugo]|[rwxXst]*)")
_WHO_BITS: Final = {
    "u": stat.S_ISUID | stat.S_IRWXU,
    "g": stat.S_ISGID | stat.S_IRWXG,
    "o": stat.S_ISVTX | stat.S_IRWXO,
}
_PERM_BITS: Final = {
    "r": 0o444,
    "w": 0o222,
    "x": 0o111,
    "s": stat.S_ISUID | stat.S_ISGID,
    "t": stat.S_ISVTX,
}
_COPY_SHIFT: Final = {"u": 6, "g": 3, "o": 0}
_SET_ID_BITS: Final = stat.S_ISUID | stat.S_ISGID


def get_effective_mode(current_mode: int, symbolic: str, is_dir: bool = False) -> int:
    """Apply a symbolic mode to ``current_mode`` and return the new mode.

    Follows GNU chmod: comma-separated clauses of ``[ugoa]*`` and one or more
    actions ``[-+=]`` with permissions ``[rwxXst]*`` or a class to copy
    (``u``, ``g``, or ``o``), e.g. ``u+r-x,g=u,o-w,a+X,+t``.

    * ``X`` adds execute only if the object is a directory (``is_dir``) or
      already has execute permission for someone.
    * ``s`` is set-user-ID (with ``u``) and set-group-ID (with ``g``); ``t`` is
      the sticky bit (with ``o``). With no ``ugoa``, both apply.
    * ``=`` clears the bits of the classes it sets, including their set-ID and
      sticky bits; directories keep set-user-ID and set-group-ID unless ``s``
      is given.
    * With no ``ugoa``, all classes are affected. Unlike GNU chmod, the umask is
      not applied.

    Raises :class:`ModeError` (a ``ValueError``) for invalid syntax and
    ``TypeError`` if ``symbolic`` isn't a string. Both are also
    ``AttributeError``, which earlier versions raised.
    """
    if not isinstance(symbolic, str):
        raise _ModeTypeError(f"symbolic must be a string, not {type(symbolic).__name__}")

    mode = current_mode
    for clause in symbolic.split(","):
        match = _CLAUSE_RE.fullmatch(clause.strip())
        if match is None:
            raise ModeError(f"invalid mode modifier {clause!r}")
        mode = _apply_clause(mode, match.group(1), match.group(2), is_dir)
    return mode


def _action_bits(mode: int, perms: str, is_dir: bool) -> tuple[int, int]:
    """Bits an action sets or clears in every class, and the bits named explicitly."""
    if perms in _COPY_SHIFT:  # e.g. g=u: copy one class's rwx to the others
        return ((mode >> _COPY_SHIFT[perms]) & 0o7) * 0o111, 0
    value = 0
    for letter in perms:
        if letter != "X":
            value |= _PERM_BITS[letter]
        elif is_dir or mode & 0o111:
            value |= 0o111
    return value, value


def _apply_clause(mode: int, who: str, actions: str, is_dir: bool) -> int:
    """Apply one clause, like gnulib's mode_adjust (with a umask of 0)."""
    if not who or "a" in who:
        affected = _FULL_MASK
    else:
        affected = 0
        for letter in who:
            affected |= _WHO_BITS[letter]

    for op, perms in _ACTION_RE.findall(actions):
        value, mentioned = _action_bits(mode, perms, is_dir)
        value &= affected
        # Directories keep set-user-ID and set-group-ID unless "s" is given.
        omit = _SET_ID_BITS & ~(mentioned & affected) if is_dir else 0
        value &= ~omit
        if op == "=":
            mode = (mode & ((~affected & _FULL_MASK) | omit)) | value
        elif op == "+":
            mode |= value
        else:
            mode &= ~value
    return mode


def mode_to_symbolic(mode: int) -> str:
    """Return the ``ls``-style permission string, e.g. ``0o4755`` -> ``"rwsr-xr-x"``.

    Set-user-ID, set-group-ID, and sticky bits are shown as ``s``/``S`` and ``t``/``T``.
    """
    return stat.filemode(mode & _FULL_MASK)[1:]


def get_object_type(path: PathType) -> int:
    """Get whether object is file or directory."""
    return FILE if os.path.isfile(path) else DIRECTORY


def get_owner(path: PathType) -> Any:
    """Get the object owner.

    On Windows, returns ``(name, domain, type)`` from ``LookupAccountSid``. If the
    account can't be looked up (e.g., a domain account while the domain
    controller is unreachable), returns ``(sid_string, "", SidTypeUnknown)``.
    """
    path = _fspath(path)
    if IS_WINDOWS:
        return _win_lookup_account(win_get_owner_sid(path))
    return pwd.getpwuid(os.stat(path).st_uid).pw_name


def get_group(path: PathType) -> Any:
    """Get the object group. On Windows, see :func:`get_owner` for the result."""
    path = _fspath(path)
    if IS_WINDOWS:
        return _win_lookup_account(win_get_group_sid(path))
    return grp.getgrgid(os.stat(path).st_gid).gr_name


_SID_TYPE_UNKNOWN: Final = 8  # SID_NAME_USE SidTypeUnknown


def _win_lookup_account(sid: Any) -> tuple[str, str, int]:
    """LookupAccountSid, or the string SID if lookup fails (offline, deleted account; #190)."""
    try:
        name, domain, sid_type = win32security.LookupAccountSid(None, sid)
    except pywinerror:
        return win32security.ConvertSidToStringSid(sid), "", _SID_TYPE_UNKNOWN
    return name, domain, sid_type


def win_get_owner_sid(path: PathType) -> Any:
    """Get the file owner."""
    sec_descriptor = win32security.GetNamedSecurityInfo(
        _fspath(path), win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION
    )
    return sec_descriptor.GetSecurityDescriptorOwner()


def win_get_group_sid(path: PathType) -> Any:
    """Get the file group."""
    sec_descriptor = win32security.GetNamedSecurityInfo(
        _fspath(path), win32security.SE_FILE_OBJECT, win32security.GROUP_SECURITY_INFORMATION
    )
    return sec_descriptor.GetSecurityDescriptorGroup()


def win_get_other_sid(other_sid: Any = None) -> Any:
    """Get the SID used for "other" permissions.

    ``other_sid`` may be a string SID (e.g., ``"S-1-5-11"``), a PySID, or
    ``None`` for the built-in Users group (``S-1-5-32-545``).
    """
    if other_sid is None:
        other_sid = USERS_SID
    if isinstance(other_sid, str):
        return win32security.ConvertStringSidToSid(other_sid)
    return other_sid


def _win_system_sid() -> Any:
    return win32security.ConvertStringSidToSid(SYSTEM_SID)


def _win_check_other_sid(sids: list[Any], system_sid: Any) -> None:
    """Reject an explicit other_sid that collides with owner, group, or SYSTEM.

    Such a SID cannot round-trip: reading the mode attributes its ACE to the
    owner/group (or ignores it for SYSTEM), so "o" bits would be lost.
    """
    other = sids[OTHER]
    for name, sid in (("owner", sids[OWNER]), ("group", sids[GROUP]), ("SYSTEM", system_sid)):
        if other == sid:
            raise SidConflictError(
                f"other_sid {win32security.ConvertSidToStringSid(other)} is the object's "
                f"{name} SID; choose a different account for 'other' permissions"
            )


def convert_win_to_stat(win_perm: int, user_type: int, object_type: int) -> int:
    """Given Win perm and user type, give stat mode."""
    mode = 0

    for oper in OPER_TYPES:
        if win_perm & WIN_RWX_PERMS[object_type][oper] == WIN_RWX_PERMS[object_type][oper]:
            mode = mode | STAT_MODES[user_type][oper]

    return mode


def convert_stat_to_win(mode: int, user_type: int, object_type: int) -> int:
    """Given stat mode, return Win bitwise permissions for user type."""
    win_perm = 0

    for oper in OPER_TYPES:
        if mode & STAT_MODES[user_type][oper] == STAT_MODES[user_type][oper]:
            win_perm = win_perm | WIN_RWX_PERMS[object_type][oper]

    return win_perm


def win_get_user_type(sid: Any, sids: list[Any]) -> int:
    """Given object and SIDs, return user type.

    Kept for backward compatibility. Mode reading no longer uses this, because it
    treats every account other than the owner and group as "other" (#185).
    """
    if sid == sids[OWNER]:
        return OWNER

    if sid == sids[GROUP]:
        return GROUP

    return OTHER


def win_get_object_sids(path: PathType, other_sid: Any = None) -> list[Any]:
    """Get the owner, group, other SIDs for an object."""
    return [win_get_owner_sid(path), win_get_group_sid(path), win_get_other_sid(other_sid)]


def _win_resolve(path: str) -> str:
    """Follow a symlink or junction, like os.stat/os.chmod do on POSIX.

    Windows security APIs otherwise act on the link itself.
    """
    if not os.path.exists(path):
        raise _not_found(path)
    return os.path.realpath(path) if _is_link(path) else path


def win_get_permissions(path: PathType, other_sid: Any = None) -> int:
    """Get the file or dir permissions (of the target, if path is a link)."""
    path = _win_resolve(_fspath(path))

    return _win_get_permissions(path, get_object_type(path), other_sid)


def _win_get_permissions(path: str, object_type: int, other_sid: Any = None) -> int:
    """Get the permissions."""
    sec_des = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT, _WIN_SECURITY_INFO
    )
    return _win_mode_from_sd(sec_des, object_type, other_sid)


def _win_roles(sec_des: Any, other_sid: Any = None) -> list[tuple[int, Any]]:
    """(user type, SID) pairs, one per distinct SID, in POSIX precedence order.

    A SID that is both owner and group is the owner only, and a group SID that is
    also the "other" SID is the group only, just as POSIX applies only the first
    matching class (#189).
    """
    roles: list[tuple[int, Any]] = []
    candidates = (
        (OWNER, sec_des.GetSecurityDescriptorOwner()),
        (GROUP, sec_des.GetSecurityDescriptorGroup()),
        (OTHER, win_get_other_sid(other_sid)),
    )
    for user_type, sid in candidates:
        if sid is not None and all(sid != seen for _, seen in roles):
            roles.append((user_type, sid))
    return roles


def _win_ace(dacl: Any, index: int) -> tuple[int, int, int, Any] | None:
    """Return (type, flags, mask, SID) for an ACE, or None if pywin32 can't read it.

    pywin32 returns ((type, flags), mask, sid) for standard ACEs, but
    ((type, flags), mask, object_type, inherited_object_type, sid) for object
    ACEs, and raises NotImplementedError for others (e.g., callback ACEs).
    """
    try:
        ace = dacl.GetAce(index)
    except NotImplementedError:
        return None
    (ace_type, ace_flags), mask = ace[0], ace[1]
    return ace_type, ace_flags, mask, ace[-1]


def _win_broader_sids(other: Any) -> list[Any]:
    """SIDs whose access also counts as access for the "other" SID."""
    broader = _BROADER_THAN.get(win32security.ConvertSidToStringSid(other), _BROADER_THAN_ANY)
    return [win32security.ConvertStringSidToSid(s) for s in broader]


def _win_mode_from_sd(sec_des: Any, object_type: int, other_sid: Any = None) -> int:
    """Compute a mode from a security descriptor with owner, group, and DACL.

    Only ACEs for the owner, the group, the "other" SID, and groups that include
    all of "other" (see _BROADER_THAN) count. ACEs for other accounts, such as
    Administrators, are ignored: counting them as "other" would make the next
    symbolic change grant their access to everyone in "other" (#185).
    """
    dacl = sec_des.GetSecurityDescriptorDacl()
    if dacl is None:  # NULL DACL: everyone has full access
        return _PERM_MASK
    roles = _win_roles(sec_des, other_sid)
    other = win_get_other_sid(other_sid)
    broader = _win_broader_sids(other)
    # Broader groups' access belongs to whichever role holds the "other" SID:
    # OTHER, or GROUP/OWNER when that SID also fills an earlier role (e.g., the
    # primary group is Users). Otherwise it would read as "o" bits that the
    # writer never stores, and an unrelated change would drop that access.
    other_role = next(t for t, role_sid in roles if role_sid == other)
    mode = 0

    for index in range(dacl.GetAceCount()):
        ace = _win_ace(dacl, index)
        if ace is None:
            continue
        ace_type, ace_flags, mask, sid = ace
        # Only plain allow ACEs count (deny and object ACEs aren't handled);
        # inherit-only ACEs apply to children, not this object.
        if (
            ace_type != win32security.ACCESS_ALLOWED_ACE_TYPE
            or ace_flags & ntsecuritycon.INHERIT_ONLY_ACE
        ):
            continue
        user_type = next((t for t, role_sid in roles if role_sid == sid), None)
        if user_type is None and sid in broader:
            user_type = other_role
        if user_type is not None:
            mode |= convert_win_to_stat(mask, user_type, object_type)

    return mode


def win_set_permissions(path: PathType, mode: int, other_sid: Any = None) -> None:
    """Set the file or dir permissions (of the target, if path is a link)."""
    path = _win_resolve(_fspath(path))

    _win_set_permissions(path, mode, get_object_type(path), other_sid)


def _win_set_permissions(path: str, mode: int, object_type: int, other_sid: Any = None) -> None:
    """Set the permissions."""
    sec_des = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT, _WIN_SECURITY_INFO
    )
    _win_update_sd(sec_des, mode, object_type, other_sid)
    # SetFileSecurity (unlike SetNamedSecurityInfo) does not re-propagate
    # inheritance to descendants, so children of a directory keep their ACEs.
    win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sec_des)


def _win_update_sd(sec_des: Any, mode: int, object_type: int, other_sid: Any = None) -> None:
    """Replace the DACL in sec_des (which has owner and group) to match mode."""
    # Read the effective DACL (including inherited ACEs), replace every ACE with
    # explicit ones, and mark it *protected*. Protection (SE_DACL_PROTECTED)
    # stops ACEs from the parent being inherited later, e.g. when someone changes
    # the parent folder's permissions. NO_INHERITANCE on each ACE only means it
    # does not propagate to this object's children.
    dacl = sec_des.GetSecurityDescriptorDacl()
    if dacl is None:
        dacl = win32security.ACL()
    system_sid = _win_system_sid()
    if other_sid is not None:
        _win_check_other_sid(
            [
                sec_des.GetSecurityDescriptorOwner(),
                sec_des.GetSecurityDescriptorGroup(),
                win_get_other_sid(other_sid),
            ],
            system_sid,
        )

    # Keep SYSTEM's access (plain allow ACEs only; never turn a deny into an allow).
    system_mask = 0
    for _ in range(dacl.GetAceCount()):
        ace = _win_ace(dacl, 0)
        if (
            ace is not None
            and ace[0] == win32security.ACCESS_ALLOWED_ACE_TYPE
            and not ace[1] & ntsecuritycon.INHERIT_ONLY_ACE
            and ace[3] == system_sid
        ):
            system_mask |= ace[2]
        dacl.DeleteAce(0)

    if system_mask:
        dacl.AddAccessAllowedAceEx(
            dacl.GetAclRevision(), win32security.NO_INHERITANCE, system_mask, system_sid
        )

    for user_type, sid in _win_roles(sec_des, other_sid):
        win_perm = convert_stat_to_win(mode, user_type, object_type)

        if win_perm > 0:
            dacl.AddAccessAllowedAceEx(
                dacl.GetAclRevision(), win32security.NO_INHERITANCE, win_perm, sid
            )

    sec_des.SetSecurityDescriptorDacl(1, dacl, 0)
    sec_des.SetSecurityDescriptorControl(
        win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED
    )


def _win_sid_display(sid: Any) -> Any:
    """Return the account for a SID, or the string SID if lookup fails (e.g., offline)."""
    try:
        return win32security.LookupAccountSid(None, sid)
    except pywinerror:
        return win32security.ConvertSidToStringSid(sid)


def print_win_inheritance(flags: int) -> None:
    """Display inheritance flags."""
    print("  -Flags:", hex(flags))
    if flags == win32security.NO_INHERITANCE:
        print("    ", "NO_INHERITANCE")
    else:
        for i in WIN_INHERITANCE_TYPES:
            if flags & getattr(win32security, i) == getattr(win32security, i):
                print("    ", i)


def print_mode_permissions(mode: int) -> None:
    """Print component permissions in a stat mode."""
    print("Mode:", oct(mode), f"(Decimal: {mode})")
    for i in STAT_KEYS:
        if mode & getattr(stat, i) == getattr(stat, i):
            print(f"  stat.{i}")


def print_win_ace_type(ace_type: int) -> None:
    """Print ACE type."""
    print("  -Type:")
    for i in WIN_ACE_TYPES:
        if getattr(ntsecuritycon, i) == ace_type:
            print("    ", i)


def print_win_permissions(win_perm: int, flags: int, object_type: int) -> None:
    """Print permissions from ACE information."""
    print("  -Permissions Mask:", hex(win_perm), f"({win_perm})")

    # files and directories do permissions differently
    permissions: tuple[str, ...]
    if object_type == FILE:
        permissions = WIN_FILE_PERMISSIONS
    else:
        permissions = WIN_DIR_PERMISSIONS
        # directories have ACE that is inherited by children within them
        inherit = ntsecuritycon.OBJECT_INHERIT_ACE | ntsecuritycon.INHERIT_ONLY_ACE
        if flags & inherit == inherit:
            permissions = WIN_DIR_INHERIT_PERMISSIONS

    calc_mask = 0  # see if we are printing all of the permissions
    for i in permissions:
        if getattr(ntsecuritycon, i) & win_perm == getattr(ntsecuritycon, i):
            calc_mask = calc_mask | getattr(ntsecuritycon, i)
            print("    ", i)
    print("  -Mask calculated from printed permissions:", hex(calc_mask))


def print_obj_info(path: PathType) -> None:
    """Print object security permission info."""
    path = _fspath(path)
    if not os.path.exists(path):
        print(path, "does not exist!")
        raise _not_found(path)

    object_type = get_object_type(path)

    print("----------------------------------------")
    if object_type == FILE:
        print("FILE:", path)
    else:
        print("DIRECTORY:", path)

    print_mode_permissions(get_mode(path))

    if IS_WINDOWS:
        print("Owner:", _win_sid_display(win_get_owner_sid(path)))
        print("Group:", _win_sid_display(win_get_group_sid(path)))
        _print_win_obj_info(path)
    else:
        print("Owner:", get_owner(path))
        print("Group:", get_group(path))


def _print_win_obj_info(path: str) -> None:
    """Print windows object security info."""
    # get ACEs
    sec_descriptor = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
    dacl = sec_descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        print("No Discretionary ACL")
        return

    for ace_no in range(dacl.GetAceCount()):
        print("ACE", ace_no)
        ace = _win_ace(dacl, ace_no)
        if ace is None:
            print("  (ACE type not supported by pywin32)")
            continue
        ace_type, ace_flags, mask, sid = ace

        print("  -SID:", _win_sid_display(sid))

        print_win_ace_type(ace_type)
        print_win_inheritance(ace_flags)
        print_win_permissions(mask, ace_flags, get_object_type(path))


def perm_test(mode: int = stat.S_IRUSR | stat.S_IWUSR) -> None:
    """Create test file and modify permissions."""
    path = "".join(random.choice(string.ascii_letters) for _ in range(10)) + ".txt"
    with open(path, "w+", encoding="utf-8") as file_hdl:
        file_hdl.write("new file")
    print("Created test file:", path)

    print("BEFORE Permissions:")
    print_obj_info(path)

    print("Setting permissions:")
    print_mode_permissions(mode)
    set_mode(path, mode)

    print("AFTER Permissions:")
    print_obj_info(path)
