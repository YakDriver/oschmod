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

import os
import platform
import random
import re
import stat
import string
from collections.abc import Iterator
from typing import Any, Final

__version__ = "0.4.0"

PathType = str | os.PathLike[str]
"""Accepted path input: a string or any path-like object."""

ModeType = int | str
"""Accepted mode input: an int (e.g., 0o755), octal string ("755"), or symbolic ("u+x")."""

IS_WINDOWS: Final = platform.system() == "Windows"
HAS_PYWIN32 = False
try:
    import ntsecuritycon
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
    W_DIRWR = (
        W_FADFL
        | W_FADSD
        | W_FWREA
        | W_FDLCH
        | W_FWRAT
        | W_DELET
        | W_RDCON
        | W_WRDAC
        | W_WROWN
        | W_SYNCH
    )
    W_DIREX = W_FTRAV | W_RDCON | W_SYNCH

    W_FILRD = W_FGNRD
    W_FILWR = W_FDLCH | W_DELET | W_WRDAC | W_WROWN | W_FGNWR
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


def get_mode(path: PathType) -> int:
    """Get bitwise mode (stat) of object (dir or file)."""
    path = _fspath(path)
    if IS_WINDOWS:
        return win_get_permissions(path)
    return os.stat(path).st_mode & _PERM_MASK


def get_full_mode(path: PathType) -> int:
    """Get mode including set-user-ID, set-group-ID, and sticky bits (up to 0o7777).

    Same as :func:`get_mode` on Windows, which has no equivalent of these bits.
    """
    path = _fspath(path)
    if IS_WINDOWS:
        return win_get_permissions(path)
    return os.stat(path).st_mode & _FULL_MASK


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
    new_mode = _resolve_mode(path, mode)

    if IS_WINDOWS:
        win_set_permissions(path, new_mode, other_sid)
        return
    os.chmod(path, new_mode)


def _resolve_mode(path: str, mode: ModeType) -> int:
    """Convert int, octal-string, or symbolic mode into an int mode for path."""
    if isinstance(mode, bool) or not isinstance(mode, int | str):
        raise TypeError(f"mode must be int or str, not {type(mode).__name__}")
    if isinstance(mode, str):
        if "+" in mode or "-" in mode or "=" in mode:
            # Symbolic modifiers change only rwx bits; keep any special bits as-is
            # instead of silently clearing them.
            current = get_full_mode(path)
            return get_effective_mode(current & _PERM_MASK, mode) | (current & _SPECIAL_MASK)
        mode = int(mode, 8)
    if not 0 <= mode <= 0o7777:
        raise ValueError(f"mode {mode:#o} is out of range (0 to 0o7777)")
    return mode


def _iter_tree(path: str) -> Iterator[tuple[str, int]]:
    """Yield (path, object type) for everything under path, bottom-up, path last."""
    for root, dirs, files in os.walk(path, topdown=False):
        for one_file in files:
            yield os.path.join(root, one_file), FILE
        for one_dir in dirs:
            yield os.path.join(root, one_dir), DIRECTORY
    yield path, DIRECTORY


def set_mode_recursive(
    path: PathType,
    mode: ModeType,
    dir_mode: ModeType | None = None,
    other_sid: Any = None,
) -> None:
    r"""Set all file and directory permissions at or under path to modes.

    Args:
    path: (:obj:`str` or :obj:`os.PathLike`)
        Object which will have its mode set. If path is a file, only its mode
        is set - no recursion occurs. If path is a directory, its mode and the
        mode of all files and subdirectories below it are set.

    mode: (`int` or `str`)
        Mode to be applied to object(s).

    dir_mode: (`int` or `str`)
        If provided, this mode is given to all directories only.

    other_sid:
        Windows only. See :func:`set_mode`.

    """
    path = _fspath(path)
    if get_object_type(path) == FILE:
        set_mode(path, mode, other_sid)
        return

    if dir_mode is None:
        dir_mode = mode

    for obj, obj_type in _iter_tree(path):
        set_mode(obj, mode if obj_type == FILE else dir_mode, other_sid)


def _get_effective_mode_multiple(current_mode: int, modes: str) -> int:
    """Get octal mode, given current mode and symbolic mode modifiers."""
    new_mode = current_mode
    for mode in modes.split(","):
        new_mode = get_effective_mode(new_mode, mode)
    return new_mode


def get_effective_mode(current_mode: int, symbolic: str) -> int:
    """Get octal mode, given current mode and symbolic mode modifier."""
    if not isinstance(symbolic, str):
        raise AttributeError("symbolic must be a string")

    if "," in symbolic:
        return _get_effective_mode_multiple(current_mode, symbolic)

    result = re.search(r"^\s*([ugoa]*)([-+=])([rwx]*)\s*$", symbolic)
    if result is None:
        raise AttributeError("bad format of symbolic representation modifier")

    whom = result.group(1) or "ugo"
    operation = result.group(2)
    perm = result.group(3)

    if "a" in whom:
        whom = "ugo"

    # bitwise magic
    bit_perm = _get_basic_symbol_to_mode(perm)
    mask_mode = (
        (bit_perm << 6 if "u" in whom else 0)
        | (bit_perm << 3 if "g" in whom else 0)
        | (bit_perm if "o" in whom else 0)
    )

    if operation == "=":
        original = (
            (current_mode & 0o700 if "u" not in whom else 0)
            | (current_mode & 0o070 if "g" not in whom else 0)
            | (current_mode & 0o007 if "o" not in whom else 0)
        )
        return mask_mode | original

    if operation == "+":
        return current_mode | mask_mode

    return current_mode & ~mask_mode


def mode_to_symbolic(mode: int) -> str:
    """Return the ``ls``-style permission string, e.g. ``0o4755`` -> ``"rwsr-xr-x"``.

    Set-user-ID, set-group-ID, and sticky bits are shown as ``s``/``S`` and ``t``/``T``.
    """
    return stat.filemode(mode & _FULL_MASK)[1:]


def get_object_type(path: PathType) -> int:
    """Get whether object is file or directory."""
    return FILE if os.path.isfile(path) else DIRECTORY


def get_owner(path: PathType) -> Any:
    """Get the object owner."""
    path = _fspath(path)
    if IS_WINDOWS:
        return win32security.LookupAccountSid(None, win_get_owner_sid(path))
    return pwd.getpwuid(os.stat(path).st_uid).pw_name


def get_group(path: PathType) -> Any:
    """Get the object group."""
    path = _fspath(path)
    if IS_WINDOWS:
        return win32security.LookupAccountSid(None, win_get_group_sid(path))
    return grp.getgrgid(os.stat(path).st_gid).gr_name


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
            raise ValueError(
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
    """Given object and SIDs, return user type."""
    if sid == sids[OWNER]:
        return OWNER

    if sid == sids[GROUP]:
        return GROUP

    return OTHER


def win_get_object_sids(path: PathType, other_sid: Any = None) -> list[Any]:
    """Get the owner, group, other SIDs for an object."""
    return [win_get_owner_sid(path), win_get_group_sid(path), win_get_other_sid(other_sid)]


def win_get_permissions(path: PathType) -> int:
    """Get the file or dir permissions."""
    path = _fspath(path)
    if not os.path.exists(path):
        raise _not_found(path)

    return _win_get_permissions(path, get_object_type(path))


def _get_basic_symbol_to_mode(symbol: str) -> int:
    """Calculate numeric value of set of 'rwx'."""
    return (4 if "r" in symbol else 0) | (2 if "w" in symbol else 0) | (1 if "x" in symbol else 0)


def _win_get_permissions(path: str, object_type: int) -> int:
    """Get the permissions."""
    sec_des = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
    )
    dacl = sec_des.GetSecurityDescriptorDacl()

    sids = win_get_object_sids(path)
    system_sid = _win_system_sid()
    mode = 0

    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        # Not handling win32security.ACCESS_DENIED_ACE_TYPE
        if ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE and ace[2] != system_sid:
            mode = mode | convert_win_to_stat(ace[1], win_get_user_type(ace[2], sids), object_type)

    return mode


def win_set_permissions(path: PathType, mode: int, other_sid: Any = None) -> None:
    """Set the file or dir permissions."""
    path = _fspath(path)
    if not os.path.exists(path):
        raise _not_found(path)

    _win_set_permissions(path, mode, get_object_type(path), other_sid)


def _win_set_permissions(path: str, mode: int, object_type: int, other_sid: Any = None) -> None:
    """Set the permissions."""
    # Read the effective DACL (including inherited ACEs), replace every ACE with
    # explicit ones, and write it back as a *protected* DACL. Protection
    # (SE_DACL_PROTECTED) stops ACEs from the parent being inherited later, e.g.
    # when someone changes the parent folder's permissions. NO_INHERITANCE on
    # each ACE only means it does not propagate to this object's children.
    sec_des = win32security.GetNamedSecurityInfo(
        path, win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
    )
    dacl = sec_des.GetSecurityDescriptorDacl()
    system_sid = _win_system_sid()
    sids = win_get_object_sids(path, other_sid)
    if other_sid is not None:
        _win_check_other_sid(sids, system_sid)

    system_ace = None
    for _ in range(dacl.GetAceCount()):
        ace = dacl.GetAce(0)
        if ace[2] == system_sid:
            system_ace = ace
        dacl.DeleteAce(0)

    if system_ace:
        dacl.AddAccessAllowedAceEx(
            dacl.GetAclRevision(), win32security.NO_INHERITANCE, system_ace[1], system_ace[2]
        )

    for user_type, sid in enumerate(sids):
        win_perm = convert_stat_to_win(mode, user_type, object_type)

        if win_perm > 0:
            dacl.AddAccessAllowedAceEx(
                dacl.GetAclRevision(), win32security.NO_INHERITANCE, win_perm, sid
            )

    # SetFileSecurity (unlike SetNamedSecurityInfo) does not re-propagate
    # inheritance to descendants, so children of a directory keep their ACEs.
    sec_des.SetSecurityDescriptorDacl(1, dacl, 0)
    sec_des.SetSecurityDescriptorControl(
        win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED
    )
    win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sec_des)


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
        ace = dacl.GetAce(ace_no)
        print("ACE", ace_no)

        print("  -SID:", _win_sid_display(ace[2]))

        print_win_ace_type(ace[0][0])
        print_win_inheritance(ace[0][1])
        print_win_permissions(ace[1], ace[0][1], get_object_type(path))


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
