"""Windows: how ACEs map to owner/group/other bits (#184, #185, #189).

Each test writes an exact, protected DACL first, so results don't depend on
what the CI runner's temp directory inherits.
"""

import os
import sys
from pathlib import Path

import pytest

import oschmod

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows ACL behavior")

if sys.platform == "win32":
    import ntsecuritycon as con
    import win32security as sec

EVERYONE = "S-1-1-0"
AUTHENTICATED_USERS = "S-1-5-11"
BACKUP_OPERATORS = "S-1-5-32-551"  # a local group that is never owner, group, or Users

FULL = 0x1F01FF  # FILE_ALL_ACCESS
MODIFY = 0x1301BF  # Explorer's "Modify": read, write, execute, delete


def _sid(s: str):
    return sec.ConvertStringSidToSid(s)


def _str(sid) -> str:
    return sec.ConvertSidToStringSid(sid)


def _owner(path: Path) -> str:
    return _str(oschmod.win_get_owner_sid(path))


def _group(path: Path) -> str:
    return _str(oschmod.win_get_group_sid(path))


def _set_dacl(path: Path, aces: list[tuple[str, int]], *, flags: int = 0, group: str | None = None):
    """Replace path's DACL with exactly these allow ACEs, protected from inheritance."""
    sd = sec.GetFileSecurity(str(path), sec.DACL_SECURITY_INFORMATION)
    dacl = sec.ACL()
    for sid, mask in aces:
        dacl.AddAccessAllowedAceEx(sec.ACL_REVISION_DS, flags, mask, _sid(sid))
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    sd.SetSecurityDescriptorControl(sec.SE_DACL_PROTECTED, sec.SE_DACL_PROTECTED)
    info = sec.DACL_SECURITY_INFORMATION
    if group is not None:
        sd.SetSecurityDescriptorGroup(_sid(group), 0)
        info |= sec.GROUP_SECURITY_INFORMATION
    sec.SetFileSecurity(str(path), info, sd)


def _aces(path: Path) -> dict[str, int]:
    """SID -> combined allow mask."""
    sd = sec.GetFileSecurity(str(path), sec.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    result: dict[str, int] = {}
    for i in range(dacl.GetAceCount()):
        (ace_type, _), mask, sid = dacl.GetAce(i)
        if ace_type == sec.ACCESS_ALLOWED_ACE_TYPE:
            result[_str(sid)] = result.get(_str(sid), 0) | mask
    return result


@pytest.fixture
def private_file(tmp_path: Path) -> Path:
    """A file only its owner and an unrelated group (Backup Operators) can use."""
    path = tmp_path / "private.txt"
    path.write_text("x")
    _set_dacl(path, [(_owner(path), FULL), (BACKUP_OPERATORS, FULL)])
    return path


# --- #185: which ACEs count as "other" ----------------------------------------


def test_unrelated_account_is_not_other(private_file):
    assert oschmod.get_mode(private_file) == 0o700


def test_symbolic_change_does_not_grant_users(private_file):
    oschmod.set_mode(private_file, "u-x")
    assert oschmod.USERS_SID not in _aces(private_file)
    assert oschmod.get_mode(private_file) == 0o600


def test_everyone_and_authenticated_users_count_as_other(tmp_path):
    for sid in (EVERYONE, AUTHENTICATED_USERS):
        path = tmp_path / f"{sid}.txt"
        path.write_text("x")
        _set_dacl(path, [(_owner(path), FULL), (sid, con.FILE_GENERIC_READ)])
        assert oschmod.get_mode(path) == 0o704, sid


def test_explicit_other_sid_is_read_as_other(private_file):
    assert oschmod.get_mode(private_file, other_sid=BACKUP_OPERATORS) == 0o707
    oschmod.set_mode(private_file, "o-wx", other_sid=BACKUP_OPERATORS)
    assert oschmod.get_mode(private_file, other_sid=BACKUP_OPERATORS) == 0o704


def test_inherit_only_aces_are_ignored(tmp_path):
    directory = tmp_path / "d"
    directory.mkdir()
    _set_dacl(directory, [(_owner(directory), FULL)])
    sd = sec.GetFileSecurity(str(directory), sec.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    dacl.AddAccessAllowedAceEx(
        sec.ACL_REVISION_DS,
        con.OBJECT_INHERIT_ACE | con.CONTAINER_INHERIT_ACE | con.INHERIT_ONLY_ACE,
        FULL,
        _sid(oschmod.USERS_SID),
    )
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    sec.SetFileSecurity(str(directory), sec.DACL_SECURITY_INFORMATION, sd)
    assert oschmod.get_mode(directory) == 0o700


# --- #184: "w" must not grant control of the ACL or ownership ------------------


@pytest.mark.parametrize("kind", ["file", "dir"])
def test_write_does_not_grant_write_dac_or_owner(tmp_path, kind):
    path = tmp_path / kind
    if kind == "file":
        path.write_text("x")
    else:
        path.mkdir()
    oschmod.set_mode(path, 0o777)
    for sid, mask in _aces(path).items():
        if sid != oschmod.SYSTEM_SID:
            assert not mask & con.WRITE_DAC, sid
            assert not mask & con.WRITE_OWNER, sid
    if kind == "file":
        assert not _aces(path)[oschmod.USERS_SID] & con.FILE_DELETE_CHILD
    assert oschmod.get_mode(path) == 0o777


def test_modify_permission_reads_as_rwx(tmp_path):
    path = tmp_path / "f.txt"
    path.write_text("x")
    _set_dacl(path, [(_owner(path), MODIFY)])
    assert oschmod.get_mode(path) == 0o700


def test_old_style_full_control_still_reads_as_rwx(tmp_path):
    """ACEs written by oschmod <= 0.4.0 (with WRITE_DAC/WRITE_OWNER) still read the same."""
    path = tmp_path / "f.txt"
    path.write_text("x")
    _set_dacl(path, [(_owner(path), FULL), (oschmod.USERS_SID, FULL)])
    assert oschmod.get_mode(path) == 0o707


def test_owner_can_still_change_mode_after_000(tmp_path):
    """The owner's implicit READ_CONTROL/WRITE_DAC is enough to recover."""
    path = tmp_path / "f.txt"
    path.write_text("x")
    oschmod.set_mode(path, 0o000)
    oschmod.set_mode(path, 0o600)
    assert oschmod.get_mode(path) == 0o600


# --- #189: one SID in two roles --------------------------------------------------


def test_owner_equal_to_group_keeps_owner_bits(tmp_path):
    path = tmp_path / "f.txt"
    path.write_text("x")
    _set_dacl(path, [(_owner(path), FULL)], group=_owner(path))
    assert _group(path) == _owner(path)
    oschmod.set_mode(path, 0o640)
    # Group bits can't be stored separately for the owner's SID; owner bits are exact.
    assert oschmod.get_mode(path) == 0o600
    oschmod.set_mode(path, 0o060)
    assert oschmod.get_mode(path) == 0o000


def test_group_equal_to_users_uses_group_bits(tmp_path):
    """With group = Users, Users get group bits (POSIX: group, not other, applies)."""
    path = tmp_path / "f.txt"
    path.write_text("x")
    _set_dacl(path, [(_owner(path), FULL)], group=oschmod.USERS_SID)
    oschmod.set_mode(path, 0o604)
    assert oschmod.get_mode(path) == 0o600
    oschmod.set_mode(path, 0o640)
    assert oschmod.get_mode(path) == 0o640


# --- Review fixes on #203 ------------------------------------------------------


def test_object_ace_is_skipped(private_file):
    """Object ACEs unpack to five fields; they must be skipped, not crash reads."""
    import pywintypes  # noqa: PLC0415

    sd = sec.GetFileSecurity(str(private_file), sec.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    dacl.AddAccessAllowedObjectAce(
        sec.ACL_REVISION_DS,
        0,
        FULL,
        pywintypes.IID("{00000000-0000-0000-0000-000000000001}"),
        None,
        _sid(oschmod.USERS_SID),
    )
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    sec.SetFileSecurity(str(private_file), sec.DACL_SECURITY_INFORMATION, sd)

    assert oschmod.get_mode(private_file) == 0o700
    oschmod.set_mode(private_file, "u-x")  # symbolic: reads, then rewrites the DACL
    assert oschmod.get_mode(private_file) == 0o600
    assert oschmod.USERS_SID not in _aces(private_file)


def test_unsupported_ace_type_is_skipped():
    """pywin32 raises NotImplementedError for some ACE types (e.g., callback ACEs)."""

    class UnsupportedAcl:
        def GetAce(self, index):  # pywin32 API name
            raise NotImplementedError("Ace type 9 is not supported yet")

    assert oschmod._win_ace(UnsupportedAcl(), 0) is None


def test_authenticated_users_is_not_other_when_other_is_everyone(tmp_path):
    """Authenticated Users doesn't include Guest, so it isn't "other" for Everyone."""
    path = tmp_path / "f.txt"
    path.write_text("x")
    _set_dacl(path, [(_owner(path), FULL), (AUTHENTICATED_USERS, con.FILE_GENERIC_READ)])
    assert oschmod.get_mode(path, other_sid=EVERYONE) == 0o700
    oschmod.set_mode(path, "u-x", other_sid=EVERYONE)
    assert EVERYONE not in _aces(path)


def test_everyone_is_other_for_any_other_sid(tmp_path):
    path = tmp_path / "f.txt"
    path.write_text("x")
    _set_dacl(path, [(_owner(path), FULL), (EVERYONE, con.FILE_GENERIC_READ)])
    assert oschmod.get_mode(path, other_sid=AUTHENTICATED_USERS) == 0o704
    assert oschmod.get_mode(path, other_sid=BACKUP_OPERATORS) == 0o704


def test_system_deny_ace_is_not_turned_into_allow(private_file):
    sd = sec.GetFileSecurity(str(private_file), sec.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    dacl.AddAccessDeniedAceEx(
        sec.ACL_REVISION_DS, 0, con.FILE_GENERIC_WRITE, _sid(oschmod.SYSTEM_SID)
    )
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    sec.SetFileSecurity(str(private_file), sec.DACL_SECURITY_INFORMATION, sd)
    oschmod.set_mode(private_file, 0o600)
    assert oschmod.SYSTEM_SID not in _aces(private_file)


def test_broader_group_access_follows_users_when_users_is_group(tmp_path):
    """With group = Users, Everyone's access is Users' access, so it reads as group bits.

    Before, it read as "o" bits, which aren't stored when Users is the group, so
    an owner-only change like u-x removed Users' read access.
    """
    path = tmp_path / "f.txt"
    path.write_text("x")
    _set_dacl(
        path,
        [(_owner(path), FULL), (EVERYONE, con.FILE_GENERIC_READ)],
        group=oschmod.USERS_SID,
    )
    assert oschmod.get_mode(path) == 0o740
    oschmod.set_mode(path, "u-x")
    assert _aces(path)[oschmod.USERS_SID] & con.FILE_GENERIC_READ == con.FILE_GENERIC_READ
    assert oschmod.get_mode(path) == 0o640


# --- open_new / mkdir (#196) -------------------------------------------------------


def _protected(path: Path) -> bool:
    sd = sec.GetFileSecurity(str(path), sec.DACL_SECURITY_INFORMATION)
    control, _ = sd.GetSecurityDescriptorControl()
    return bool(control & sec.SE_DACL_PROTECTED)


def test_open_new_creates_protected_owner_only_dacl(tmp_path):
    path = tmp_path / "secret.txt"
    with oschmod.open_new(path) as f:
        f.write("token")
    assert _protected(path)
    assert set(_aces(path)) == {_owner(path)}  # nothing inherited from tmp_path
    assert oschmod.get_mode(path) == 0o600


def test_open_new_other_sid(tmp_path):
    path = tmp_path / "f.txt"
    with oschmod.open_new(path, perms=0o604, other_sid=AUTHENTICATED_USERS):
        pass
    assert AUTHENTICATED_USERS in _aces(path)
    assert oschmod.USERS_SID not in _aces(path)
    assert oschmod.get_mode(path, other_sid=AUTHENTICATED_USERS) == 0o604


def test_open_new_handle_is_not_inheritable(tmp_path):
    with oschmod.open_new(tmp_path / "f") as f:
        assert not os.get_inheritable(f.fileno())


def test_mkdir_creates_protected_dacl(tmp_path):
    path = tmp_path / "private"
    oschmod.mkdir(path, 0o700)
    assert _protected(path)
    assert set(_aces(path)) == {_owner(path)}
    assert oschmod.get_mode(path) == 0o700
