"""Windows-only tests for ACL handling."""

import sys
from pathlib import Path

import pytest

import oschmod

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows ACL behavior")


@pytest.fixture
def file_path(tmp_path: Path) -> Path:
    path = tmp_path / "file.txt"
    path.write_text("x")
    return path


def _ace_sids(path: Path) -> list[str]:
    import win32security  # noqa: PLC0415

    sec = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
    dacl = sec.GetSecurityDescriptorDacl()
    return [
        win32security.ConvertSidToStringSid(dacl.GetAce(i)[2]) for i in range(dacl.GetAceCount())
    ]


def test_offline_domain_lookup_does_not_break_get_set(file_path, monkeypatch):
    """Issue #73: LookupAccountSid fails when a domain controller is unreachable."""
    import pywintypes  # noqa: PLC0415
    import win32security  # noqa: PLC0415

    def offline(*_args, **_kwargs):
        raise pywintypes.error(
            1789,
            "LookupAccountSid",
            "The trust relationship between this workstation and the primary domain failed.",
        )

    monkeypatch.setattr(win32security, "LookupAccountSid", offline)

    oschmod.set_mode(file_path, 0o640)
    assert oschmod.get_mode(file_path) == 0o640
    oschmod.set_mode(file_path, "u+x")
    assert oschmod.get_mode(file_path) == 0o740
    oschmod.print_obj_info(file_path)  # falls back to string SIDs


def test_other_sid(file_path):
    """Issue #8: "other" permissions can target a SID other than Users."""
    authenticated_users = "S-1-5-11"
    oschmod.set_mode(file_path, 0o604, other_sid=authenticated_users)
    sids = _ace_sids(file_path)
    assert authenticated_users in sids
    assert oschmod.USERS_SID not in sids
    assert oschmod.get_mode(file_path) == 0o604


def test_default_other_sid_is_users(file_path):
    oschmod.set_mode(file_path, 0o604)
    assert oschmod.USERS_SID in _ace_sids(file_path)


@pytest.mark.parametrize("which", ["owner", "group", "system"])
def test_other_sid_collision_rejected(file_path, which):
    import win32security  # noqa: PLC0415

    oschmod.set_mode(file_path, 0o644)
    before = _ace_sids(file_path)
    sid = {
        "owner": lambda: win32security.ConvertSidToStringSid(oschmod.win_get_owner_sid(file_path)),
        "group": lambda: win32security.ConvertSidToStringSid(oschmod.win_get_group_sid(file_path)),
        "system": lambda: oschmod.SYSTEM_SID,
    }[which]()
    with pytest.raises(ValueError, match=which if which != "system" else "SYSTEM"):
        oschmod.set_mode(file_path, 0o604, other_sid=sid)
    assert _ace_sids(file_path) == before  # DACL untouched


def test_dacl_is_protected_from_parent_changes(tmp_path):
    """After set_mode, ACEs added to the parent later must not be inherited."""
    import ntsecuritycon  # noqa: PLC0415
    import win32security  # noqa: PLC0415

    parent = tmp_path / "parent"
    parent.mkdir()
    child = parent / "child.txt"
    child.write_text("x")
    oschmod.set_mode(child, 0o600)

    sec = win32security.GetFileSecurity(str(child), win32security.DACL_SECURITY_INFORMATION)
    control, _ = sec.GetSecurityDescriptorControl()
    assert control & win32security.SE_DACL_PROTECTED

    # Grant Authenticated Users read on the parent, inheritable by files.
    auth_users = "S-1-5-11"
    parent_sec = win32security.GetNamedSecurityInfo(
        str(parent), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
    )
    dacl = parent_sec.GetSecurityDescriptorDacl()
    dacl.AddAccessAllowedAceEx(
        dacl.GetAclRevision(),
        ntsecuritycon.OBJECT_INHERIT_ACE | ntsecuritycon.CONTAINER_INHERIT_ACE,
        ntsecuritycon.FILE_GENERIC_READ,
        win32security.ConvertStringSidToSid(auth_users),
    )
    win32security.SetNamedSecurityInfo(
        str(parent),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )

    assert auth_users not in _ace_sids(child)
    assert oschmod.get_mode(child) == 0o600


def test_unprotected_file_does_inherit(tmp_path):
    """Control for the test above: without oschmod, the parent ACE propagates."""
    import ntsecuritycon  # noqa: PLC0415
    import win32security  # noqa: PLC0415

    parent = tmp_path / "parent"
    parent.mkdir()
    child = parent / "child.txt"
    child.write_text("x")
    auth_users = "S-1-5-11"
    parent_sec = win32security.GetNamedSecurityInfo(
        str(parent), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
    )
    dacl = parent_sec.GetSecurityDescriptorDacl()
    dacl.AddAccessAllowedAceEx(
        dacl.GetAclRevision(),
        ntsecuritycon.OBJECT_INHERIT_ACE | ntsecuritycon.CONTAINER_INHERIT_ACE,
        ntsecuritycon.FILE_GENERIC_READ,
        win32security.ConvertStringSidToSid(auth_users),
    )
    win32security.SetNamedSecurityInfo(
        str(parent),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )
    assert auth_users in _ace_sids(child)


def test_set_mode_on_dir_keeps_descendants_accessible(tmp_path):
    """Protecting a directory's DACL must not strip inherited ACEs from children."""
    top = tmp_path / "top"
    deep = top / "a" / "b"
    deep.mkdir(parents=True)
    before = _ace_sids(deep)
    oschmod.set_mode(top, 0o700)
    assert deep.exists()
    assert _ace_sids(deep) == before
