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


def test_recursive_skips_junctions(tmp_path):
    """Junctions are reparse points, not symlinks, but must be skipped too (#183)."""
    import _winapi  # noqa: PLC0415

    target = tmp_path / "target"
    target.mkdir()
    (target / "inner.txt").write_text("x")
    oschmod.set_mode(target / "inner.txt", 0o600)
    tree = tmp_path / "tree"
    tree.mkdir()
    _winapi.CreateJunction(str(target), str(tree / "junction"))

    oschmod.set_mode_recursive(tree, 0o644, 0o755)
    assert oschmod.get_mode(target / "inner.txt") == 0o600

    oschmod.set_mode_recursive(tree, 0o644, 0o755, follow_symlinks=True)
    assert oschmod.get_mode(target / "inner.txt") == 0o644


def test_set_mode_follows_symlink_like_posix(tmp_path):
    """set_mode/get_mode on a link act on the target, as os.chmod does on POSIX."""
    import os  # noqa: PLC0415

    target = tmp_path / "target.txt"
    target.write_text("x")
    link = tmp_path / "link.txt"
    try:
        os.symlink(target, link)
    except OSError as exc:
        pytest.skip(f"cannot create symlinks: {exc}")
    oschmod.set_mode(target, 0o600)
    oschmod.set_mode(link, 0o644)
    assert oschmod.get_mode(target) == 0o644
    assert oschmod.get_mode(link) == 0o644


def test_sid_conflict_is_reported_per_object(tmp_path):
    """SidConflictError depends on each object's owner, so -R reports and continues."""
    import win32security  # noqa: PLC0415

    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "f.txt").write_text("x")
    owner = win32security.ConvertSidToStringSid(oschmod.win_get_owner_sid(tree))
    errors: list[Exception] = []
    oschmod.set_mode_recursive(tree, 0o604, other_sid=owner, on_error=lambda _, e: errors.append(e))
    assert len(errors) == 3
    assert all(isinstance(e, oschmod.SidConflictError) for e in errors)
    assert all(isinstance(e, ValueError) for e in errors)  # backward compatible


def test_recursive_writes_protected_dacl(tmp_path):
    """The handle-based walk (SetKernelObjectSecurity) still protects each DACL."""
    import win32security  # noqa: PLC0415

    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "f.txt").write_text("x")
    oschmod.set_mode_recursive(tree, 0o640, 0o750)
    for obj, mode in ((tree / "sub" / "f.txt", 0o640), (tree / "sub", 0o750), (tree, 0o750)):
        assert oschmod.get_mode(obj) == mode
        sec = win32security.GetFileSecurity(str(obj), win32security.DACL_SECURITY_INFORMATION)
        control, _ = sec.GetSecurityDescriptorControl()
        assert control & win32security.SE_DACL_PROTECTED


def test_get_owner_and_group_offline(file_path, monkeypatch):
    """Issue #190: fall back to the string SID when LookupAccountSid fails."""
    import pywintypes  # noqa: PLC0415
    import win32security  # noqa: PLC0415

    owner_sid = win32security.ConvertSidToStringSid(oschmod.win_get_owner_sid(file_path))
    group_sid = win32security.ConvertSidToStringSid(oschmod.win_get_group_sid(file_path))
    name, _domain, _type = oschmod.get_owner(file_path)  # online result is a 3-tuple
    assert name

    def offline(*_args, **_kwargs):
        raise pywintypes.error(1789, "LookupAccountSid", "The trust relationship failed.")

    monkeypatch.setattr(win32security, "LookupAccountSid", offline)
    assert oschmod.get_owner(file_path) == (owner_sid, "", win32security.SidTypeUnknown)
    assert oschmod.get_group(file_path) == (group_sid, "", win32security.SidTypeUnknown)
