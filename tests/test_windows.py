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
