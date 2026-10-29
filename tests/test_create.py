"""open_new() and mkdir(): create with final permissions, no window (#196)."""

import os
import sys
from pathlib import Path

import pytest

import oschmod

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes and umask")


@pytest.fixture
def umask():
    """Set a umask for the test and restore it afterwards."""
    old = os.umask(0o022)
    os.umask(old)

    def set_umask(value: int) -> None:
        os.umask(value)

    yield set_umask
    os.umask(old)


def test_open_new_writes_and_sets_mode(tmp_path):
    path = tmp_path / "secret.txt"
    with oschmod.open_new(path) as f:
        f.write("token")
    assert path.read_text() == "token"
    assert oschmod.get_mode(path) == 0o600


@pytest.mark.parametrize("perms", [0o600, "640", "u=rw,g=r"])
def test_open_new_perms_forms(tmp_path, perms):
    path = tmp_path / "f"
    with oschmod.open_new(path, perms=perms):
        pass
    assert oschmod.get_mode(path) == (0o600 if perms == 0o600 else 0o640)


@posix_only
@pytest.mark.parametrize("value", [0o000, 0o077, 0o777])
def test_open_new_ignores_umask(tmp_path, umask, value):
    umask(value)
    path = tmp_path / "f"
    with oschmod.open_new(path, perms=0o640):
        pass
    assert oschmod.get_full_mode(path) == 0o640


@posix_only
def test_open_new_never_more_open_than_perms(tmp_path, umask, monkeypatch):
    """The mode passed to os.open is a subset of perms, so there is no window."""
    umask(0o000)
    seen: list[int] = []
    real_open = os.open

    def spy(path, flags, mode=0o777, *args, **kwargs):
        seen.append(mode)
        return real_open(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(os, "open", spy)
    with oschmod.open_new(tmp_path / "f", perms=0o600):
        pass
    assert seen
    assert seen[0] & ~0o600 == 0


def test_open_new_refuses_existing(tmp_path):
    path = tmp_path / "f"
    path.write_text("keep")
    with pytest.raises(FileExistsError):
        oschmod.open_new(path)
    assert path.read_text() == "keep"


def test_open_new_refuses_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    link = tmp_path / "link"
    try:
        os.symlink(target, link)
    except OSError as exc:
        pytest.skip(f"cannot create symlinks: {exc}")
    with pytest.raises(FileExistsError):
        oschmod.open_new(link)
    assert not target.exists()  # the dangling link's target was not created


def test_open_new_binary_and_read(tmp_path):
    path = tmp_path / "f.bin"
    with oschmod.open_new(path, "wb+") as f:
        f.write(b"a\nb")
        f.seek(0)
        assert f.read() == b"a\nb"
    assert path.read_bytes() == b"a\nb"  # no newline translation


def test_open_new_text_newlines(tmp_path):
    path = tmp_path / "f.txt"
    with oschmod.open_new(path, "x", encoding="utf-8", newline="\n") as f:
        f.write("a\nb")
    assert path.read_bytes() == b"a\nb"


def test_open_new_append_mode(tmp_path):
    path = tmp_path / "log"
    with oschmod.open_new(path, "a") as f:
        f.write("one")
        f.seek(0)
        f.write("two")
    assert path.read_text() == "onetwo"


def test_open_new_with_read_only_perms_can_still_write(tmp_path):
    """The creating handle has write access even if perms don't grant it."""
    path = tmp_path / "ro"
    with oschmod.open_new(path, perms=0o400) as f:
        f.write("x")
    assert path.read_text() == "x"
    assert oschmod.get_mode(path) == 0o400
    oschmod.set_mode(path, 0o600)  # owner can still change it


@pytest.mark.parametrize("bad", ["r", "r+", "rb", "w+x", "wa", "", "wbt"])
def test_open_new_rejects_modes(tmp_path, bad):
    with pytest.raises(ValueError, match="invalid mode"):
        oschmod.open_new(tmp_path / "f", bad)
    assert not (tmp_path / "f").exists()


def test_open_new_rejects_bad_perms(tmp_path):
    with pytest.raises(oschmod.ModeError):
        oschmod.open_new(tmp_path / "f", perms="u+q")
    assert not (tmp_path / "f").exists()


def test_open_new_accepts_pathlike(tmp_path):
    with oschmod.open_new(Path(tmp_path) / "p") as f:
        f.write("x")


def test_mkdir(tmp_path):
    path = tmp_path / "private"
    oschmod.mkdir(path)
    assert path.is_dir()
    assert oschmod.get_mode(path) == 0o700
    with pytest.raises(FileExistsError):
        oschmod.mkdir(path)


@posix_only
def test_mkdir_ignores_umask_and_sets_special_bits(tmp_path, umask):
    umask(0o077)
    path = tmp_path / "shared"
    oschmod.mkdir(path, 0o2750)
    assert oschmod.get_full_mode(path) == 0o2750


@posix_only
def test_open_new_sets_special_bits(tmp_path):
    path = tmp_path / "f"
    with oschmod.open_new(path, perms=0o4700):
        pass
    assert oschmod.get_full_mode(path) == 0o4700


def test_mkdir_refuses_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    link = tmp_path / "link"
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"cannot create symlinks: {exc}")
    with pytest.raises(FileExistsError):
        oschmod.mkdir(link)
    assert not target.exists()
