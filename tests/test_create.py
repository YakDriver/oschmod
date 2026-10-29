"""open_new() and mkdir(): create with final permissions, no window (#196)."""

import builtins
import contextlib
import errno
import os
import sys
from pathlib import Path

import pytest

import oschmod


def _open_and_close(*args, **kwargs) -> None:
    """Call open_new() where it should raise, closing the file if it doesn't."""
    with oschmod.open_new(*args, **kwargs):
        pass


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

    def spy(path, flags, mode=0o600, *args, **kwargs):
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
        _open_and_close(path)
    assert path.read_text() == "keep"


def test_open_new_refuses_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    link = tmp_path / "link"
    try:
        os.symlink(target, link)
    except OSError as exc:
        pytest.skip(f"cannot create symlinks: {exc}")
    with pytest.raises(FileExistsError):
        _open_and_close(link)
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
        _open_and_close(tmp_path / "f", bad)
    assert not (tmp_path / "f").exists()


def test_open_new_rejects_bad_perms(tmp_path):
    with pytest.raises(oschmod.ModeError):
        _open_and_close(tmp_path / "f", perms="u+q")
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


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"buffering": 0}, ValueError),
        ({"encoding": "no-such-codec"}, LookupError),
        ({"newline": "bad"}, ValueError),
    ],
)
def test_open_new_bad_text_args_create_nothing(tmp_path, kwargs, error):
    """Errors are the same as open()'s, and no file is created or left behind."""
    path = tmp_path / "f"
    with pytest.raises(error):
        _open_and_close(path, "w", **kwargs)
    assert not path.exists()


def test_open_new_binary_rejects_text_args(tmp_path):
    path = tmp_path / "f"
    with pytest.raises(ValueError, match="encoding"):
        _open_and_close(path, "wb", encoding="utf-8")
    with pytest.raises(ValueError, match="errors"):
        _open_and_close(path, "wb", errors="strict")
    with pytest.raises(ValueError, match="newline"):
        _open_and_close(path, "wb", newline="\n")
    assert not path.exists()


def test_open_new_unbuffered_binary(tmp_path):
    path = tmp_path / "f"
    with oschmod.open_new(path, "wb", buffering=0) as f:
        f.write(b"x")
    assert path.read_bytes() == b"x"


def test_open_new_existing_file_is_not_removed(tmp_path):
    path = tmp_path / "f"
    path.write_text("keep")
    with pytest.raises(FileExistsError):
        _open_and_close(path, "a")
    assert path.read_text() == "keep"


@posix_only
@pytest.mark.parametrize(("perms", "mask"), [(0o300, 0o022), (0o700, 0o777), (0o000, 0o022)])
def test_mkdir_without_read_permission(tmp_path, umask, perms, mask):
    """The final mode is set without opening the new directory, which may be unreadable."""
    umask(mask)
    path = tmp_path / "d"
    try:
        oschmod.mkdir(path, perms)
        assert oschmod.get_full_mode(path) == perms
    finally:
        if path.exists():
            path.chmod(0o700)


def test_mkdir_relative_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    oschmod.mkdir("rel", 0o750)
    assert oschmod.get_mode(tmp_path / "rel") == 0o750


def test_open_new_failure_after_check_keeps_existing_file(tmp_path):
    """An error from open() before anything is created never removes an existing file."""
    path = tmp_path / "f"
    path.write_text("keep")
    with pytest.raises((OverflowError, FileExistsError)):
        _open_and_close(path, buffering=2**100)
    assert path.read_text() == "keep"


def test_open_new_failure_after_create_removes_only_its_file(tmp_path, monkeypatch):
    """If open() fails after the opener created the file, that file is removed."""
    path = tmp_path / "f"

    def failing_open(file, *args, **kwargs):
        os.close(kwargs["opener"](os.fspath(file), 0))  # create the file, as open() would
        raise MemoryError

    with monkeypatch.context() as m, pytest.raises(MemoryError):
        m.setattr(builtins, "open", failing_open)
        _open_and_close(path)
    assert not path.exists()


def test_open_new_locale_encoding(tmp_path):
    path = tmp_path / "f"
    with oschmod.open_new(path, encoding="locale") as f:
        f.write("x")
    assert path.read_text() == "x"


@posix_only
def test_mkdir_dotdot_through_symlink(tmp_path, monkeypatch):
    """Creation and chmod address the same object: '..' after a symlink isn't collapsed."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "real" / "sub").mkdir(parents=True)
    os.symlink("real/sub", "link")
    oschmod.mkdir("link/../new", 0o710)
    assert oschmod.get_full_mode(tmp_path / "real" / "new") == 0o710
    assert not (tmp_path / "new").exists()


@posix_only
@pytest.mark.skipif(sys.platform != "win32" and os.geteuid() == 0, reason="root ignores modes")
def test_mkdir_in_unreadable_parent(tmp_path, umask):
    """A write+search-only parent is enough, as for os.mkdir."""
    umask(0o077)
    parent = tmp_path / "p"
    parent.mkdir(0o700)
    parent.chmod(0o300)
    try:
        oschmod.mkdir(parent / "c", 0o755)
        parent.chmod(0o700)
        assert oschmod.get_full_mode(parent / "c") == 0o755
    finally:
        parent.chmod(0o700)


@posix_only
def test_mkdir_trailing_slash(tmp_path):
    oschmod.mkdir(f"{tmp_path / 'd'}/", 0o751)
    assert oschmod.get_full_mode(tmp_path / "d") == 0o751


@posix_only
def test_mkdir_new_dir_replaced_by_symlink(tmp_path, monkeypatch):
    """A symlink swapped in for the new directory is never followed, even with a trailing slash."""
    victim = tmp_path / "victim"
    victim.mkdir(0o700)
    victim.chmod(0o700)
    target = tmp_path / "d"
    real_mkdir = os.mkdir

    def swap(name, mode=0o777, *, dir_fd=None):
        real_mkdir(name, mode, dir_fd=dir_fd)
        os.rmdir(name, dir_fd=dir_fd)
        os.symlink(victim, name, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", swap)
    with contextlib.suppress(OSError):
        oschmod.mkdir(f"{target}/", 0o755)
    assert oschmod.get_full_mode(victim) == 0o700


@posix_only
def test_mkdir_parent_swapped(tmp_path, monkeypatch):
    """Swapping the parent for a symlink after creation can't redirect the chmod."""
    parent = tmp_path / "a"
    parent.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    private = elsewhere / "new"
    private.write_text("secret")
    private.chmod(0o600)
    real_mkdir = os.mkdir

    def swap(name, mode=0o777, *, dir_fd=None):
        real_mkdir(name, mode, dir_fd=dir_fd)
        os.rename(parent, tmp_path / "a_old")
        os.symlink(elsewhere, parent)

    monkeypatch.setattr(os, "mkdir", swap)
    oschmod.mkdir(parent / "new", 0o755)
    assert oschmod.get_full_mode(private) == 0o600
    assert oschmod.get_full_mode(tmp_path / "a_old" / "new") == 0o755


def test_open_new_allows_other_handles_while_open(tmp_path):
    """Like open(), the file isn't locked: other handles can read and write it."""
    path = tmp_path / "f"
    with oschmod.open_new(path, "w") as f:
        f.write("one")
        f.flush()
        assert path.read_text() == "one"
        with open(path, "a") as other:
            other.write("two")
    assert path.read_text() == "onetwo"


@posix_only
def test_search_flags_defined():
    """macOS and Linux always have a search-only open, even if os doesn't name it."""
    if sys.platform in ("darwin", "linux"):
        assert oschmod._SEARCH_FLAGS


@posix_only
def test_open_search_dir_falls_back_on_einval(tmp_path, monkeypatch):
    real_open = os.open

    def no_search(path, flags, *args, **kwargs):
        if flags & oschmod._SEARCH_FLAGS == oschmod._SEARCH_FLAGS and oschmod._SEARCH_FLAGS:
            raise OSError(errno.EINVAL, "Invalid argument")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", no_search)
    fd = oschmod._open_search_dir(str(tmp_path))
    os.close(fd)
