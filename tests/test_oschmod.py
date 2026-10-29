"""Tests for the oschmod library."""

import os
import stat
import sys
from pathlib import Path
from random import randrange

import pytest

import oschmod

TRIPLE7 = 0o777


def _make_tree(top: Path) -> tuple[Path, Path, Path, Path]:
    """Create top/file1 and top/testdir2/testdir3/file2."""
    testdir = top / "testdir2" / "testdir3"
    testdir.mkdir(parents=True)
    file1 = top / "file1"
    file2 = testdir / "file2"
    file1.write_text("contents")
    file2.write_text("contents")
    return testdir, top / "testdir2", file1, file2


@pytest.mark.parametrize(
    "mode",
    [
        stat.S_IRUSR | stat.S_IWUSR,
        stat.S_IRWXU | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH,
        TRIPLE7,
    ],
)
def test_permissions(tmp_path, mode):
    path = tmp_path / "file.txt"
    path.write_text("x")
    oschmod.set_mode(str(path), mode)
    assert oschmod.get_mode(str(path)) == mode


def test_set_recursive(tmp_path):
    testdir, middir, file1, file2 = _make_tree(tmp_path / "testdir1")
    top = tmp_path / "testdir1"
    for obj in (top, testdir, file1, file2):
        oschmod.set_mode(str(obj), TRIPLE7)

    oschmod.set_mode_recursive(str(top), 0o600, 0o700)

    for obj in (top, middir, testdir):
        assert oschmod.get_mode(str(obj)) == 0o700
    for obj in (file1, file2):
        assert oschmod.get_mode(str(obj)) == 0o600


def test_set_recursive_dir_mode_zero_is_honored(tmp_path):
    """dir_mode=0 must not fall back to mode (previously treated as falsy)."""
    top = tmp_path / "d"
    top.mkdir()
    (top / "f").write_text("x")
    oschmod.set_mode_recursive(top, 0o600, 0)
    try:
        assert oschmod.get_mode(top) == 0
    finally:
        oschmod.set_mode(top, 0o700)  # allow tmp_path cleanup
    assert oschmod.get_mode(top / "f") == 0o600


def test_set_recursive_on_file(tmp_path):
    path = tmp_path / "f"
    path.write_text("x")
    oschmod.set_mode_recursive(path, 0o640, 0o700)
    assert oschmod.get_mode(path) == 0o640


def test_set_mode_octal_string(tmp_path):
    path = tmp_path / "f"
    path.write_text("x")
    oschmod.set_mode(path, "640")
    assert oschmod.get_mode(path) == 0o640


@pytest.mark.parametrize("bad", [None, 6.4, True, b"644"])
def test_set_mode_rejects_bad_type(tmp_path, bad):
    path = tmp_path / "f"
    path.write_text("x")
    oschmod.set_mode(path, 0o644)
    with pytest.raises(TypeError):
        oschmod.set_mode(path, bad)
    assert oschmod.get_mode(path) == 0o644  # unchanged


@pytest.mark.parametrize("bad", ["u+q", "x+r", "u+r w", "u"])
def test_bad_symbolic(bad):
    with pytest.raises(oschmod.ModeError, match="invalid mode modifier") as exc_info:
        oschmod.get_effective_mode(0o644, bad)
    assert repr(bad) in str(exc_info.value)
    # Backward compatible with code that caught AttributeError (#191).
    assert isinstance(exc_info.value, ValueError)
    assert isinstance(exc_info.value, AttributeError)


def test_get_effective_mode_rejects_non_string():
    with pytest.raises(TypeError) as exc_info:
        oschmod.get_effective_mode(0o644, 123)  # type: ignore[arg-type]
    assert isinstance(exc_info.value, AttributeError)


@pytest.mark.parametrize("bad", ["u+q", "9", "rwx", ""])
def test_set_mode_rejects_bad_mode_string(tmp_path, bad):
    path = tmp_path / "f"
    path.write_text("x")
    oschmod.set_mode(path, 0o644)
    with pytest.raises(oschmod.ModeError):
        oschmod.set_mode(path, bad)
    assert oschmod.get_mode(path) == 0o644


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (0o000, "---------"),
        (0o750, "rwxr-x---"),
        (0o644, "rw-r--r--"),
        (0o777, "rwxrwxrwx"),
        (0o4755, "rwsr-xr-x"),
        (0o4644, "rwSr--r--"),
        (0o2750, "rwxr-s---"),
        (0o2740, "rwxr-S---"),
        (0o1777, "rwxrwxrwt"),
        (0o1776, "rwxrwxrwT"),
    ],
)
def test_mode_to_symbolic(mode, expected):
    assert oschmod.mode_to_symbolic(mode) == expected


def test_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        oschmod.get_mode(tmp_path / "nope")


def test_symbolic_effective_add():
    """Check calculation of effective mode from symbolic."""
    assert oschmod.get_effective_mode(0b111000000, "g+x") == 0b111001000
    assert oschmod.get_effective_mode(0b111000000, "o+x") == 0b111000001
    assert oschmod.get_effective_mode(0b111000000, "u+x") == 0b111000000
    assert oschmod.get_effective_mode(0b111000000, "+x") == 0b111001001
    assert oschmod.get_effective_mode(0b111000000, "ugo+x") == 0b111001001
    assert oschmod.get_effective_mode(0b111000000, "a+x") == 0b111001001

    assert oschmod.get_effective_mode(0b111000000, "g+wx") == 0b111011000
    assert oschmod.get_effective_mode(0b111000000, "o+wx") == 0b111000011
    assert oschmod.get_effective_mode(0b111000000, "u+wx") == 0b111000000
    assert oschmod.get_effective_mode(0b111000000, "+wx") == 0b111011011
    assert oschmod.get_effective_mode(0b111000000, "a+wx") == 0b111011011

    assert oschmod.get_effective_mode(0b111000000, "g+rwx") == 0b111111000
    assert oschmod.get_effective_mode(0b111000000, "o+rwx") == 0b111000111
    assert oschmod.get_effective_mode(0b111000000, "u+rwx") == 0b111000000
    assert oschmod.get_effective_mode(0b111000000, "+rwx") == 0b111111111
    assert oschmod.get_effective_mode(0b111000000, "a+rwx") == 0b111111111

    # randomly chosen starting permission = 394
    assert oschmod.get_effective_mode(0b110001010, "g+x") == 0b110001010
    assert oschmod.get_effective_mode(0b110001010, "o+x") == 0b110001011
    assert oschmod.get_effective_mode(0b110001010, "u+x") == 0b111001010
    assert oschmod.get_effective_mode(0b110001010, "+x") == 0b111001011
    assert oschmod.get_effective_mode(0b110001010, "ugo+x") == 0b111001011
    assert oschmod.get_effective_mode(0b110001010, "a+x") == 0b111001011

    assert oschmod.get_effective_mode(0b110001010, "g+wx") == 0b110011010
    assert oschmod.get_effective_mode(0b110001010, "o+wx") == 0b110001011
    assert oschmod.get_effective_mode(0b110001010, "u+wx") == 0b111001010
    assert oschmod.get_effective_mode(0b110001010, "+wx") == 0b111011011
    assert oschmod.get_effective_mode(0b110001010, "a+wx") == 0b111011011

    assert oschmod.get_effective_mode(0b110001010, "g+rwx") == 0b110111010
    assert oschmod.get_effective_mode(0b110001010, "o+rwx") == 0b110001111
    assert oschmod.get_effective_mode(0b110001010, "u+rwx") == 0b111001010
    assert oschmod.get_effective_mode(0b110001010, "+rwx") == 0b111111111
    assert oschmod.get_effective_mode(0b110001010, "a+rwx") == 0b111111111


def test_symbolic_effective_add2():
    """Check calculation of effective mode from symbolic."""
    # randomly chosen starting permission = 53
    assert oschmod.get_effective_mode(0b000110101, "g+x") == 0b000111101
    assert oschmod.get_effective_mode(0b000110101, "o+x") == 0b000110101
    assert oschmod.get_effective_mode(0b000110101, "u+x") == 0b001110101
    assert oschmod.get_effective_mode(0b000110101, "+x") == 0b001111101
    assert oschmod.get_effective_mode(0b000110101, "ugo+x") == 0b001111101
    assert oschmod.get_effective_mode(0b000110101, "a+x") == 0b001111101

    assert oschmod.get_effective_mode(0b000110101, "g+wx") == 0b000111101
    assert oschmod.get_effective_mode(0b000110101, "o+wx") == 0b000110111
    assert oschmod.get_effective_mode(0b000110101, "u+wx") == 0b011110101
    assert oschmod.get_effective_mode(0b000110101, "+wx") == 0b011111111
    assert oschmod.get_effective_mode(0b000110101, "a+wx") == 0b011111111

    assert oschmod.get_effective_mode(0b000110101, "g+rwx") == 0b000111101
    assert oschmod.get_effective_mode(0b000110101, "o+rwx") == 0b000110111
    assert oschmod.get_effective_mode(0b000110101, "u+rwx") == 0b111110101

    # randomly chosen starting permission = 372
    assert oschmod.get_effective_mode(0b101110100, "g+x") == 0b101111100
    assert oschmod.get_effective_mode(0b101110100, "o+x") == 0b101110101
    assert oschmod.get_effective_mode(0b101110100, "u+x") == 0b101110100
    assert oschmod.get_effective_mode(0b101110100, "+x") == 0b101111101
    assert oschmod.get_effective_mode(0b101110100, "ugo+x") == 0b101111101
    assert oschmod.get_effective_mode(0b101110100, "a+x") == 0b101111101

    assert oschmod.get_effective_mode(0b101110100, "g+rx") == 0b101111100
    assert oschmod.get_effective_mode(0b101110100, "o+rx") == 0b101110101
    assert oschmod.get_effective_mode(0b101110100, "u+rx") == 0b101110100
    assert oschmod.get_effective_mode(0b101110100, "+rx") == 0b101111101
    assert oschmod.get_effective_mode(0b101110100, "a+rx") == 0b101111101

    assert oschmod.get_effective_mode(0b101110100, "g+rwx") == 0b101111100
    assert oschmod.get_effective_mode(0b101110100, "o+rwx") == 0b101110111
    assert oschmod.get_effective_mode(0b101110100, "u+rwx") == 0b111110100

    # randomly chosen starting permission = 501
    assert oschmod.get_effective_mode(0b111110101, "g+x") == 0b111111101
    assert oschmod.get_effective_mode(0b111110101, "o+x") == 0b111110101
    assert oschmod.get_effective_mode(0b111110101, "u+x") == 0b111110101
    assert oschmod.get_effective_mode(0b111110101, "+x") == 0b111111101
    assert oschmod.get_effective_mode(0b111110101, "ugo+x") == 0b111111101
    assert oschmod.get_effective_mode(0b111110101, "a+x") == 0b111111101

    assert oschmod.get_effective_mode(0b111110101, "g+rw") == 0b111110101
    assert oschmod.get_effective_mode(0b111110101, "o+rw") == 0b111110111
    assert oschmod.get_effective_mode(0b111110101, "u+rw") == 0b111110101
    assert oschmod.get_effective_mode(0b111110101, "+rw") == 0b111110111
    assert oschmod.get_effective_mode(0b111110101, "a+rw") == 0b111110111

    assert oschmod.get_effective_mode(0b111110101, "g+rwx") == 0b111111101
    assert oschmod.get_effective_mode(0b111110101, "o+rwx") == 0b111110111
    assert oschmod.get_effective_mode(0b111110101, "u+rwx") == 0b111110101


def test_symbolic_effective_sub():
    """Check calculation of effective mode from symbolic."""
    # randomly chosen starting permission = 328
    assert oschmod.get_effective_mode(0b101001000, "g-x") == 0b101000000
    assert oschmod.get_effective_mode(0b101001000, "o-x") == 0b101001000
    assert oschmod.get_effective_mode(0b101001000, "u-x") == 0b100001000
    assert oschmod.get_effective_mode(0b101001000, "uo-x") == 0b100001000
    assert oschmod.get_effective_mode(0b101001000, "-x") == 0b100000000
    assert oschmod.get_effective_mode(0b101001000, "ugo-x") == 0b100000000
    assert oschmod.get_effective_mode(0b101001000, "a-x") == 0b100000000

    # randomly chosen starting permission = 256
    assert oschmod.get_effective_mode(0b100000000, "g-r") == 0b100000000
    assert oschmod.get_effective_mode(0b100000000, "o-r") == 0b100000000
    assert oschmod.get_effective_mode(0b100000000, "u-r") == 0b000000000
    assert oschmod.get_effective_mode(0b100000000, "uo-r") == 0b000000000
    assert oschmod.get_effective_mode(0b100000000, "-r") == 0b000000000
    assert oschmod.get_effective_mode(0b100000000, "ugo-r") == 0b000000000
    assert oschmod.get_effective_mode(0b100000000, "a-r") == 0b000000000

    # randomly chosen starting permission = 166
    assert oschmod.get_effective_mode(0b010100110, "g-x") == 0b010100110
    assert oschmod.get_effective_mode(0b010100110, "o-w") == 0b010100100
    assert oschmod.get_effective_mode(0b010100110, "u-rw") == 0b000100110
    assert oschmod.get_effective_mode(0b010100110, "uo-rw") == 0b000100000
    assert oschmod.get_effective_mode(0b010100110, "-wx") == 0b000100100
    assert oschmod.get_effective_mode(0b010100110, "ugo-rwx") == 0b000000000
    assert oschmod.get_effective_mode(0b010100110, "a-r") == 0b010000010

    # randomly chosen starting permission = 174
    assert oschmod.get_effective_mode(0b010101110, "ug-w") == 0b000101110
    assert oschmod.get_effective_mode(0b010101110, "u-r") == 0b010101110
    assert oschmod.get_effective_mode(0b010101110, "u-rx") == 0b010101110
    assert oschmod.get_effective_mode(0b010101110, "ug-rwx") == 0b000000110
    assert oschmod.get_effective_mode(0b010101110, "g-rx") == 0b010000110
    assert oschmod.get_effective_mode(0b010101110, "go-rw") == 0b010001000
    assert oschmod.get_effective_mode(0b010101110, "ug-x") == 0b010100110


def test_symbolic_effective_eq():
    """Check calculation of effective mode from symbolic."""
    # randomly chosen starting permission = 494
    assert oschmod.get_effective_mode(0b111101110, "go=rx") == 0b111101101
    assert oschmod.get_effective_mode(0b111101110, "=r") == 0b100100100
    assert oschmod.get_effective_mode(0b111101110, "ugo=rw") == 0b110110110
    assert oschmod.get_effective_mode(0b111101110, "ugo=rx") == 0b101101101
    assert oschmod.get_effective_mode(0b111101110, "uo=r") == 0b100101100
    assert oschmod.get_effective_mode(0b111101110, "o=rw") == 0b111101110
    assert oschmod.get_effective_mode(0b111101110, "=x") == 0b001001001

    # randomly chosen starting permission = 417
    assert oschmod.get_effective_mode(0b110100001, "ugo=x") == 0b001001001
    assert oschmod.get_effective_mode(0b110100001, "ug=rw") == 0b110110001
    assert oschmod.get_effective_mode(0b110100001, "ugo=rw") == 0b110110110
    assert oschmod.get_effective_mode(0b110100001, "u=wx") == 0b011100001
    assert oschmod.get_effective_mode(0b110100001, "=rx") == 0b101101101
    assert oschmod.get_effective_mode(0b110100001, "u=r") == 0b100100001
    assert oschmod.get_effective_mode(0b110100001, "uo=wx") == 0b011100011

    # randomly chosen starting permission = 359
    assert oschmod.get_effective_mode(0b101100111, "go=") == 0b101000000
    assert oschmod.get_effective_mode(0b101100111, "ugo=") == 0b000000000
    assert oschmod.get_effective_mode(0b101100111, "ugo=rwx") == 0b111111111
    assert oschmod.get_effective_mode(0b101100111, "uo=w") == 0b010100010
    assert oschmod.get_effective_mode(0b101100111, "=w") == 0b010010010
    assert oschmod.get_effective_mode(0b101100111, "uo=wx") == 0b011100011
    assert oschmod.get_effective_mode(0b101100111, "u=r") == 0b100100111


def generate_symbolic():
    """Generate one symbolic representation of a mode modifier."""
    who = randrange(8)
    whom = (
        ("u" if who & 0b100 else "") + ("g" if who & 0b010 else "") + ("o" if who & 0b001 else "")
    )
    operation = "+-="[randrange(3)]
    perm = randrange(8)
    perms = (
        ("r" if perm & 0b100 else "")
        + ("w" if perm & 0b010 else "")
        + ("x" if perm & 0b001 else "")
    )
    return whom + operation + perms


def generate_cases(count):
    """Generate test cases to be solved manually and added to tests."""
    for _ in range(count):
        symbolics = ",".join(generate_symbolic() for _ in range(randrange(1, 4)))
        start = randrange(512)
        print(f'assert oschmod.get_effective_mode(0b{start:09b}, "{symbolics}") == 0b{start:09b}')


def test_symbolic_multiples():
    """Check calculation of effective mode from symbolic."""
    assert oschmod.get_effective_mode(0b000101010, "g-rwx,go=") == 0b000000000
    assert oschmod.get_effective_mode(0b011001011, "uo-wx,u=x") == 0b001001000
    assert oschmod.get_effective_mode(0b111101000, "u=rwx,o=x") == 0b111101001
    assert oschmod.get_effective_mode(0b110101001, "+r,ug=rx") == 0b101101101
    assert oschmod.get_effective_mode(0b010010000, "go-,go+,u+rw") == 0b110010000
    assert oschmod.get_effective_mode(0b000101110, "ug-rw,go=x") == 0b000001001
    assert oschmod.get_effective_mode(0b010110000, "=rwx,=rw,ug-") == 0b110110110
    assert oschmod.get_effective_mode(0b010001111, "o-rwx,o=rwx,ug-x") == 0b010000111
    assert oschmod.get_effective_mode(0b100111011, "u-r,o=rwx,ug-wx") == 0b000100111
    assert oschmod.get_effective_mode(0b111110101, "o=rwx,ugo-,g=rx") == 0b111101111
    assert oschmod.get_effective_mode(0b010010000, "u=rx") == 0b101010000
    assert oschmod.get_effective_mode(0b001011111, "=") == 0b000000000
    assert oschmod.get_effective_mode(0b100011010, "ug-w,uo=rw") == 0b110001110
    assert oschmod.get_effective_mode(0b111001001, "ug=rw,g-wx") == 0b110100001
    assert oschmod.get_effective_mode(0b111000000, "u-,uo+rx,go+x") == 0b111001101
    assert oschmod.get_effective_mode(0b000000000, "u=rx,uo-x") == 0b100000000
    assert oschmod.get_effective_mode(0b101110101, "uo=rx") == 0b101110101
    assert oschmod.get_effective_mode(0b111111010, "g-wx,ug=,-x") == 0b000000010
    assert oschmod.get_effective_mode(0b100011000, "uo+rw") == 0b110011110
    assert oschmod.get_effective_mode(0b011111000, "ugo+,uo+w,-rwx") == 0b000000000
    assert oschmod.get_effective_mode(0b000010100, "ug=x,ug=x,g-rx") == 0b001000100
    assert oschmod.get_effective_mode(0b110101101, "g=rwx") == 0b110111101
    assert oschmod.get_effective_mode(0b000010111, "=wx") == 0b011011011
    assert oschmod.get_effective_mode(0b000111011, "u-rw,uo-x,o+wx") == 0b000111011
    assert oschmod.get_effective_mode(0b010110000, "uo+,u+") == 0b010110000
    assert oschmod.get_effective_mode(0b000111110, "go=x,ug+x,uo=rx") == 0b101001101
    assert oschmod.get_effective_mode(0b011101111, "o+wx") == 0b011101111
    assert oschmod.get_effective_mode(0b001001011, "u-,go+w,ugo=w") == 0b010010010
    assert oschmod.get_effective_mode(0b110110100, "u=w,=x") == 0b001001001
    assert oschmod.get_effective_mode(0b110011100, "u=w,ug-rwx,uo+rwx") == 0b111000111
    assert oschmod.get_effective_mode(0b100101001, "go-r") == 0b100001001
    assert oschmod.get_effective_mode(0b110100110, "uo=r,ug+rx,ugo=") == 0b000000000
    assert oschmod.get_effective_mode(0b101100000, "go=wx,o-") == 0b101011011
    assert oschmod.get_effective_mode(0b111111101, "-r,o=r,o-w") == 0b011011100
    assert oschmod.get_effective_mode(0b110101000, "uo-rx,+rwx") == 0b111111111
    assert oschmod.get_effective_mode(0b101011111, "go=wx") == 0b101011011
    assert oschmod.get_effective_mode(0b110110010, "go+x,ugo-w,u+rwx") == 0b111101001
    assert oschmod.get_effective_mode(0b001100101, "=rx,-rwx") == 0b000000000
    assert oschmod.get_effective_mode(0b001010011, "uo=x") == 0b001010001
    assert oschmod.get_effective_mode(0b011101110, "ugo-rx,uo+rw,uo-rw") == 0b000000000


def test_symbolic_use(tmp_path):
    top = tmp_path / "testdir1"
    testdir, middir, file1, file2 = _make_tree(top)
    for obj in (top, testdir, file1, file2):
        oschmod.set_mode(str(obj), "+rwx")

    oschmod.set_mode_recursive(str(top), "u=rw,go=", "u=rwx,go=")

    for obj in (top, middir, testdir):
        assert oschmod.get_mode(str(obj)) == 0o700
    for obj in (file1, file2):
        assert oschmod.get_mode(str(obj)) == 0o600


@pytest.mark.parametrize("bad", [-1, 0o10000, 2**70, "777777777777777777777777", "17777"])
def test_set_mode_rejects_out_of_range(tmp_path, bad):
    path = tmp_path / "f"
    path.write_text("x")
    oschmod.set_mode(path, 0o644)
    with pytest.raises(ValueError, match="out of range"):
        oschmod.set_mode(path, bad)
    assert oschmod.get_mode(path) == 0o644


posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX special bits")


@posix_only
def test_get_full_mode_includes_special_bits(tmp_path):
    path = tmp_path / "f"
    path.write_text("x")
    oschmod.set_mode(path, 0o4755)
    assert oschmod.get_mode(path) == 0o755
    assert oschmod.get_full_mode(path) == 0o4755


@posix_only
def test_symbolic_preserves_special_bits(tmp_path):
    directory = tmp_path / "d"
    directory.mkdir()
    oschmod.set_mode(directory, 0o1755)  # sticky bit
    oschmod.set_mode(directory, "g+w,o-rx")
    assert oschmod.get_full_mode(directory) == 0o1770


# Recorded from GNU coreutils chmod 9.12: (start, mode, file result, dir result).
GNU_SYMBOLIC_SPECIAL_BITS = [
    (0o7755, "a=r", 0o0444, 0o6444),
    (0o7755, "u=rwx", 0o3755, 0o7755),
    (0o7755, "g=rx", 0o5755, 0o7755),
    (0o7755, "o=rx", 0o6755, 0o6755),
    (0o7755, "ug=rw", 0o1665, 0o7665),
    (0o7755, "go=", 0o4700, 0o6700),
    (0o7755, "=r", 0o0444, 0o6444),
    (0o7755, "u=", 0o3055, 0o7055),
    (0o7755, "a=", 0o0000, 0o6000),
    (0o7755, "u+x", 0o7755, 0o7755),
    (0o7755, "go-w", 0o7755, 0o7755),
    (0o7755, "u=rw,g-x", 0o3645, 0o7645),
    (0o4755, "a=r", 0o0444, 0o4444),
    (0o4755, "u=rwx", 0o0755, 0o4755),
    (0o4755, "g=rx", 0o4755, 0o4755),
    (0o4755, "go=", 0o4700, 0o4700),
    (0o2755, "g=rx", 0o0755, 0o2755),
    (0o2755, "u=", 0o2055, 0o2055),
    (0o1755, "a=r", 0o0444, 0o0444),
    (0o1755, "o=rx", 0o0755, 0o0755),
    (0o1755, "ug=rw", 0o1665, 0o1665),
    (0o6644, "u=rwx", 0o2744, 0o6744),
    (0o6644, "g=rx", 0o4654, 0o6654),
    (0o6644, "u=rw,g-x", 0o2644, 0o6644),
]


@posix_only
@pytest.mark.parametrize(("start", "mode", "file_result", "dir_result"), GNU_SYMBOLIC_SPECIAL_BITS)
def test_symbolic_special_bits_match_gnu(tmp_path, start, mode, file_result, dir_result):
    """'=' clears the set-ID/sticky bits of the classes it sets, like GNU (#188)."""
    file_path = tmp_path / "f"
    file_path.write_text("x")
    dir_path = tmp_path / "d"
    dir_path.mkdir()
    for path, expected in ((file_path, file_result), (dir_path, dir_result)):
        os.chmod(path, start)
        if os.stat(path).st_mode & 0o7777 != start:
            pytest.skip(f"filesystem doesn't keep {start:#o} on {path.name}")
        oschmod.set_mode(path, mode)
        assert oschmod.get_full_mode(path) == expected, (path.name, mode)
    os.chmod(dir_path, 0o700)


@posix_only
def test_recursive_equals_clears_file_special_bits(tmp_path):
    top = tmp_path / "t"
    top.mkdir()
    (top / "f").write_text("x")
    os.chmod(top / "f", 0o4700)
    os.chmod(top, 0o2700)
    oschmod.set_mode_recursive(top, "u=rwx,go=")
    assert oschmod.get_full_mode(top / "f") == 0o0700
    assert oschmod.get_full_mode(top) == 0o2700  # directories keep set-ID bits


@pytest.mark.parametrize("bad", ["17777", "77777777", "777777777777777777777777"])
def test_out_of_range_mode_string_is_mode_error(tmp_path, bad):
    path = tmp_path / "f"
    path.write_text("x")
    with pytest.raises(oschmod.ModeError, match="out of range"):
        oschmod.set_mode(path, bad)


@pytest.mark.parametrize("bad", [-1, 0o10000])
def test_out_of_range_int_mode_is_plain_value_error(tmp_path, bad):
    path = tmp_path / "f"
    path.write_text("x")
    with pytest.raises(ValueError, match="out of range") as exc_info:
        oschmod.set_mode(path, bad)
    assert not isinstance(exc_info.value, oschmod.ModeError)
