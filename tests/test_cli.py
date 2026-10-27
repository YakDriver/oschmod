"""CLI tests."""

import subprocess
import sys
from pathlib import Path

import pytest

import oschmod
import oschmod.cli


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    top = tmp_path / "top"
    (top / "sub").mkdir(parents=True)
    (top / "a").write_text("x")
    (top / "sub" / "b").write_text("x")
    return top


def test_set_mode(tree):
    assert oschmod.cli.main(["600", str(tree / "a")]) == 0
    assert oschmod.get_mode(tree / "a") == 0o600


def test_recursive(tree):
    assert oschmod.cli.main(["-R", "u=rwx,go=", str(tree)]) == 0
    for obj in (tree, tree / "sub", tree / "a", tree / "sub" / "b"):
        assert oschmod.get_mode(obj) == 0o700


def test_verbose_lists_objects(tree, capsys):
    assert oschmod.cli.main(["-v", "-R", "700", str(tree)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[-1] == str(tree)  # root is set last
    assert sorted(lines) == sorted(
        str(p) for p in (tree, tree / "sub", tree / "a", tree / "sub" / "b")
    )


def test_very_verbose_shows_modes(tree, capsys):
    target = tree / "a"
    oschmod.set_mode(target, 0o644)
    assert oschmod.cli.main(["-vv", "600", str(target)]) == 0
    assert capsys.readouterr().out.strip() == f"{target}: 0o644 (rw-r--r--) -> 0o600 (rw-------)"


def test_quiet_by_default(tree, capsys):
    assert oschmod.cli.main(["600", str(tree / "a")]) == 0
    assert capsys.readouterr().out == ""


def test_missing_file(tmp_path, capsys):
    assert oschmod.cli.main(["600", str(tmp_path / "missing")]) == 1
    assert "could not be found" in capsys.readouterr().err


def test_bad_mode(tree, capsys):
    assert oschmod.cli.main(["u+q", str(tree / "a")]) == 1
    assert capsys.readouterr().err.startswith("oschmod:")


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        oschmod.cli.main(["--version"])
    assert exc.value.code == 0
    assert oschmod.__version__ in capsys.readouterr().out


def test_python_dash_m(tree):
    result = subprocess.run(
        [sys.executable, "-m", "oschmod", "640", str(tree / "a")],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert oschmod.get_mode(tree / "a") == 0o640


@pytest.mark.skipif(sys.platform != "win32", reason="Windows SID handling")
def test_invalid_other_sid(tree, capsys):
    target = tree / "a"
    oschmod.set_mode(target, 0o644)
    assert oschmod.cli.main(["--other-sid", "not-a-sid", "600", str(target)]) == 1
    assert capsys.readouterr().err.startswith("oschmod:")
    assert oschmod.get_mode(target) == 0o644  # DACL not written


def test_oversized_mode(tree, capsys):
    assert oschmod.cli.main(["777777777777777777777777", str(tree / "a")]) == 1
    assert "out of range" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX special bits")
def test_very_verbose_shows_special_bits(tree, capsys):
    target = tree / "a"
    oschmod.set_mode(target, 0o4755)
    assert oschmod.cli.main(["-vv", "2750", str(target)]) == 0
    out = capsys.readouterr().out.strip()
    assert out == f"{target}: 0o4755 (rwsr-xr-x) -> 0o2750 (rwxr-s---)"
