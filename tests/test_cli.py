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
    missing = tmp_path / "missing"
    assert oschmod.cli.main(["600", str(missing)]) == 1
    assert capsys.readouterr().err.strip() == f"oschmod: {missing}: No such file or directory"


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


def test_invalid_symbolic_mode_message(tree, capsys):
    assert oschmod.cli.main(["u+q", str(tree / "a")]) == 1
    assert capsys.readouterr().err.strip() == "oschmod: invalid mode modifier 'u+q'"


# --- Multiple paths (#194) -------------------------------------------------------


def test_multiple_paths(tree):
    paths = [tree / "a", tree / "sub" / "b", tree / "sub"]
    assert oschmod.cli.main(["700", *map(str, paths)]) == 0
    for path in paths:
        assert oschmod.get_mode(path) == 0o700


def test_multiple_paths_keep_going_after_error(tree, tmp_path, capsys):
    missing = tmp_path / "missing"
    assert oschmod.cli.main(["600", str(missing), str(tree / "a"), str(tree / "sub" / "b")]) == 1
    assert capsys.readouterr().err.strip() == f"oschmod: {missing}: No such file or directory"
    assert oschmod.get_mode(tree / "a") == 0o600
    assert oschmod.get_mode(tree / "sub" / "b") == 0o600


def test_multiple_paths_recursive(tmp_path):
    tops = []
    for name in ("one", "two"):
        top = tmp_path / name
        (top / "d").mkdir(parents=True)
        (top / "d" / "f").write_text("x")
        tops.append(top)
    assert oschmod.cli.main(["-R", "u=rwX,go=", *map(str, tops)]) == 0
    for top in tops:
        assert oschmod.get_mode(top / "d" / "f") == 0o600
        assert oschmod.get_mode(top / "d") == 0o700
        assert oschmod.get_mode(top) == 0o700


def test_invalid_mode_is_reported_once_and_nothing_changes(tree, capsys):
    oschmod.set_mode(tree / "a", 0o644)
    assert oschmod.cli.main(["u+q", str(tree / "a"), str(tree / "sub" / "b")]) == 1
    assert capsys.readouterr().err.strip() == "oschmod: invalid mode modifier 'u+q'"
    assert oschmod.get_mode(tree / "a") == 0o644


def test_object_is_required(capsys):
    with pytest.raises(SystemExit):
        oschmod.cli.main(["600"])
    assert "required: object" in capsys.readouterr().err


def test_capital_x_recursive(tmp_path):
    """a+rX: the common idiom for 'make readable, and directories enterable' (#192)."""
    top = tmp_path / "t"
    (top / "d").mkdir(parents=True)
    (top / "d" / "plain").write_text("x")
    (top / "d" / "script").write_text("x")
    oschmod.set_mode(top / "d" / "plain", 0o600)
    oschmod.set_mode(top / "d" / "script", 0o700)
    oschmod.set_mode(top / "d", 0o700)
    oschmod.set_mode(top, 0o700)
    assert oschmod.cli.main(["-R", "a+rX", str(top)]) == 0
    assert oschmod.get_mode(top / "d" / "plain") == 0o644
    assert oschmod.get_mode(top / "d" / "script") == 0o755
    assert oschmod.get_mode(top / "d") == 0o755
    assert oschmod.get_mode(top) == 0o755
