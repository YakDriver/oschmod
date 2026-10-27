"""CLI tests."""

import subprocess
import sys
from pathlib import Path

import pytest

import oschmod
from oschmod import cli


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    top = tmp_path / "top"
    (top / "sub").mkdir(parents=True)
    (top / "a").write_text("x")
    (top / "sub" / "b").write_text("x")
    return top


def test_set_mode(tree):
    assert cli.main(["600", str(tree / "a")]) == 0
    assert oschmod.get_mode(tree / "a") == 0o600


def test_recursive(tree):
    assert cli.main(["-R", "u=rwx,go=", str(tree)]) == 0
    for obj in (tree, tree / "sub", tree / "a", tree / "sub" / "b"):
        assert oschmod.get_mode(obj) == 0o700


def test_verbose_lists_objects(tree, capsys):
    assert cli.main(["-v", "-R", "700", str(tree)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[-1] == str(tree)  # root is set last
    assert sorted(lines) == sorted(
        str(p) for p in (tree, tree / "sub", tree / "a", tree / "sub" / "b")
    )


def test_very_verbose_shows_modes(tree, capsys):
    target = tree / "a"
    oschmod.set_mode(target, 0o644)
    assert cli.main(["-vv", "600", str(target)]) == 0
    assert capsys.readouterr().out.strip() == f"{target}: 0o644 (rw-r--r--) -> 0o600 (rw-------)"


def test_quiet_by_default(tree, capsys):
    assert cli.main(["600", str(tree / "a")]) == 0
    assert capsys.readouterr().out == ""


def test_missing_file(tmp_path, capsys):
    assert cli.main(["600", str(tmp_path / "missing")]) == 1
    assert "could not be found" in capsys.readouterr().err


def test_bad_mode(tree, capsys):
    assert cli.main(["u+q", str(tree / "a")]) == 1
    assert capsys.readouterr().err.startswith("oschmod:")


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
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
