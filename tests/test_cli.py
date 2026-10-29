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
        # X keeps execute on files that already have it, and new files on Windows
        # inherit full control, so start from a known non-executable mode.
        oschmod.set_mode(top / "d" / "f", 0o644)
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
    assert "a MODE and at least one FILE are required" in capsys.readouterr().err


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


# --- -c, -f, --reference, long options (#195) --------------------------------------


def test_changes_reports_only_changed(tree, capsys):
    a, b = tree / "a", tree / "sub" / "b"
    oschmod.set_mode(a, 0o644)
    oschmod.set_mode(b, 0o600)
    assert oschmod.cli.main(["-c", "600", str(a), str(b)]) == 0
    assert capsys.readouterr().out.splitlines() == [f"{a}: 0o644 (rw-r--r--) -> 0o600 (rw-------)"]
    assert oschmod.cli.main(["--changes", "600", str(a), str(b)]) == 0
    assert capsys.readouterr().out == ""


def test_changes_overrides_verbose(tree, capsys):
    a = tree / "a"
    oschmod.set_mode(a, 0o600)
    assert oschmod.cli.main(["-v", "-c", "600", str(a)]) == 0
    assert capsys.readouterr().out == ""


def test_changes_recursive(tree, capsys):
    oschmod.set_mode_recursive(tree, 0o600, 0o700)
    oschmod.set_mode(tree / "a", 0o644)
    assert oschmod.cli.main(["-R", "-c", "u=rwX,go=", str(tree)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines == [f"{tree / 'a'}: 0o644 (rw-r--r--) -> 0o600 (rw-------)"]


def test_silent_hides_errors_but_fails(tree, tmp_path, capsys):
    missing = tmp_path / "missing"
    assert oschmod.cli.main(["-f", "600", str(missing), str(tree / "a")]) == 1
    assert capsys.readouterr().err == ""
    assert oschmod.get_mode(tree / "a") == 0o600
    for flag in ("--silent", "--quiet"):
        assert oschmod.cli.main([flag, "600", str(missing)]) == 1
        assert capsys.readouterr().err == ""


def test_silent_still_reports_invalid_mode(tree, capsys):
    """Like GNU, -f doesn't hide usage errors such as an invalid mode."""
    assert oschmod.cli.main(["-f", "u+q", str(tree / "a")]) == 1
    assert "invalid mode modifier" in capsys.readouterr().err


def test_reference(tree):
    ref, a, b = tree / "sub" / "b", tree / "a", tree / "c"
    b.write_text("x")
    oschmod.set_mode(ref, 0o640)
    oschmod.set_mode(a, 0o600)
    oschmod.set_mode(b, 0o600)
    assert oschmod.cli.main([f"--reference={ref}", str(a)]) == 0
    assert oschmod.get_mode(a) == 0o640
    assert oschmod.cli.main(["--reference", str(ref), str(a), str(b)]) == 0
    assert oschmod.get_mode(b) == 0o640


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX special bits")
def test_reference_copies_special_bits(tmp_path):
    ref, target = tmp_path / "ref", tmp_path / "target"
    ref.write_text("x")
    target.write_text("x")
    ref.chmod(0o4700)
    assert oschmod.cli.main([f"--reference={ref}", str(target)]) == 0
    assert oschmod.get_full_mode(target) == 0o4700


def test_reference_missing(tree, tmp_path, capsys):
    oschmod.set_mode(tree / "a", 0o600)
    missing = tmp_path / "nope"
    assert oschmod.cli.main([f"--reference={missing}", str(tree / "a")]) == 1
    assert capsys.readouterr().err.startswith(f"oschmod: {missing}: ")
    assert oschmod.get_mode(tree / "a") == 0o600


def test_reference_treats_all_operands_as_files(tree, capsys):
    """Like GNU, '600' after --reference is a file name, not a mode."""
    oschmod.set_mode(tree / "a", 0o640)
    assert oschmod.cli.main([f"--reference={tree / 'a'}", "600", str(tree / "sub" / "b")]) == 1
    assert "600: No such file or directory" in capsys.readouterr().err
    assert oschmod.get_mode(tree / "sub" / "b") == 0o640


def test_reference_recursive(tree):
    ref = tree / "a"
    oschmod.set_mode(ref, 0o750)
    assert oschmod.cli.main(["-R", f"--reference={ref}", str(tree / "sub")]) == 0
    assert oschmod.get_mode(tree / "sub") == 0o750
    assert oschmod.get_mode(tree / "sub" / "b") == 0o750


def test_long_options(tree, capsys):
    assert oschmod.cli.main(["--recursive", "--verbose", "u=rwx,go=", str(tree)]) == 0
    assert capsys.readouterr().out.splitlines()[-1] == str(tree)
    assert oschmod.get_mode(tree / "sub" / "b") == 0o700


def test_copy_mode(tmp_path):
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.write_text("x")
    dst.write_text("x")
    oschmod.set_mode(src, 0o640)
    oschmod.set_mode(dst, 0o600)
    oschmod.copy_mode(src, dst)
    assert oschmod.get_mode(dst) == 0o640


@pytest.mark.parametrize(
    "argv",
    [
        ["600", "-v", "{f}"],
        ["600", "{f}", "-v"],
        ["-R", "600", "-v", "{f}"],
        ["600", "-R", "{f}"],
        ["600", "--recursive", "{f}", "-c"],
    ],
)
def test_options_after_mode(tree, capsys, argv):
    """Options may follow MODE or FILE, as in GNU chmod and oschmod 0.5."""
    target = tree / "a"
    oschmod.set_mode(target, 0o644)
    assert oschmod.cli.main([a.format(f=target) for a in argv]) == 0
    assert oschmod.get_mode(target) == 0o600


@pytest.mark.skipif(sys.platform != "win32", reason="Windows SID handling")
def test_other_sid_after_mode(tree):
    target = tree / "a"
    assert oschmod.cli.main(["604", "--other-sid", "S-1-5-11", str(target)]) == 0
    assert oschmod.get_mode(target, other_sid="S-1-5-11") == 0o604


def test_double_dash_for_hyphen_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "-v").write_text("x")
    oschmod.set_mode(tmp_path / "-v", 0o644)
    assert oschmod.cli.main(["600", "--", "-v"]) == 0
    assert oschmod.get_mode(tmp_path / "-v") == 0o600


def test_double_dash_with_reference(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ref").write_text("x")
    (tmp_path / "-f").write_text("x")
    oschmod.set_mode(tmp_path / "ref", 0o640)
    assert oschmod.cli.main(["--reference=ref", "--", "-f"]) == 0
    assert oschmod.get_mode(tmp_path / "-f") == 0o640


def test_unknown_option_is_rejected(tree, capsys):
    with pytest.raises(SystemExit):
        oschmod.cli.main(["600", "--bogus", str(tree / "a")])
    assert "unrecognized arguments: --bogus" in capsys.readouterr().err


def test_no_operands(capsys):
    with pytest.raises(SystemExit):
        oschmod.cli.main([])
    assert "a MODE and at least one FILE are required" in capsys.readouterr().err
