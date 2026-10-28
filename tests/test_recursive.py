"""Recursive traversal: symlinks (#183), error handling (#187), unlistable dirs (#186)."""

import os
import sys
from pathlib import Path

import pytest

import oschmod
import oschmod.cli


def _symlink(target: Path, link: Path, *, is_dir: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=is_dir)
    except (OSError, NotImplementedError) as exc:  # Windows without symlink privilege
        pytest.skip(f"cannot create symlinks: {exc}")


@pytest.fixture
def layout(tmp_path: Path) -> dict[str, Path]:
    """A tree whose links point at a file and a directory outside it."""
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("secret")
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "inner.txt").write_text("x")
    for path in (outside_file, outside_dir / "inner.txt"):
        oschmod.set_mode(path, 0o600)
    oschmod.set_mode(outside_dir, 0o700)

    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "f.txt").write_text("x")
    _symlink(outside_file, tree / "sub" / "file_link")
    _symlink(outside_dir, tree / "dir_link", is_dir=True)
    return {"tree": tree, "file": outside_file, "dir": outside_dir}


def test_symlinks_skipped_by_default(layout):
    oschmod.set_mode_recursive(layout["tree"], 0o644, 0o755)
    assert oschmod.get_mode(layout["tree"] / "sub" / "f.txt") == 0o644
    assert oschmod.get_mode(layout["file"]) == 0o600
    assert oschmod.get_mode(layout["dir"]) == 0o700
    assert oschmod.get_mode(layout["dir"] / "inner.txt") == 0o600


def test_follow_symlinks(layout):
    oschmod.set_mode_recursive(layout["tree"], 0o644, 0o755, follow_symlinks=True)
    assert oschmod.get_mode(layout["file"]) == 0o644
    assert oschmod.get_mode(layout["dir"]) == 0o755
    assert oschmod.get_mode(layout["dir"] / "inner.txt") == 0o644


def test_follow_symlinks_cycle_terminates(tmp_path):
    (tmp_path / "loop" / "d").mkdir(parents=True)
    _symlink(Path(".."), tmp_path / "loop" / "d" / "up", is_dir=True)
    calls: list[str] = []
    oschmod._walk_apply(str(tmp_path / "loop"), lambda p, _: calls.append(p), follow_symlinks=True)
    assert len(calls) == 2  # d and loop, each once


def test_root_symlink_is_followed(layout, tmp_path):
    root_link = tmp_path / "root_link"
    _symlink(layout["dir"], root_link, is_dir=True)
    oschmod.set_mode_recursive(root_link, 0o640, 0o750)
    assert oschmod.get_mode(layout["dir"] / "inner.txt") == 0o640


def test_error_raises_by_default(tmp_path):
    (tmp_path / "t").mkdir()
    _symlink(tmp_path / "nowhere", tmp_path / "t" / "dangling")
    with pytest.raises(FileNotFoundError):
        oschmod.set_mode_recursive(tmp_path / "t", 0o600, 0o700, follow_symlinks=True)


def test_on_error_continues(tmp_path):
    top = tmp_path / "t"
    for name in ("a", "z"):
        (top / name).mkdir(parents=True)
        (top / name / "f").write_text("x")
    _symlink(tmp_path / "nowhere", top / "m_dangling")
    errors: list[tuple[str, Exception]] = []
    oschmod.set_mode_recursive(
        top,
        0o600,
        0o700,
        follow_symlinks=True,
        on_error=lambda p, e: errors.append((p, e)),
    )
    assert [Path(p).name for p, _ in errors] == ["m_dangling"]
    for obj in (top / "a" / "f", top / "z" / "f"):
        assert oschmod.get_mode(obj) == 0o600
    for obj in (top, top / "a", top / "z"):
        assert oschmod.get_mode(obj) == 0o700


def test_invalid_mode_still_raises_with_on_error(tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "f").write_text("x")
    with pytest.raises(AttributeError):
        oschmod.set_mode_recursive(tmp_path / "t", "u+q", on_error=lambda *_: None)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory permissions")
def test_unlistable_directory_is_repaired(tmp_path):
    top = tmp_path / "t"
    (top / "locked").mkdir(parents=True)
    inner = top / "locked" / "inner"
    inner.write_text("x")
    inner.chmod(0o600)
    (top / "locked").chmod(0o000)
    try:
        oschmod.set_mode_recursive(top, "u+rwx,go=rx")
        assert oschmod.get_mode(top / "locked") == 0o755
        assert oschmod.get_mode(inner) == 0o755
    finally:
        (top / "locked").chmod(0o700)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory permissions")
def test_removing_search_permission_still_traverses(tmp_path):
    """Contents are changed before their directory, so -R 600 reaches every file."""
    top = tmp_path / "t"
    (top / "sub").mkdir(parents=True)
    (top / "sub" / "f").write_text("x")
    try:
        oschmod.set_mode_recursive(top, 0o600)
        top.chmod(0o700)
        (top / "sub").chmod(0o700)
        assert oschmod.get_mode(top / "sub" / "f") == 0o600
    finally:
        top.chmod(0o700)
        (top / "sub").chmod(0o700)


# --- CLI ---------------------------------------------------------------------


def test_cli_default_skips_symlinks(layout):
    assert oschmod.cli.main(["-R", "755", str(layout["tree"])]) == 0
    assert oschmod.get_mode(layout["file"]) == 0o600
    assert oschmod.get_mode(layout["dir"]) == 0o700


def test_cli_follow_all(layout):
    assert oschmod.cli.main(["-R", "-L", "755", str(layout["tree"])]) == 0
    assert oschmod.get_mode(layout["file"]) == 0o755
    assert oschmod.get_mode(layout["dir"] / "inner.txt") == 0o755


def test_cli_no_follow_root(layout, tmp_path):
    root_link = tmp_path / "root_link"
    _symlink(layout["dir"], root_link, is_dir=True)
    assert oschmod.cli.main(["-R", "-P", "755", str(root_link)]) == 0
    assert oschmod.get_mode(layout["dir"]) == 0o700
    assert oschmod.cli.main(["-R", "755", str(root_link)]) == 0  # -H default
    assert oschmod.get_mode(layout["dir"]) == 0o755


def test_cli_continues_after_error(tmp_path, capsys):
    top = tmp_path / "t"
    for name in ("a", "z"):
        (top / name).mkdir(parents=True)
        (top / name / "f").write_text("x")
    _symlink(tmp_path / "nowhere", top / "m_dangling")
    assert oschmod.cli.main(["-R", "-L", "700", str(top)]) == 1
    err = capsys.readouterr().err.splitlines()
    assert len(err) == 1
    assert err[0].startswith(f"oschmod: {top / 'm_dangling'}: ")
    for obj in (top / "a" / "f", top / "z" / "f", top / "a", top):
        assert oschmod.get_mode(obj) == 0o700


def test_cli_link_options_are_exclusive(capsys):
    with pytest.raises(SystemExit):
        oschmod.cli.main(["-R", "-L", "-P", "755", "."])
    assert "not allowed with" in capsys.readouterr().err
