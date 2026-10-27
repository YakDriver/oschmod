"""pathlib / os.PathLike support (issue #111).

Idea and original fix by @zapplecat in PR #112.
"""

from pathlib import Path

import pytest

import oschmod


@pytest.fixture
def file_path(tmp_path: Path) -> Path:
    path = tmp_path / "file.txt"
    path.write_text("x")
    return path


def test_get_and_set_mode_with_path(file_path):
    oschmod.set_mode(file_path, 0o600)
    assert oschmod.get_mode(file_path) == 0o600


def test_symbolic_with_path(file_path):
    oschmod.set_mode(file_path, 0o600)
    oschmod.set_mode(file_path, "u+x,g+r")
    assert oschmod.get_mode(file_path) == 0o740


def test_recursive_with_path(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "f").write_text("x")
    oschmod.set_mode_recursive(tmp_path / "sub", 0o600, 0o700)
    assert oschmod.get_mode(tmp_path / "sub") == 0o700
    assert oschmod.get_mode(tmp_path / "sub" / "f") == 0o600


def test_object_type_with_path(file_path):
    assert oschmod.get_object_type(file_path) == oschmod.FILE
    assert oschmod.get_object_type(file_path.parent) == oschmod.DIRECTORY


def test_owner_group_with_path(file_path):
    assert oschmod.get_owner(file_path)
    assert oschmod.get_group(file_path)


def test_print_obj_info_with_path(file_path, capsys):
    oschmod.print_obj_info(file_path)
    assert str(file_path) in capsys.readouterr().out


def test_bytes_path_rejected(file_path):
    with pytest.raises(TypeError):
        oschmod.get_mode(bytes(file_path))
