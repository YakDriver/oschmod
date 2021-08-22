"""Unit tests for operations that might fail due to using Pathlib"""

import mock
import pytest

import oschmod

@mock.patch('oschmod._win_get_permissions')
@mock.patch('oschmod._win_transform_pathlib_to_str')
def test_win_get_permissions(transform_mock, get_permissions_mock):
    oschmod.win_get_permissions('.')

    transform_mock.assert_called_once_with('.')


@mock.patch('oschmod._win_set_permissions')
@mock.patch('oschmod._win_transform_pathlib_to_str')
def test_win_set_permissions(transform_mock, set_permissions_mock):
    oschmod.win_set_permissions('.', "mock_mode")

    transform_mock.assert_called_once_with('.')


@mock.patch('oschmod.sys')
def test_win_transform_pathlib_to_str_negative_py26(mock_sys):
    """Tests versions that do not support pathlib throws an exception.
    py26 sys.version_info implemented different from >py26"""

    mock_sys.version = '2.6.0'

    with pytest.raises(RuntimeError, match='Pathlib not supported for <py34.'):
        oschmod._win_transform_pathlib_to_str('mock_path')

    mock_sys.version_info.assert_not_called()


@pytest.mark.parametrize(
    'major_version, minor_version',
    [(2, 7), (2, 9), (3, 2), (3, 3)],
)
@mock.patch('oschmod.sys')
def test_win_transform_pathlib_to_str_negative(
    mock_sys, major_version, minor_version
):
    """Tests versions that do not support pathlib throws an exception.
    py27 is the only supported version by lib, but testing other edge
    cases as well
    """
    mock_sys.version = '{}.{}'.format(major_version, minor_version)
    mock_sys.version_info.major = major_version
    mock_sys.version_info.minor = minor_version

    with pytest.raises(RuntimeError, match='Pathlib not supported for <py34.'):
        oschmod._win_transform_pathlib_to_str('mock_path')


@pytest.mark.parametrize(
    'major_version, minor_version',
    [(3, 5), (3, 6), (3, 7), (3, 8)],
)
@mock.patch('oschmod.sys')
def test_win_transform_pathlib_to_str_positive(
    mock_sys, major_version, minor_version
):
    """Tests pathlib is transformed into a string for windows for
    supported versions."""
    mock_sys.version = '{}.{}'.format(major_version, minor_version)
    mock_sys.version_info.major = major_version
    mock_sys.version_info.minor = minor_version

    actual_path = oschmod._win_transform_pathlib_to_str('mock_path')

    assert actual_path == 'mock_path'
