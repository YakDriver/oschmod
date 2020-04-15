# -*- coding: utf-8 -*-
# pylint: disable=redefined-outer-name
"""test_oschmod module."""
import glob
import os
import random
import stat
import string

import oschmod


def test_permissions():
    """Tests for stuff."""
    test_dir = "tests"
    path = os.path.join(test_dir, ''.join(
        random.choice(string.ascii_letters) for i in range(10)) + '.txt')
    file_hdl = open(path, 'w+')
    file_hdl.write(path)
    file_hdl.close()
    oschmod.set_mode(path, stat.S_IRUSR | stat.S_IWUSR)
    assert oschmod.get_mode(path) == stat.S_IRUSR | stat.S_IWUSR

    path = os.path.join(test_dir, ''.join(
        random.choice(string.ascii_letters) for i in range(10)) + '.txt')
    file_hdl = open(path, 'w+')
    file_hdl.write(path)
    file_hdl.close()
    mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | \
        stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH
    oschmod.set_mode(path, mode)
    assert oschmod.get_mode(path) == mode

    path = os.path.join(test_dir, ''.join(
        random.choice(string.ascii_letters) for i in range(10)) + '.txt')
    file_hdl = open(path, 'w+')
    file_hdl.write(path)
    file_hdl.close()
    mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | \
        stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IWOTH | \
        stat.S_IXOTH
    oschmod.set_mode(path, mode)
    assert oschmod.get_mode(path) == mode

    file_list = glob.glob(os.path.join(test_dir, "*txt"))
    for file_path in file_list:
        try:
            os.remove(file_path)
        except FileNotFoundError:
            print("Error while deleting file : ", file_path)
