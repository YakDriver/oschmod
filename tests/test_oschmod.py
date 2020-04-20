# -*- coding: utf-8 -*-
# pylint: disable=redefined-outer-name
"""test_oschmod module."""
import glob
import os
import random
import shutil
import stat
import string
import time

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


def test_set_recursive():
    """Check file permissions are recursively set."""
    # create dirs
    topdir = 'testdir1'
    testdir = os.path.join(topdir, 'testdir2', 'testdir3')
    os.makedirs(testdir)

    # create files
    fileh = open(os.path.join(topdir, 'file1'), "w+")
    fileh.write("contents")
    fileh.close()

    fileh = open(os.path.join(testdir, 'file2'), "w+")
    fileh.write("contents")
    fileh.close()

    # set permissions to badness
    triple7 = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP\
        | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IWOTH\
        | stat.S_IXOTH
    oschmod.set_mode(topdir, triple7)
    oschmod.set_mode(testdir, triple7)
    oschmod.set_mode(os.path.join(topdir, 'file1'), triple7)
    oschmod.set_mode(os.path.join(testdir, 'file2'), triple7)
    time.sleep(1)  # modes aren't always ready to go immediately

    # set permissions - the test
    file_mode = 0o600
    dir_mode = 0o700
    oschmod.set_mode_recursive(topdir, file_mode, dir_mode)
    time.sleep(1)  # modes aren't always ready to go immediately

    # check it out
    assert oschmod.get_mode(topdir) == dir_mode
    assert oschmod.get_mode(os.path.join(topdir, 'testdir2')) == dir_mode
    assert oschmod.get_mode(testdir) == dir_mode
    assert oschmod.get_mode(os.path.join(topdir, 'file1')) == file_mode
    assert oschmod.get_mode(os.path.join(testdir, 'file2')) == file_mode

    # clean up
    shutil.rmtree(topdir)
