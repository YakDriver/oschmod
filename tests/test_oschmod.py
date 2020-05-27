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


def test_symbolic_use():
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
    triple7 = "+rwx"
    oschmod.set_mode(topdir, triple7)
    oschmod.set_mode(testdir, triple7)
    oschmod.set_mode(os.path.join(topdir, 'file1'), triple7)
    oschmod.set_mode(os.path.join(testdir, 'file2'), triple7)
    time.sleep(1)  # modes aren't always ready to go immediately

    # set permissions - the test
    oschmod.set_mode_recursive(topdir, "u=rw,go-rwx", "u+rwx,go-rwx")
    time.sleep(1)  # modes aren't always ready to go immediately

    # check it out
    assert oschmod.get_mode(topdir) == 0o700
    assert oschmod.get_mode(os.path.join(topdir, 'testdir2')) == 0o700
    assert oschmod.get_mode(testdir) == 0o700
    assert oschmod.get_mode(os.path.join(topdir, 'file1')) == 0o600
    assert oschmod.get_mode(os.path.join(testdir, 'file2')) == 0o600

    # clean up
    shutil.rmtree(topdir)
