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

from random import randrange

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

    mode_dir1 = oschmod.get_mode(topdir)
    mode_dir2 = oschmod.get_mode(os.path.join(topdir, 'testdir2'))
    mode_dir3 = oschmod.get_mode(testdir)
    mode_file1 = oschmod.get_mode(os.path.join(topdir, 'file1'))
    mode_file2 = oschmod.get_mode(os.path.join(testdir, 'file2'))

    # clean up
    shutil.rmtree(topdir)

    # check it out
    assert mode_dir1 == dir_mode
    assert mode_dir2 == dir_mode
    assert mode_dir3 == dir_mode
    assert mode_file1 == file_mode
    assert mode_file2 == file_mode


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

    # randomly chosen starting permission = 359
    assert oschmod.get_effective_mode(0b101100111, "go=") == 0b101000000
    assert oschmod.get_effective_mode(0b101100111, "ugo=") == 0b000000000
    assert oschmod.get_effective_mode(0b101100111, "ugo=rwx") == 0b111111111
    assert oschmod.get_effective_mode(0b101100111, "uo=w") == 0b010100010
    assert oschmod.get_effective_mode(0b101100111, "=w") == 0b010010010
    assert oschmod.get_effective_mode(0b101100111, "uo=wx") == 0b011100011
    assert oschmod.get_effective_mode(0b101100111, "u=r") == 0b100100111


def generate_symbolic():
    """Generate one symbolic representation of a mode modifier."""
    who = randrange(8)
    whom = ((who & 0b100 > 0 and "u") or "") + \
        ((who & 0b010 > 0 and "g") or "") + \
        ((who & 0b001 > 0 and "o") or "")
    oper = randrange(3)
    operation = ((oper == 0 and "+") or "") + \
        ((oper == 1 and "-") or "") + \
        ((oper == 2 and "=") or "")
    perm = randrange(8)
    perms = ((perm & 0b100 > 0 and "r") or "") + \
        ((perm & 0b010 > 0 and "w") or "") + \
        ((perm & 0b001 > 0 and "x") or "")
    return whom + operation + perms


def generate_case(prefix, suffix):
    """Generate a test case to be solved manually."""
    symbolic = [generate_symbolic() for _ in range(randrange(1, 4))]
    symbolics = ",".join(symbolic)
    return "{0:s}0b{1:09b}, \"{2:s}\"{3:s} == 0b{1:09b}".format(
        prefix,
        randrange(512),
        symbolics,
        suffix
    )


def generate_cases(count):
    """Generate test cases to be solved manually and added to tests."""
    prefix = "assert oschmod.get_effective_mode("
    suffix = ")"
    cases = [generate_case(prefix, suffix) for _ in range(count)]
    print("\n".join(cases))


def test_symbolic_multiples():
    """Check calculation of effective mode from symbolic."""
    assert oschmod.get_effective_mode(0b000101010, "g-rwx,go=") == 0b000000000
    assert oschmod.get_effective_mode(0b011001011, "uo-wx,u=x") == 0b001001000
    assert oschmod.get_effective_mode(0b111101000, "u=rwx,o=x") == 0b111101001
    assert oschmod.get_effective_mode(0b110101001, "+r,ug=rx") == 0b101101101
    assert oschmod.get_effective_mode(
        0b010010000, "go-,go+,u+rw") == 0b110010000
    assert oschmod.get_effective_mode(0b000101110, "ug-rw,go=x") == 0b000001001
    assert oschmod.get_effective_mode(
        0b010110000, "=rwx,=rw,ug-") == 0b110110110
    assert oschmod.get_effective_mode(
        0b010001111, "o-rwx,o=rwx,ug-x") == 0b010000111
    assert oschmod.get_effective_mode(
        0b100111011, "u-r,o=rwx,ug-wx") == 0b000100111
    assert oschmod.get_effective_mode(
        0b111110101, "o=rwx,ugo-,g=rx") == 0b111101111
    assert oschmod.get_effective_mode(0b010010000, "u=rx") == 0b101010000
    assert oschmod.get_effective_mode(0b001011111, "=") == 0b000000000
    assert oschmod.get_effective_mode(0b100011010, "ug-w,uo=rw") == 0b110001110
    assert oschmod.get_effective_mode(0b111001001, "ug=rw,g-wx") == 0b110100001
    assert oschmod.get_effective_mode(
        0b111000000, "u-,uo+rx,go+x") == 0b111001101
    assert oschmod.get_effective_mode(0b000000000, "u=rx,uo-x") == 0b100000000
    assert oschmod.get_effective_mode(0b101110101, "uo=rx") == 0b101110101
    assert oschmod.get_effective_mode(
        0b111111010, "g-wx,ug=,-x") == 0b000000010
    assert oschmod.get_effective_mode(0b100011000, "uo+rw") == 0b110011110
    assert oschmod.get_effective_mode(
        0b011111000, "ugo+,uo+w,-rwx") == 0b000000000
    assert oschmod.get_effective_mode(
        0b000010100, "ug=x,ug=x,g-rx") == 0b001000100
    assert oschmod.get_effective_mode(0b110101101, "g=rwx") == 0b110111101
    assert oschmod.get_effective_mode(0b000010111, "=wx") == 0b011011011
    assert oschmod.get_effective_mode(
        0b000111011, "u-rw,uo-x,o+wx") == 0b000111011
    assert oschmod.get_effective_mode(0b010110000, "uo+,u+") == 0b010110000
    assert oschmod.get_effective_mode(
        0b000111110, "go=x,ug+x,uo=rx") == 0b101001101
    assert oschmod.get_effective_mode(0b011101111, "o+wx") == 0b011101111
    assert oschmod.get_effective_mode(
        0b001001011, "u-,go+w,ugo=w") == 0b010010010
    assert oschmod.get_effective_mode(0b110110100, "u=w,=x") == 0b001001001
    assert oschmod.get_effective_mode(
        0b110011100, "u=w,ug-rwx,uo+rwx") == 0b111000111
    assert oschmod.get_effective_mode(0b100101001, "go-r") == 0b100001001
    assert oschmod.get_effective_mode(
        0b110100110, "uo=r,ug+rx,ugo=") == 0b000000000
    assert oschmod.get_effective_mode(0b101100000, "go=wx,o-") == 0b101011011
    assert oschmod.get_effective_mode(0b111111101, "-r,o=r,o-w") == 0b011011100
    assert oschmod.get_effective_mode(0b110101000, "uo-rx,+rwx") == 0b111111111
    assert oschmod.get_effective_mode(0b101011111, "go=wx") == 0b101011011
    assert oschmod.get_effective_mode(
        0b110110010, "go+x,ugo-w,u+rwx") == 0b111101001
    assert oschmod.get_effective_mode(0b001100101, "=rx,-rwx") == 0b000000000
    assert oschmod.get_effective_mode(0b001010011, "uo=x") == 0b001010001
    assert oschmod.get_effective_mode(
        0b011101110, "ugo-rx,uo+rw,uo-rw") == 0b000000000


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
    oschmod.set_mode_recursive(topdir, "u=rw,go=", "u=rwx,go=")
    time.sleep(1)  # modes aren't always ready to go immediately

    dir_mode = 0o700
    file_mode = 0o600

    mode_dir1 = oschmod.get_mode(topdir)
    mode_dir2 = oschmod.get_mode(os.path.join(topdir, 'testdir2'))
    mode_dir3 = oschmod.get_mode(testdir)
    mode_file1 = oschmod.get_mode(os.path.join(topdir, 'file1'))
    mode_file2 = oschmod.get_mode(os.path.join(testdir, 'file2'))

    # clean up
    shutil.rmtree(topdir)

    # check it out
    assert mode_dir1 == dir_mode
    assert mode_dir2 == dir_mode
    assert mode_dir3 == dir_mode
    assert mode_file1 == file_mode
    assert mode_file2 == file_mode
