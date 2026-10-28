<p>
    <a href="./LICENSE" alt="License">
        <img src="https://img.shields.io/github/license/YakDriver/oschmod.svg" /></a>
    <a href="https://github.com/YakDriver/oschmod/actions/workflows/ci.yml" alt="Build status">
        <img src="https://github.com/YakDriver/oschmod/actions/workflows/ci.yml/badge.svg?branch=main" /></a>
    <a href="https://pypi.python.org/pypi/oschmod" alt="Python versions">
        <img src="https://img.shields.io/pypi/pyversions/oschmod.svg" /></a>
    <a href="https://pypi.python.org/pypi/oschmod" alt="Version">
        <img src="https://img.shields.io/pypi/v/oschmod.svg" /></a>
</p>

# oschmod

***oschmod*** sets consistent file permissions across Windows, Linux and macOS.

## oschmod TL;DR

***oschmod*** brings `chmod` functionality to **Windows**, macOS, and Linux! If you're not familiar, `chmod` is a handy macOS and Linux-only tool for setting file permissions.

Prior to ***oschmod***, Windows file permissions couldn't be set in the familiar `chmod` way. Tools did not translate `chmod`-style permissions into Windows-style file permissions. Even though Python's `os.chmod()` sets read, write, and execute file permissions, on Windows, `os.chmod()` basically has no effect. Even worse, Python on Windows gives no warnings or errors. If you think you set file permissions on Windows with `os.chmod()`, you're wrong!

***oschmod*** allows you to set consistent file permissions in a consistent way across platforms.

* Read more about [oschmod](https://medium.com/@dirk.avery/securing-files-on-windows-macos-and-linux-7b2b9899992) on Medium
* For more background, have a look at the [oschmod Wiki](https://github.com/YakDriver/oschmod/wiki).

## Installation

```console
$ pip install oschmod
```

Or with conda:

```console
$ conda install -c conda-forge oschmod
```

***oschmod*** requires Python 3.11 or newer. On Windows, it depends on `pywin32`, which is installed automatically.

## GNU Documentation

***oschmod*** changes the file mode bits of each given file according to mode, which can be either a symbolic representation of changes to make, or an octal number representing the bit pattern for the new mode bits.

The format of a symbolic mode is `[ugoa...][+-=][perms...]` where perms is zero or more letters from the set `rwx`. Multiple symbolic modes can be given, separated by commas.

A combination of the letters `ugoa` controls which users' access to the file will be changed: the user who owns it (`u`), other users in the file's group (`g`), other users not in the file's group (`o`), or all users (`a`). If none of these are given, the effect is as if `a` were given.

*(Modified from the GNU manpage for chmod.)*

## Command line interface

***oschmod*** brings the ability to set consistent file permissions using the command line to Windows, macOS, and Linux platforms. If you are familiar with `chmod`, ***oschmod*** works similarly, albeit with fewer options.

```console
$ oschmod -h
usage: oschmod [-h] [-R] [-v] [--other-sid SID] [--version] mode object

Change the mode (permissions) of a file or directory

positional arguments:
  mode             octal or symbolic mode of the object
  object           file or directory

options:
  -h, --help       show this help message and exit
  -R               apply mode recursively
  -v               verbose: show each object as its mode is set; repeat (-vv)
                   to also show old and new modes
  --other-sid SID  Windows only: SID that receives "other" permissions
                   (default: S-1-5-32-545, the built-in Users group)
  --version        show program's version number and exit
```

You can also run it as `python -m oschmod`.

## Command line examples

You can use symbolic (e.g., "u+rw") or octal (e.g., "600") representations of modes. Multiple mode modifications can be made in a single call by separating modifiers with commas.

### Symbolic representation examples

Symbolic representation mode modifiers have three parts:

1. **whom:** To whom does the modification apply? You can include zero or more of `[ugoa]*` where `a` is for all, `u` is for the file owner (i.e., "**u**ser"), `g` is for the file group, and `o` is for others. In other words, `ugo` is equivalent to `a`. Also, if you do not provide a "whom," ***oschmod*** assumes you mean `a` (everyone).
2. **operation:** Which operation should be applied? You must include one and only one operation, `[+-=]{1}`, per modifier (although you can have multiple modifiers). `+` adds permissions, `-` removes permissions, and `=` sets permissions regardless of previous permissions. `+` and `-` modifications often depend on the current permissions.
3. **permission:** Which permission or permissions will be affected? You can include zero or more of `[rwx]*` where `r` is for read, `w` is for write, and `x` is for execute. If you do not include a permission with `+` or `-` (e.g., `u-`), the modifier has no effect. However, if you use no permissions with `=` (e.g., `o=`), all permissions are removed.

**Example 1:** To give everyone execute permissions on a file (all of these are equivalent):

```console
$ oschmod +x <file name>
$ oschmod a+x <file name>
$ oschmod ugo+x <file name>
```

**Example 2:** To remove read, write, and execute permissions from the file group and all others (these are equivalent):

```console
$ oschmod go-rwx <file name>
$ oschmod go= <file name>
```

**Example 3:** To give the file owner read and execute permissions, and remove execute permissions from the group and all others:

```console
$ oschmod u+rx,go-x <file name>
```

**Example 4:** To give everyone all permissions, and then remove execute write from the group, and execute from all others:

```console
$ oschmod a+rwx,g-w,o-x <file name>
```

### Octal representation examples

For more about what octal representations mean, see [this article](https://medium.com/@dirk.avery/securing-files-on-windows-macos-and-linux-7b2b9899992) on Medium.

**Example 5:** To give everyone read, write, and execute permissions on a file:

```console
$ oschmod 777 <file name>
```

**Example 6:** To lock down a file to just give the file owner read, write, and execute permissions and deny all permissions to everyone else:

```console
$ oschmod 700 <file name>
```

### Verbose output

**Example 7:** Show each object as its mode is set (`-v`), or show old and new modes too (`-vv`):

```console
$ oschmod -vv 600 secrets.txt
secrets.txt: 0o644 (rw-r--r--) -> 0o600 (rw-------)
```

## Python usage

You can use ***oschmod*** from Python code. Any of the command line examples above will work very similarly. For example, *Example 4* above, in Python code, would look like this:

```python
import oschmod

oschmod.set_mode("myfile", "a+rwx,g-w,o-x")
```

*Example 5* above, in Python code, could be done in two ways:

```python
import oschmod

oschmod.set_mode("myfile", "777")
oschmod.set_mode("myfile", 0o777)
```

***oschmod*** is compatible with bitwise permissions as defined in the `stat` module. To give a file's owner read, write, and execute permissions and deny the group and others any permissions (i.e., equivalent of `700`):

```python
import oschmod
import stat

oschmod.set_mode("myfile", stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
```

Replacing `os.chmod()` with ***oschmod*** should usually be an easy drop-in replacement. Replacement will allow you to get consistent file permission settings on Windows, macOS, and Linux:

If this is your Python code using `os.chmod()`:

```python
import os

os.chmod("myfile1", "u+x")
os.chmod("myfile2", 0o777)
```

The replacement using ***oschmod*** is very similar:

```python
import oschmod

oschmod.set_mode("myfile1", "u+x")
oschmod.set_mode("myfile2", 0o777)
```

`get_mode()` returns only the read/write/execute bits (`0o777`). On macOS and Linux, use `get_full_mode()` to also include set-user-ID, set-group-ID, and sticky bits (`0o7777`). Symbolic modes such as `g+w` change only read/write/execute bits and leave those special bits as they are.

Paths can be strings or any path-like object, such as `pathlib.Path`:

```python
from pathlib import Path

import oschmod

oschmod.set_mode(Path("myfile"), 0o600)
```

## Windows notes

Windows has no owner/group/other mode bits, so ***oschmod*** maps them to ACL entries:

* **Owner** is the file's owner SID, and **group** is the file's primary group SID.
* **Others** is the built-in *Users* group (`S-1-5-32-545`) by default. To use a different account, pass `other_sid` (for example, `"S-1-5-11"` for *Authenticated Users*). In Python, use `oschmod.set_mode(path, "o+r", other_sid="S-1-5-11")`; on the command line, use `--other-sid S-1-5-11`.
* Setting a mode replaces the object's DACL with explicit entries and marks it **protected**, so permissions are no longer inherited from the parent folder, including after later changes to the parent. Any existing entry for the local SYSTEM account is kept.
* Set-user-ID, set-group-ID, and sticky bits have no Windows equivalent and are ignored there.
* `ACCESS_DENIED` entries are not considered when reading a mode.
