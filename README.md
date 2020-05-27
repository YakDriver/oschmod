<p>
    <a href="./LICENSE" alt="License">
        <img src="https://img.shields.io/github/license/YakDriver/oschmod.svg" /></a>
    <a href="http://travis-ci.org/YakDriver/oschmod" alt="Build status">
        <img src="https://travis-ci.org/YakDriver/oschmod.svg?branch=master" /></a>
    <a href="https://pypi.python.org/pypi/oschmod" alt="Python versions">
        <img src="https://img.shields.io/pypi/pyversions/oschmod.svg" /></a>
    <a href="https://pypi.python.org/pypi/oschmod" alt="Version">
        <img src="https://img.shields.io/pypi/v/oschmod.svg" /></a>
    <img src="https://img.shields.io/endpoint.svg?url=https://gh.mergify.io/badges/YakDriver/oschmod" alt="Mergify"/>
</p>

# oschmod 

***oschmod*** sets consistent file permissions across Windows, Linux and macOS.

## TL;DR

Python includes `os.chmod()` to set read, write, and execute file permissions. However, on Windows, Python's `os.chmod()` basically has no effect. Even worse, Windows Python does not give a warning or error -- you think you've protected a file but you have not. In order to set the same file permissions across platforms, use ***oschmod***.

* Read more about [oschmod](https://medium.com/@dirk.avery/securing-files-on-windows-macos-and-linux-7b2b9899992) on Medium
* For more background, have a look at the [oschmod Wiki](https://github.com/YakDriver/oschmod/wiki).

## Installation

```console
$ pip install oschmod
```

## Command line interface

***oschmod*** brings the ability to set consistent file permissions using the command line to Windows, macOS, and Linux platforms. If you are familiar with `chmod` on Unix, Linux and/or macOS, ***oschmod*** works similarly, albeit with fewer options. 

```console
$ oschmod -h
usage: oschmod [-h] [-R] mode object

Change the mode (permissions) of a file or directory

positional arguments:
  mode        octal mode of the object
  object      file or directory

optional arguments:
  -h, --help  show this help message and exit
  -R          apply mode recursively
```

For example, to give everyone read, write, and execute permissions on a file, you can run this command:

```console
$ oschmod 777 file_name
```

You can also lock down a file to just give the file owner read, write, and execute permissions and deny any permissions to everyone else:

```console
$ oschmod 700 file_name
```

## Python Usage

You can use ***oschmod*** from Python code.

Replacing `os.chmod()` with ***oschmod*** is straightforward and you will get consistent file permissions on Windows, macOS, and Linux:

For example, this is an example of using `os.chmod()` in Python:

```python
import os
import stat
os.chmod('myfile', stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
```

On Linux or macOS, this gives a file's owner read, write, and execute permissions and denies the group and others any permissions (i.e., equivalent of `700`). On Windows, the best this command may have done is set the read-only attribute of the file. The read-only attribute restricts anyone from deleting, changing or renaming the file. The owner isn't given any permissions and the group and others are not denied any permissions. There is no consistency between the platforms.

However, using ***oschmod*** you can use the same command on Windows, macOS or Linux and get the same results:

```python
import oschmod
import stat
oschmod.set_mode('myfile', stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
```
