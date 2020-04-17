# oschmod
Python chmod that works on Windows and Linux

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

Use ***oschmod*** to set permissions for files and directories on Windows, Linux and macOS. While Python's standard libraries include a simple command to do this on Linux and macOS (`os.chmod()`), the same command does not work on Windows.

* Read more about [oschmod](https://medium.com/faun/secure-files-with-python-on-windows-macos-and-linux-7b2b9899992) on Medium
* For more background, have a look at the [oschmod Wiki](https://github.com/YakDriver/oschmod/wiki).

## Usage

The problem is that on Linux and macOS, you can easily set distinct permissions for a file's owner, group, and all others. It takes one command and one mode, or, in other words, a number representing bitwise permissions for reading, writing, and executing. On Linux and macOS, you use the `os` module and `os.chmod()`.

Misleadingly, on Windows, `os.chmod()` does not have the same effect and does not give a warning or error. You think you've protected a file but you have not. 

For example, on Linux or macOS, to give a file owner read, write, and execute permissions and deny the group and others any permissions (i.e., equivalent of `700`), you can make a single call:

```python
import os
import stat
os.chmod('myfile', stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
```

Running the same command on Windows does not achieve the same results. The owner isn't given any permissions and the group and others are not denied any permissions. All you can do is restrict anyone from deleting, changing or renaming the file. That's nothing like what `os.chmod()` does.

However, using ***oschmod*** you can use the same command on Windows, macOS or Linux and get the same results:

```python
import oschmod
oschmod.set_mode('myfile', stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
```

## Installation

```console
$ pip install oschmod
```
