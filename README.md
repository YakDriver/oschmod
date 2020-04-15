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

With ***oschmod***, on Windows and Linux, you can use stat modes (permissions) for files and directories. Python's `os.chmod()` does not work properly on Windows, only setting the read-only bit.

For example, on Linux, you can easily give a file owner read, write, and execute permissions, and deny the group and others any permissions (i.e., equivalent of `700`). You can do it like:

```python
import os
import stat
os.chmod('myfile', stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
```

Running the same command on Windows does not achieve the same results, such as the group and others are not denied permissions.

However, using ***oschmod*** you can use the same command on Windows or Linux and get the same results:

```python
import oschmod
oschmod.set_mode('myfile', stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
```

## Installation

```console
$ pip install oschmod
```
