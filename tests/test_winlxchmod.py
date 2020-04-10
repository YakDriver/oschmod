# -*- coding: utf-8 -*-
# pylint: disable=redefined-outer-name
"""test_winlxchmod module."""
import winlxchmod


def test_getowner():
    """Tests for stuff."""
    winlxchmod.display_permissions("this_file")
