# -*- coding: utf-8 -*-
# pylint: disable=redefined-outer-name
"""test_oschmod module."""
import oschmod


def test_getowner():
    """Tests for stuff."""
    oschmod.display_permissions("this_file")
