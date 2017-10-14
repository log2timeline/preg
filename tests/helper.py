#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Tests for the Windows Registry helper."""

import unittest

from l2tpreg import helper

from tests import test_lib


class PregRegistryHelperTest(test_lib.BaseTestCase):
  """Tests for the Windows Registry helper."""

  def testInitialize(self):
    """Tests the __init__ function."""
    test_helper = helper.PregRegistryHelper(None, None)
    self.assertIsNotNone(test_helper)

  # TODO: add tests for __enter__.
  # TODO: add tests for __exit__.
  # TODO: add tests for properties.
  # TODO: add tests for _Reset.
  # TODO: add tests for ChangeKeyByPath.
  # TODO: add tests for GetCurrentRegistryKey.
  # TODO: add tests for GetCurrentRegistryPath.
  # TODO: add tests for GetKeyByPath.
  # TODO: add tests for GetRegistryFileType.
  # TODO: add tests for Open and Close.


if __name__ == '__main__':
  unittest.main()
