#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Tests for the list of plaso Windows Registry plugins."""

import unittest

from l2tpreg import plugin_list

from tests import test_lib


class PluginListTest(test_lib.BaseTestCase):
  """Tests for the list of plaso Windows Registry plugins."""

  def testInitialize(self):
    """Tests the __init__ function."""
    test_list = plugin_list.PluginList()
    self.assertIsNotNone(test_list)

  # TODO: add tests for __iter__
  # TODO: add tests for _GetPluginsByType
  # TODO: add tests for AddPlugin
  # TODO: add tests for GetAllPlugins
  # TODO: add tests for GetKeyPaths
  # TODO: add tests for GetKeyPathsFromPlugin
  # TODO: add tests for GetPluginObjectByName
  # TODO: add tests for GetPluginObjects
  # TODO: add tests for GetPlugins
  # TODO: add tests for GetRegistryPlugins
  # TODO: add tests for GetRegistryTypes
  # TODO: add tests for GetRegistryTypesFromPlugins
  # TODO: add tests for GetRegistryPluginsFromRegistryType


if __name__ == '__main__':
  unittest.main()
