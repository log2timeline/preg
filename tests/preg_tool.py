#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Tests for the preg tool."""

import unittest

from plaso.lib import errors

from l2tpreg import preg_tool

from tests import test_lib


class PregToolTest(test_lib.CLIToolTestCase):
  """Tests for the preg tool."""

  def _ExtractPluginsAndKey(self, string):
    """Takes a string and returns two sets with names of plugins and keys.

    Args:
      string: a string containing the full output from preg that contains
              headings and results.

    Returns:
      Two sets, plugins and registry_keys. The set plugins contains a list
      of all plugins that were found in the output string and the registry_key
      extracts a list of all Registry keys that were parsed in the supplied
      string.
    """
    # TODO: refactor to more accurate way to test this.
    plugins = set()
    registry_keys = set()

    for line in string.split(b'\n'):
      line = line.lstrip()

      if b'** Plugin' in line:
        _, _, plugin_name_line = line.rpartition(b':')
        plugin_name, _, _ = plugin_name_line.partition(b'*')
        plugins.add(plugin_name.strip())

      if b'Key Path :' in line:
        _, _, key_name = line.rpartition(b':')
        registry_keys.add(key_name.strip())

    return plugins, registry_keys

  def setUp(self):
    """Sets up the needed objects used throughout the test."""
    self._output_writer = test_lib.TestOutputWriter(encoding=u'utf-8')
    self._test_tool = preg_tool.PregTool(output_writer=self._output_writer)

  def testParseOptions(self):
    """Tests the ParseOptions function."""
    options = test_lib.TestOptions()
    options.foo = u'bar'

    with self.assertRaises(errors.BadConfigOption):
      self._test_tool.ParseOptions(options)

    options = test_lib.TestOptions()
    options.registry_file = u'this_path_does_not_exist'

    with self.assertRaises(errors.BadConfigOption):
      self._test_tool.ParseOptions(options)

  def testListPluginInformation(self):
    """Tests the ListPluginInformation function."""
    options = test_lib.TestOptions()
    options.show_info = True

    self._test_tool.ParseOptions(options)

    self._test_tool.ListPluginInformation()

    output = self._output_writer.ReadOutput()

    # TODO: refactor to more accurate way to test this.
    self.assertIn(b'* Supported Plugins *', output)
    self.assertIn(b'userassist : Parser for User Assist Registry data', output)
    # TODO: how is this supposed to work since windows_services does not have
    # an explicit key path defined.
    # self.assertIn(
    #     b'windows_services : Parser for services and drivers', output)

  def testPrintHeader(self):
    """Tests the PrintHeader function."""
    self._test_tool.PrintHeader(u'Text')
    string = self._output_writer.ReadOutput()
    expected_string = (
        b'\n'
        b'************************************* '
        b'Text '
        b'*************************************\n')
    self.assertEqual(string, expected_string)

    self._test_tool.PrintHeader(u'Another Text', character=u'x')
    string = self._output_writer.ReadOutput()
    expected_string = (
        b'\n'
        b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx '
        b'Another Text '
        b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n')
    self.assertEqual(string, expected_string)

    # TODO: determine if this is the desired behavior.
    self._test_tool.PrintHeader(u'')
    string = self._output_writer.ReadOutput()
    expected_string = (
        b'\n'
        b'*************************************** '
        b' '
        b'***************************************\n')
    self.assertEqual(string, expected_string)

    # TODO: determine if this is the desired behavior.
    self._test_tool.PrintHeader(None)
    string = self._output_writer.ReadOutput()
    expected_string = (
        b'\n'
        b'************************************* '
        b'None '
        b'*************************************\n')
    self.assertEqual(string, expected_string)

    # TODO: determine if this is the desired behavior.
    expected_string = (
        u'\n '
        u'In computer programming, a string is traditionally a sequence '
        u'of characters, either as a literal constant or as some kind of '
        u'variable. \n')
    self._test_tool.PrintHeader(expected_string[2:-2])
    string = self._output_writer.ReadOutput()
    self.assertEqual(string, expected_string)

  def testRunModeRegistryPlugin(self):
    """Tests the RunModeRegistryPlugin function."""
    options = test_lib.TestOptions()
    options.registry_file = self._GetTestFilePath([u'NTUSER.DAT'])
    options.plugin_names = u'userassist'
    options.verbose = False

    self._test_tool.ParseOptions(options)

    self._test_tool.RunModeRegistryPlugin()

    output = self._output_writer.ReadOutput()

    # TODO: refactor to more accurate way to test this.
    expected_string = (
        b'UEME_RUNPATH:C:\\Program Files\\Internet Explorer\\iexplore.exe')
    self.assertIn(expected_string, output)

    # TODO: Add tests that parse a disk image. Test both Registry key parsing
    # and plugin parsing.

  def testRunModeRegistryKey(self):
    """Tests the RunModeRegistryKey function."""
    options = test_lib.TestOptions()
    options.key = (
        u'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion')
    options.parser_names = u''
    options.registry_file = self._GetTestFilePath([u'SOFTWARE'])
    options.verbose = False

    self._test_tool.ParseOptions(options)

    self._test_tool.RunModeRegistryKey()

    output = self._output_writer.ReadOutput()

    # TODO: refactor to more accurate way to test this.
    self.assertIn(b'Product name : Windows 7 Ultimate', output)

  def testRunModeRegistryFile(self):
    """Tests the RunModeRegistryFile function."""
    options = test_lib.TestOptions()
    options.registry_file = self._GetTestFilePath([u'SOFTWARE'])

    self._test_tool.ParseOptions(options)

    self._test_tool.RunModeRegistryFile()

    output = self._output_writer.ReadOutput()

    plugins, registry_keys = self._ExtractPluginsAndKey(output)

    # Define the minimum set of plugins that need to be in the output.
    # This information is gathered from the actual tool output, which
    # for aesthetics reasons surrounds the text with **. The above processing
    # then cuts of the first half of that, but leaves the second ** intact.
    expected_plugins = set([
        b'msie_zone',
        b'windows_run',
        b'windows_task_cache',
        b'windows_version'])

    self.assertTrue(expected_plugins.issubset(plugins))

    self.assertIn((
        b'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\'
        b'CurrentVersion\\Schedule\\TaskCache'), registry_keys)
    self.assertIn((
        b'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\'
        b'CurrentVersion\\Run'), registry_keys)
    self.assertIn((
        b'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\'
        b'CurrentVersion\\Internet Settings\\Lockdown_Zones'), registry_keys)

    # The output should grow with each newly added plugin, and it might be
    # reduced with changes to the codebase, yet there should be at least 1.400
    # lines in the output.
    line_count = 0
    for _ in output:
      line_count += 1
    self.assertGreater(line_count, 1400)


if __name__ == '__main__':
  unittest.main()
