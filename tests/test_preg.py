#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the preg front-end."""

from __future__ import unicode_literals

import unittest

from l2tpreg import helper
from l2tpreg import preg_tool

from scripts import preg

from tests import test_lib


class PregConsoleTest(test_lib.CLIToolTestCase):
  """Tests for the preg console."""

  # pylint: disable=protected-access

  _EXPECTED_BANNER_HEADER = [
      b'',
      b'Welcome to PREG - home of the Plaso Windows Registry Parsing.',
      b'',
      (b'****************************** Available commands '
       b'******************************'),
      b'                 Function : Description',
      (b'----------------------------------------------------------------------'
       b'----------'),
      (b'                   cd key : Navigate the Registry like a directory '
       b'structure.'),
      (b'                  ls [-v] : List all subkeys and values of a Registry '
       b'key. If'),
      (b'                            called as ls True then values of '
       b'keys will be'),
      b'                            included in the output.',
      b'               parse -[v] : Parse the current key using all plugins.',
      (b'  plugin [-h] plugin_name : Run a particular key-based plugin on the '
       b'loaded'),
      (b'                            hive. The correct Registry key will '
       b'be loaded,'),
      b'                            opened and then parsed.',
      (b'     get_value value_name : Get a value from the currently loaded '
       b'Registry key.'),
      (b'get_value_data value_name : Get a value data from a value stored in '
       b'the'),
      b'                            currently loaded Registry key.',
      b'                  get_key : Return the currently loaded Registry key.',
      (b'---------------------------------------------------------------------'
       b'-----------')]

  _EXPECTED_BANNER_FOOTER = b'Happy command line console fu-ing.'

  def setUp(self):
    """Sets up the needed objects used throughout the test."""
    self._output_writer = test_lib.TestOutputWriter(encoding='utf-8')
    self._test_tool = preg_tool.PregTool(output_writer=self._output_writer)
    self._test_console = preg.PregConsole(self._test_tool)
    file_entry = self._GetTestFileEntry(['NTUSER.DAT'])
    self._file_path = self._GetTestFilePath(['NTUSER.DAT'])
    self._registry_helper = helper.PregRegistryHelper(file_entry, 'OS')

  def tearDown(self):
    """Tears down the needed objects after a test."""
    self._registry_helper.Close()

  def testAddRegistryHelpers(self):
    """Test the add registry helper."""
    self._test_console.AddRegistryHelper(self._registry_helper)
    registry_helpers = getattr(self._test_console, '_registry_helpers', [])

    self.assertEqual(len(registry_helpers), 1)
    setattr(self._test_console, '_registry_helpers', [])

  def testPrintBanner(self):
    """Test the PrintBanner function."""
    output_writer = test_lib.TestOutputWriter(encoding='utf-8')
    setattr(self._test_console, '_output_writer', output_writer)
    setattr(self._test_console.preg_tool, '_output_writer', output_writer)

    self.assertFalse(self._test_console.IsLoaded())
    self._test_console.AddRegistryHelper(self._registry_helper)
    self._test_console.LoadRegistryFile(0)
    self.assertTrue(self._test_console.IsLoaded())
    self._test_console.PrintBanner()

    extra_text = (
        b'Opening hive: {0:s} [OS]\n'
        b'Registry file: NTUSER.DAT [{0:s}] is available and '
        b'loaded.\n').format(self._file_path)

    expected_banner = b'{0:s}\n{1:s}\n{2:s}'.format(
        b'\n'.join(self._EXPECTED_BANNER_HEADER), extra_text,
        self._EXPECTED_BANNER_FOOTER)
    banner = output_writer.ReadOutput()

    # Splitting the string makes it easier to see differences.
    self.assertEqual(banner.split(b'\n'), expected_banner.split(b'\n'))

  def testPrintRegistryFileList(self):
    """Test the PrintRegistryFileList function."""
    output_writer = test_lib.TestOutputWriter(encoding='utf-8')
    setattr(self._test_console, '_output_writer', output_writer)
    setattr(self._test_console.preg_tool, '_output_writer', output_writer)

    self._test_console.PrintRegistryFileList()
    text = output_writer.ReadOutput()
    self.assertEqual(text, '')

    self._test_console.AddRegistryHelper(self._registry_helper)
    self._test_console.PrintRegistryFileList()
    text = output_writer.ReadOutput()

    expected_text = (
        'Index Hive [collector]\n'
        '0     {0:s} [OS]\n').format(self._file_path)

    self.assertEqual(text, expected_text)

  def testGetValueData(self):
    """Test getting values and value entries."""
    self._test_console.AddRegistryHelper(self._registry_helper)
    self._test_console.LoadRegistryFile(0)

    # Open a Registry key using the magic class.
    registry_key_path = (
        'HKEY_CURRENT_USER\\Software\\JavaSoft\\Java Update\\Policy')
    key = self._registry_helper.GetKeyByPath(registry_key_path)
    self.assertEqual(key.path, registry_key_path)

    registry_key = self._test_console._CommandGetCurrentKey()
    self.assertIsNotNone(registry_key)
    self.assertEqual(registry_key.path, registry_key_path)

    current_key = self._registry_helper.GetCurrentRegistryKey()
    self.assertIsNotNone(current_key)
    self.assertEqual(current_key.path, registry_key_path)

    # Get a value out of the currently loaded Registry key.
    value = self._test_console._CommandGetValue('VersionXmlURL')
    self.assertEqual(value.name, 'VersionXmlURL')

    value_data = self._test_console._CommandGetValueData('VersionXmlURL')
    self.assertEqual(
        value_data,
        'http://javadl.sun.com/webapps/download/AutoDL?BundleId=33742')


class PregMagicClassTest(test_lib.CLIToolTestCase):
  """Tests for the IPython magic class."""

  # pylint: disable=protected-access

  def setUp(self):
    """Sets up the needed objects used throughout the test."""
    self._output_writer = test_lib.TestOutputWriter(encoding='utf-8')
    test_tool = preg_tool.PregTool(output_writer=self._output_writer)

    self._test_console = preg.PregConsole(test_tool)
    self._magic_obj = preg.PregMagics(None)
    self._magic_obj.console = self._test_console
    self._magic_obj.output_writer = self._output_writer

    registry_file_entry = self._GetTestFileEntry(['NTUSER.DAT'])
    self._registry_helper = helper.PregRegistryHelper(
        registry_file_entry, 'OS')

    self._test_console.AddRegistryHelper(self._registry_helper)
    self._test_console.LoadRegistryFile(0)
    setattr(self._test_console, '_output_writer', self._output_writer)

  def tearDown(self):
    """Tears down the needed objects after a test."""
    self._registry_helper.Close()

  def testHiveActions(self):
    """Test the HiveAction function."""
    self._magic_obj.HiveActions('list')
    output = self._output_writer.ReadOutput()

    registry_file_path = self._GetTestFilePath(['NTUSER.DAT'])
    # TODO: output is a binary string, correct the expected output.
    expected_output = (
        'Index Hive [collector]\n0     *{0:s} [OS]\n\n'
        'To open a Registry file, use: hive open INDEX\n').format(
            registry_file_path)

    self.assertEqual(output, expected_output)

  def testMagicClass(self):
    """Test the magic class functions."""
    self.assertEqual(self._registry_helper.name, 'NTUSER.DAT')
    # Change directory and verify it worked.
    registry_key_path = (
        'HKEY_CURRENT_USER\\Software\\JavaSoft\\Java Update\\Policy')
    self._magic_obj.ChangeDirectory(registry_key_path)

    registry_key = self._test_console._CommandGetCurrentKey()
    self.assertIsNotNone(registry_key)
    self.assertEqual(registry_key.path, registry_key_path)

    current_key = self._registry_helper.GetCurrentRegistryKey()
    self.assertIsNotNone(current_key)
    self.assertEqual(current_key.path, registry_key_path)

    # List the directory content.
    self._magic_obj.ListDirectoryContent('')
    expected_output = (
        b'-r-xr-xr-x                            [REG_SZ]  LastUpdateBeginTime\n'
        b'-r-xr-xr-x                            [REG_SZ]  '
        b'LastUpdateFinishTime\n'
        b'-r-xr-xr-x                            [REG_SZ]  VersionXmlURL\n')
    output = self._output_writer.ReadOutput()
    self.assertEqual(output.split(b'\n'), expected_output.split(b'\n'))

    # Parse the current key.
    self._magic_obj.ParseCurrentKey('')
    partial_string = (
        'LastUpdateFinishTime : [REG_SZ] Tue, 04 Aug 2009 15:18:35 GMT')
    output = self._output_writer.ReadOutput()
    self.assertTrue(partial_string in output)

    # Parse using a plugin.
    self._magic_obj.ParseWithPlugin('userassist')

    expected_string = (
        b'UEME_RUNPIDL:%csidl2%\\BCWipe 3.0\\BCWipe Task Manager.lnk')
    output = self._output_writer.ReadOutput()
    self.assertIn(expected_string, output)

    self._magic_obj.PrintCurrentWorkingDirectory('')

    current_directory = (
        b'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\'
        b'Explorer\\UserAssist\\{75048700-EF1F-11D0-9888-006097DEACF9}\n')

    output = self._output_writer.ReadOutput()
    self.assertEqual(current_directory, output)

  def testTopLevelMethods(self):
    """Test few of the top level methods in the preg module."""
    # Open a Registry key using the magic class.
    registry_key_path = (
        'HKEY_CURRENT_USER\\Software\\JavaSoft\\Java Update\\Policy')
    self._magic_obj.ChangeDirectory(registry_key_path)

    registry_key = self._test_console._CommandGetCurrentKey()
    self.assertIsNotNone(registry_key)
    self.assertEqual(registry_key.path, registry_key_path)

    current_key = self._registry_helper.GetCurrentRegistryKey()
    self.assertIsNotNone(current_key)
    self.assertEqual(current_key.path, registry_key_path)

    # Change back to the base key.
    self._magic_obj.ChangeDirectory('')
    registry_key = self._test_console._CommandGetCurrentKey()
    self.assertEqual(registry_key.path, 'HKEY_CURRENT_USER')


if __name__ == '__main__':
  unittest.main()
