#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the preg tool."""

from __future__ import unicode_literals

import unittest

from artifacts import reader as artifacts_reader
from artifacts import registry as artifacts_registry

from dfvfs.helpers import source_scanner
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.path import factory as path_spec_factory

from plaso.engine import knowledge_base
from plaso.lib import errors

from l2tpreg import definitions
from l2tpreg import preg_tool

from tests import test_lib


class PregToolTest(test_lib.CLIToolTestCase):
  """Tests for the preg tool."""

  # pylint: disable=protected-access

  def _ConfigureSingleFileTest(self, knowledge_base_values=None):
    """Configure a single file test.

    Args:
      knowledge_base_values (Optional[dict[str, object]): knowledge base
          values.

    Returns:
      PregTool: preg tool.
    """
    registry_file_path = self._GetTestFilePath(['SYSTEM'])
    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=registry_file_path)

    knowledge_base_object = knowledge_base.KnowledgeBase()
    if knowledge_base_values:
      for identifier, value in iter(knowledge_base_values.items()):
        knowledge_base_object.SetValue(identifier, value)

    test_tool = preg_tool.PregTool()
    test_tool._single_file = True
    test_tool._source_path = registry_file_path
    test_tool._source_path_specs = [path_spec]
    test_tool.knowledge_base_object = knowledge_base_object
    return test_tool

  @test_lib.skipUnlessHasTestFile(['registry_test.dd'])
  def _ConfigureStorageMediaFileTest(self):
    """Configures a test against a storage media file.

    Returns:
      PregTool: preg tool.
    """
    storage_media_path = self._GetTestFilePath(['registry_test.dd'])

    test_source_scanner = source_scanner.SourceScanner()
    scan_context = source_scanner.SourceScannerContext()
    scan_context.OpenSourcePath(storage_media_path)
    test_source_scanner.Scan(scan_context)

    # Getting the most upper node.
    scan_node = scan_context.GetRootScanNode()
    while scan_node.sub_nodes:
      scan_node = scan_node.sub_nodes[0]

    test_tool = preg_tool.PregTool()
    test_tool._single_file = False
    test_tool._source_path = storage_media_path
    test_tool._source_path_specs = [scan_node.path_spec]
    test_tool.knowledge_base_object = knowledge_base.KnowledgeBase()
    return test_tool

  def _ExtractPluginsAndKey(self, output):
    """Extracts plugins and keys from preg output.

    Args:
      output (str): output from preg.

    Returns:
      tuple: contains:

      * set: all plugins that were found in the output.
      * set: all Windows Registry keys were found in the output.
    """
    # TODO: refactor to more accurate way to test this.
    plugins = set()
    registry_keys = set()

    for line in output.split(b'\n'):
      line = line.lstrip()

      if b'** Plugin' in line:
        _, _, plugin_name_line = line.rpartition(b':')
        plugin_name, _, _ = plugin_name_line.partition(b'*')
        plugins.add(plugin_name.strip())

      if b'Key Path :' in line:
        _, _, key_name = line.rpartition(b':')
        registry_keys.add(key_name.strip())

    return plugins, registry_keys

  # TODO: add tests for _CreateWindowsPathResolver

  @test_lib.skipUnlessHasTestFile(['SYSTEM'])
  def testExpandKeysRedirect(self):
    """Tests the _ExpandKeysRedirect function."""
    test_tool = self._ConfigureSingleFileTest()
    registry_key_paths = [
        '\\Software\\Foobar',
        '\\Software\\Key\\SubKey\\MagicalKey',
        '\\Canons\\Blast\\Night',
        '\\EvilCorp\\World Plans\\Takeover']
    test_tool._ExpandKeysRedirect(registry_key_paths)

    added_key_paths = [
        '\\Software\\Wow6432Node\\Foobar',
        '\\Software\\Wow6432Node\\Key\\SubKey\\MagicalKey']

    for added_key_path in added_key_paths:
      self.assertIn(added_key_path, registry_key_paths)

  # TODO: add tests for _GetEventDataHexDump
  # TODO: add tests for _GetFormatString

  @test_lib.skipUnlessHasTestFile(['SYSTEM'])
  def testGetRegistryFilePaths(self):
    """Tests the GetRegistryFilePaths function."""
    test_tool = self._ConfigureSingleFileTest()

    expected_paths = ['%UserProfile%\\NTUSER.DAT']
    registry_file_types = ['NTUSER']
    paths = test_tool._GetRegistryFilePaths(registry_file_types)
    self.assertEqual(sorted(paths), sorted(expected_paths))

    expected_paths = ['%SystemRoot%\\System32\\config\\SOFTWARE']
    registry_file_types = ['SOFTWARE']
    paths = test_tool._GetRegistryFilePaths(registry_file_types)
    self.assertEqual(sorted(paths), sorted(expected_paths))

  @test_lib.skipUnlessHasTestFile(['artifacts'])
  @test_lib.skipUnlessHasTestFile(['SYSTEM'])
  @test_lib.skipUnlessHasTestFile(['registry_test.dd'])
  def testGetRegistryHelpers(self):
    """Tests the _GetRegistryHelpers function."""
    path = self._GetTestFilePath(['artifacts'])
    artifact_registry = artifacts_registry.ArtifactDefinitionsRegistry()
    reader = artifacts_reader.YamlArtifactsReader()
    artifact_registry.ReadFromDirectory(reader, path)

    test_tool = self._ConfigureSingleFileTest()
    with self.assertRaises(ValueError):
      test_tool._GetRegistryHelpers(artifact_registry)

    registry_helpers = test_tool._GetRegistryHelpers(
        artifact_registry, registry_file_types=['SYSTEM'])

    self.assertEqual(len(registry_helpers), 1)

    registry_helper = registry_helpers[0]

    file_path = self._GetTestFilePath(['SYSTEM'])
    self.assertEqual(registry_helper.path, file_path)

    test_tool = self._ConfigureStorageMediaFileTest()
    registry_helpers = test_tool._GetRegistryHelpers(
        artifact_registry, registry_file_types=['NTUSER'])

    self.assertEqual(len(registry_helpers), 3)

    registry_helper = registry_helpers[0]
    registry_helper.Open()
    expected_file_type = definitions.REGISTRY_FILE_TYPE_NTUSER
    self.assertEqual(registry_helper.file_type, expected_file_type)
    self.assertEqual(registry_helper.name, 'NTUSER.DAT')
    self.assertEqual(registry_helper.collector_name, 'TSK')
    registry_helper.Close()

    registry_helpers = test_tool._GetRegistryHelpers(
        artifact_registry, plugin_names=['userassist'])
    self.assertEqual(len(registry_helpers), 3)

    registry_helpers = test_tool._GetRegistryHelpers(
        artifact_registry, registry_file_types=['SAM'])
    self.assertEqual(len(registry_helpers), 1)

    # TODO: Add a test for getting Registry helpers from a storage media file
    # that contains VSS stores.

  # TODO: add tests for _GetRegistryHelperFromPath

  @test_lib.skipUnlessHasTestFile(['SYSTEM'])
  def testGetRegistryPlugins(self):
    """Tests the _GetRegistryPlugins function."""
    test_tool = self._ConfigureSingleFileTest()
    usb_plugins = test_tool._GetRegistryPlugins('usb')
    self.assertIsNotNone(usb_plugins)

    usb_plugin_names = [plugin.NAME for plugin in usb_plugins]
    self.assertIn('windows_usb_devices', usb_plugin_names)
    self.assertIn('windows_usbstor_devices', usb_plugin_names)

    other_plugins = test_tool._GetRegistryPlugins('user')
    self.assertIsNotNone(other_plugins)
    other_plugin_names = [plugin.NAME for plugin in other_plugins]

    self.assertIn('userassist', other_plugin_names)

  # TODO: add tests for _GetRegistryPluginsFromRegistryType
  # TODO: add tests for _GetRegistryTypes
  # TODO: add tests for _GetSourceFileSystem
  # TODO: add tests for _GetTSKPartitionIdentifiers

  # TODO: split tests for _ParseRegistryFile and ParseRegistryKey

  @test_lib.skipUnlessHasTestFile(['artifacts'])
  @test_lib.skipUnlessHasTestFile(['SYSTEM'])
  def testParseRegistry(self):
    """Tests the _ParseRegistryFile and ParseRegistryKey functions."""
    path = self._GetTestFilePath(['artifacts'])
    artifact_registry = artifacts_registry.ArtifactDefinitionsRegistry()
    reader = artifacts_reader.YamlArtifactsReader()
    artifact_registry.ReadFromDirectory(reader, path)

    test_tool = self._ConfigureSingleFileTest()

    registry_helpers = test_tool._GetRegistryHelpers(
        artifact_registry, registry_file_types=['SYSTEM'])
    registry_helper = registry_helpers[0]

    plugins = test_tool._GetRegistryPluginsFromRegistryType('SYSTEM')
    key_list = []
    plugin_list = []
    for plugin in plugins:
      for key_filter in plugin.FILTERS:
        plugin_list.append(plugin.NAME)
        key_list.extend(key_filter.key_paths)

    test_tool._ExpandKeysRedirect(key_list)

    parsed_data = test_tool._ParseRegistryFile(
        registry_helper, key_paths=key_list, use_plugins=plugin_list)
    for key_parsed in parsed_data:
      self.assertIn(key_parsed, key_list)

    usb_parsed_data = parsed_data.get(
        'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Enum\\USBSTOR', None)
    self.assertIsNotNone(usb_parsed_data)
    usb_key = usb_parsed_data.get('key', None)
    self.assertIsNotNone(usb_key)

    expected_key_path = (
        'HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Enum\\USBSTOR')
    self.assertEqual(usb_key.path, expected_key_path)

    data = usb_parsed_data.get('data', None)
    self.assertIsNotNone(data)

    plugin_names = [plugin.NAME for plugin in data.keys()]
    self.assertIn('windows_usbstor_devices', plugin_names)

    usb_plugin = None
    for plugin in data.keys():
      if plugin.NAME == 'windows_usbstor_devices':
        usb_plugin = plugin
        break

    event_objects = data.get(usb_plugin, [])

    self.assertEqual(len(event_objects), 5)
    event = event_objects[2]

    self.assertEqual(event.data_type, 'windows:registry:key_value')

    parse_key_data = test_tool.ParseRegistryKey(
        usb_key, registry_helper, use_plugins='windows_usbstor_devices')

    self.assertEqual(len(parse_key_data.keys()), 1)
    parsed_key_value = parse_key_data.values()[0]

    for index, event in enumerate(event_objects):
      parsed_key_event = parsed_key_value[index]

      event_values = event.CopyToDict()
      parsed_key_event_values = parsed_key_event.CopyToDict()

      self.assertEqual(event_values, parsed_key_event_values)

  # TODO: add tests for _PathExists
  # TODO: add tests for _PrintEventBody
  # TODO: add tests for _PrintEventHeader
  # TODO: add tests for _PrintEventObjectsBasedOnTime
  # TODO: add tests for _PrintParsedRegistryFile
  # TODO: add tests for _PrintParsedRegistryInformation
  # TODO: add tests for _ScanFileSystem
  # TODO: add tests for GetWindowsRegistryPlugins
  # TODO: add tests for GetWindowsVolumeIdentifiers

  def testListPluginInformation(self):
    """Tests the ListPluginInformation function."""
    output_writer = test_lib.TestOutputWriter(encoding='utf-8')
    test_tool = preg_tool.PregTool(output_writer=output_writer)

    options = test_lib.TestOptions()
    options.show_info = True

    test_tool.ParseOptions(options)

    test_tool.ListPluginInformation()

    output = output_writer.ReadOutput()

    # TODO: refactor to more accurate way to test this.
    self.assertIn(b'* Supported Plugins *', output)
    self.assertIn(b'userassist : Parser for User Assist Registry data', output)
    # TODO: how is this supposed to work since windows_services does not have
    # an explicit key path defined.
    # self.assertIn(
    #     b'windows_services : Parser for services and drivers', output)

  # TODO: add tests for ParseArguments

  def testParseOptions(self):
    """Tests the ParseOptions function."""
    output_writer = test_lib.TestOutputWriter(encoding='utf-8')
    test_tool = preg_tool.PregTool(output_writer=output_writer)

    options = test_lib.TestOptions()
    options.foo = 'bar'

    with self.assertRaises(errors.BadConfigOption):
      test_tool.ParseOptions(options)

    options = test_lib.TestOptions()
    options.registry_file = 'this_path_does_not_exist'

    with self.assertRaises(errors.BadConfigOption):
      test_tool.ParseOptions(options)

  def testPrintHeader(self):
    """Tests the PrintHeader function."""
    output_writer = test_lib.TestOutputWriter(encoding='utf-8')
    test_tool = preg_tool.PregTool(output_writer=output_writer)

    test_tool.PrintHeader('Text')
    string = output_writer.ReadOutput()
    expected_string = (
        b'\n'
        b'************************************* '
        b'Text '
        b'*************************************\n')
    self.assertEqual(string, expected_string)

    test_tool.PrintHeader('Another Text', character='x')
    string = output_writer.ReadOutput()
    expected_string = (
        b'\n'
        b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx '
        b'Another Text '
        b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n')
    self.assertEqual(string, expected_string)

    # TODO: determine if this is the desired behavior.
    test_tool.PrintHeader('')
    string = output_writer.ReadOutput()
    expected_string = (
        b'\n'
        b'*************************************** '
        b' '
        b'***************************************\n')
    self.assertEqual(string, expected_string)

    # TODO: determine if this is the desired behavior.
    test_tool.PrintHeader(None)
    string = output_writer.ReadOutput()
    expected_string = (
        b'\n'
        b'************************************* '
        b'None '
        b'*************************************\n')
    self.assertEqual(string, expected_string)

    # TODO: determine if this is the desired behavior.
    expected_string = (
        '\n '
        'In computer programming, a string is traditionally a sequence '
        'of characters, either as a literal constant or as some kind of '
        'variable. \n')
    test_tool.PrintHeader(expected_string[2:-2])
    string = output_writer.ReadOutput()
    self.assertEqual(string, expected_string)

  # TODO: add tests for PrintParsedRegistryKey

  def testRunModeRegistryFile(self):
    """Tests the RunModeRegistryFile function."""
    output_writer = test_lib.TestOutputWriter(encoding='utf-8')
    test_tool = preg_tool.PregTool(output_writer=output_writer)

    options = test_lib.TestOptions()
    options.registry_file = self._GetTestFilePath(['SOFTWARE'])

    test_tool.ParseOptions(options)

    test_tool.RunModeRegistryFile()

    output = output_writer.ReadOutput()

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

  def testRunModeRegistryKey(self):
    """Tests the RunModeRegistryKey function."""
    output_writer = test_lib.TestOutputWriter(encoding='utf-8')
    test_tool = preg_tool.PregTool(output_writer=output_writer)

    options = test_lib.TestOptions()
    options.key = (
        'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion')
    options.parser_names = ''
    options.registry_file = self._GetTestFilePath(['SOFTWARE'])
    options.verbose = False

    test_tool.ParseOptions(options)

    test_tool.RunModeRegistryKey()

    output = output_writer.ReadOutput()

    # TODO: refactor to more accurate way to test this.
    self.assertIn(b'Product name : Windows 7 Ultimate', output)

  def testRunModeRegistryPlugin(self):
    """Tests the RunModeRegistryPlugin function."""
    output_writer = test_lib.TestOutputWriter(encoding='utf-8')
    test_tool = preg_tool.PregTool(output_writer=output_writer)

    options = test_lib.TestOptions()
    options.registry_file = self._GetTestFilePath(['NTUSER.DAT'])
    options.plugin_names = 'userassist'
    options.verbose = False

    test_tool.ParseOptions(options)

    test_tool.RunModeRegistryPlugin()

    output = output_writer.ReadOutput()

    # TODO: refactor to more accurate way to test this.
    expected_string = (
        b'UEME_RUNPATH:C:\\Program Files\\Internet Explorer\\iexplore.exe')
    self.assertIn(expected_string, output)

    # TODO: Add tests that parse a disk image. Test both Registry key parsing
    # and plugin parsing.


if __name__ == '__main__':
  unittest.main()
