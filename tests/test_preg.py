#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Tests for the preg front-end."""

import unittest

from dfvfs.helpers import source_scanner
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.path import factory as path_spec_factory

from plaso.engine import knowledge_base
from plaso.lib import errors

from scripts import preg

from tests import test_lib


class PregFrontendTest(test_lib.BaseTestCase):
  """Tests for the preg front-end."""

  def _ConfigureSingleFileTest(self, knowledge_base_values=None):
    """Configure a single file test.

    Args:
      knowledge_base_values: optional dict containing the knowledge base
                             values.

    Returns:
      A front-end object (instance of PregFrontend).
    """
    front_end = preg.PregFrontend()
    front_end.SetSingleFile(True)
    registry_file_path = self._GetTestFilePath([u'SYSTEM'])
    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=registry_file_path)

    front_end.SetSourcePath(registry_file_path)
    front_end.SetSourcePathSpecs([path_spec])

    knowledge_base_object = knowledge_base.KnowledgeBase()
    if knowledge_base_values:
      for identifier, value in iter(knowledge_base_values.items()):
        knowledge_base_object.SetValue(identifier, value)

    front_end.SetKnowledgeBase(knowledge_base_object)
    return front_end

  @test_lib.skipUnlessHasTestFile([u'registry_test.dd'])
  def _ConfigureStorageMediaFileTest(self):
    """Configure a test against a storage media file.

    Returns:
      A front-end object (instance of PregFrontend).
    """
    front_end = preg.PregFrontend()
    front_end.SetSingleFile(False)

    knowledge_base_object = knowledge_base.KnowledgeBase()
    front_end.SetKnowledgeBase(knowledge_base_object)

    storage_media_path = self._GetTestFilePath([u'registry_test.dd'])

    test_source_scanner = source_scanner.SourceScanner()
    scan_context = source_scanner.SourceScannerContext()
    scan_context.OpenSourcePath(storage_media_path)
    test_source_scanner.Scan(scan_context)

    # Getting the most upper node.
    scan_node = scan_context.GetRootScanNode()
    while scan_node.sub_nodes:
      scan_node = scan_node.sub_nodes[0]

    front_end.SetSourcePath(storage_media_path)
    front_end.SetSourcePathSpecs([scan_node.path_spec])
    return front_end

  @test_lib.skipUnlessHasTestFile([u'SYSTEM'])
  def testExpandKeysRedirect(self):
    """Tests the ExpandKeysRedirect function."""
    front_end = self._ConfigureSingleFileTest()
    registry_key_paths = [
        u'\\Software\\Foobar',
        u'\\Software\\Key\\SubKey\\MagicalKey',
        u'\\Canons\\Blast\\Night',
        u'\\EvilCorp\\World Plans\\Takeover']
    front_end.ExpandKeysRedirect(registry_key_paths)

    added_key_paths = [
        u'\\Software\\Wow6432Node\\Foobar',
        u'\\Software\\Wow6432Node\\Key\\SubKey\\MagicalKey']

    for added_key_path in added_key_paths:
      self.assertIn(added_key_path, registry_key_paths)

  @test_lib.skipUnlessHasTestFile([u'SYSTEM'])
  def testGetRegistryFilePaths(self):
    """Tests the GetRegistryFilePaths function."""
    front_end = self._ConfigureSingleFileTest()

    expected_paths = [u'%UserProfile%\\NTUSER.DAT']
    registry_file_types = [u'NTUSER']
    paths = front_end.GetRegistryFilePaths(registry_file_types)
    self.assertEqual(sorted(paths), sorted(expected_paths))

    expected_paths = [u'%SystemRoot%\\System32\\config\\SOFTWARE']
    registry_file_types = [u'SOFTWARE']
    paths = front_end.GetRegistryFilePaths(registry_file_types)
    self.assertEqual(sorted(paths), sorted(expected_paths))

  @test_lib.skipUnlessHasTestFile([u'SYSTEM'])
  @test_lib.skipUnlessHasTestFile([u'registry_test.dd'])
  def testGetRegistryHelpers(self):
    """Tests the GetRegistryHelpers function."""
    front_end = self._ConfigureSingleFileTest()
    with self.assertRaises(ValueError):
      front_end.GetRegistryHelpers()

    registry_helpers = front_end.GetRegistryHelpers(
        registry_file_types=[u'SYSTEM'])

    self.assertEqual(len(registry_helpers), 1)

    registry_helper = registry_helpers[0]

    file_path = self._GetTestFilePath([u'SYSTEM'])
    self.assertEqual(registry_helper.path, file_path)

    front_end = self._ConfigureStorageMediaFileTest()
    registry_helpers = front_end.GetRegistryHelpers(
        registry_file_types=[u'NTUSER'])

    self.assertEqual(len(registry_helpers), 3)

    registry_helper = registry_helpers[0]
    registry_helper.Open()
    expected_file_type = preg.REGISTRY_FILE_TYPE_NTUSER
    self.assertEqual(registry_helper.file_type, expected_file_type)
    self.assertEqual(registry_helper.name, u'NTUSER.DAT')
    self.assertEqual(registry_helper.collector_name, u'TSK')
    registry_helper.Close()

    registry_helpers = front_end.GetRegistryHelpers(
        plugin_names=[u'userassist'])
    self.assertEqual(len(registry_helpers), 3)

    registry_helpers = front_end.GetRegistryHelpers(
        registry_file_types=[u'SAM'])
    self.assertEqual(len(registry_helpers), 1)

    # TODO: Add a test for getting Registry helpers from a storage media file
    # that contains VSS stores.

  @test_lib.skipUnlessHasTestFile([u'SYSTEM'])
  def testGetRegistryPlugins(self):
    """Tests the GetRegistryPlugin function."""
    front_end = self._ConfigureSingleFileTest()
    usb_plugins = front_end.GetRegistryPlugins(u'usb')
    self.assertIsNotNone(usb_plugins)

    usb_plugin_names = [plugin.NAME for plugin in usb_plugins]
    self.assertIn(u'windows_usb_devices', usb_plugin_names)
    self.assertIn(u'windows_usbstor_devices', usb_plugin_names)

    other_plugins = front_end.GetRegistryPlugins(u'user')
    self.assertIsNotNone(other_plugins)
    other_plugin_names = [plugin.NAME for plugin in other_plugins]

    self.assertIn(u'userassist', other_plugin_names)

  @test_lib.skipUnlessHasTestFile([u'SYSTEM'])
  def testParseRegistry(self):
    """Tests the ParseRegistryFile and ParseRegistryKey functions."""
    front_end = self._ConfigureSingleFileTest()

    registry_helpers = front_end.GetRegistryHelpers(
        registry_file_types=[u'SYSTEM'])
    registry_helper = registry_helpers[0]

    plugins = front_end.GetRegistryPluginsFromRegistryType(u'SYSTEM')
    key_list = []
    plugin_list = []
    for plugin in plugins:
      plugin_list.append(plugin.NAME)
      key_list.extend(plugin.GetKeyPaths())

    front_end.ExpandKeysRedirect(key_list)

    parsed_data = front_end.ParseRegistryFile(
        registry_helper, key_paths=key_list, use_plugins=plugin_list)
    for key_parsed in parsed_data:
      self.assertIn(key_parsed, key_list)

    usb_parsed_data = parsed_data.get(
        u'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Enum\\USBSTOR', None)
    self.assertIsNotNone(usb_parsed_data)
    usb_key = usb_parsed_data.get(u'key', None)
    self.assertIsNotNone(usb_key)

    expected_key_path = (
        u'HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Enum\\USBSTOR')
    self.assertEqual(usb_key.path, expected_key_path)

    data = usb_parsed_data.get(u'data', None)
    self.assertIsNotNone(data)

    plugin_names = [plugin.NAME for plugin in data.keys()]
    self.assertIn(u'windows_usbstor_devices', plugin_names)

    usb_plugin = None
    for plugin in data.keys():
      if plugin.NAME == u'windows_usbstor_devices':
        usb_plugin = plugin
        break

    event_objects = data.get(usb_plugin, [])

    self.assertEqual(len(event_objects), 5)
    event = event_objects[2]

    self.assertEqual(event.data_type, u'windows:registry:key_value')

    parse_key_data = front_end.ParseRegistryKey(
        usb_key, registry_helper, use_plugins=u'windows_usbstor_devices')

    self.assertEqual(len(parse_key_data.keys()), 1)
    parsed_key_value = parse_key_data.values()[0]

    for index, event in enumerate(event_objects):
      parsed_key_event = parsed_key_value[index]

      event_values = event.CopyToDict()
      parsed_key_event_values = parsed_key_event.CopyToDict()

      self.assertEqual(event_values, parsed_key_event_values)


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
    self._test_tool = preg.PregTool(output_writer=self._output_writer)

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
    self._output_writer = test_lib.TestOutputWriter(encoding=u'utf-8')
    self._test_tool = preg.PregTool(output_writer=self._output_writer)
    self._test_console = preg.PregConsole(self._test_tool)
    file_entry = self._GetTestFileEntry([u'NTUSER.DAT'])
    self._file_path = self._GetTestFilePath([u'NTUSER.DAT'])
    self._registry_helper = preg.PregRegistryHelper(
        file_entry, u'OS', self._test_tool._knowledge_base_object)

  def tearDown(self):
    """Tears down the needed ojects after a test."""
    self._registry_helper.Close()

  def testAddRegistryHelpers(self):
    """Test the add registry helper."""
    self._test_console.AddRegistryHelper(self._registry_helper)
    registry_helpers = getattr(self._test_console, u'_registry_helpers', [])

    self.assertEqual(len(registry_helpers), 1)
    setattr(self._test_console, u'_registry_helpers', [])

  def testPrintBanner(self):
    """Test the PrintBanner function."""
    output_writer = test_lib.TestOutputWriter(encoding=u'utf-8')
    setattr(self._test_console, u'_output_writer', output_writer)
    setattr(self._test_console.preg_tool, u'_output_writer', output_writer)

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
    output_writer = test_lib.TestOutputWriter(encoding=u'utf-8')
    setattr(self._test_console, u'_output_writer', output_writer)
    setattr(self._test_console.preg_tool, u'_output_writer', output_writer)

    self._test_console.PrintRegistryFileList()
    text = output_writer.ReadOutput()
    self.assertEqual(text, u'')

    self._test_console.AddRegistryHelper(self._registry_helper)
    self._test_console.PrintRegistryFileList()
    text = output_writer.ReadOutput()

    expected_text = (
        u'Index Hive [collector]\n'
        u'0     {0:s} [OS]\n').format(self._file_path)

    self.assertEqual(text, expected_text)

  def testGetValueData(self):
    """Test getting values and value entries."""
    self._test_console.AddRegistryHelper(self._registry_helper)
    self._test_console.LoadRegistryFile(0)

    # Open a Registry key using the magic class.
    registry_key_path = (
        u'HKEY_CURRENT_USER\\Software\\JavaSoft\\Java Update\\Policy')
    key = self._registry_helper.GetKeyByPath(registry_key_path)
    self.assertEqual(key.path, registry_key_path)

    registry_key = self._test_console._CommandGetCurrentKey()
    self.assertIsNotNone(registry_key)
    self.assertEqual(registry_key.path, registry_key_path)

    current_key = self._registry_helper.GetCurrentRegistryKey()
    self.assertIsNotNone(current_key)
    self.assertEqual(current_key.path, registry_key_path)

    # Get a value out of the currently loaded Registry key.
    value = self._test_console._CommandGetValue(u'VersionXmlURL')
    self.assertEqual(value.name, u'VersionXmlURL')

    value_data = self._test_console._CommandGetValueData(u'VersionXmlURL')
    self.assertEqual(
        value_data,
        u'http://javadl.sun.com/webapps/download/AutoDL?BundleId=33742')


class PregMagicClassTest(test_lib.CLIToolTestCase):
  """Tests for the IPython magic class."""

  # pylint: disable=protected-access

  def setUp(self):
    """Sets up the needed objects used throughout the test."""
    self._output_writer = test_lib.TestOutputWriter(encoding=u'utf-8')
    test_tool = preg.PregTool(output_writer=self._output_writer)
    front_end = getattr(test_tool, '_front_end', None)
    front_end.SetKnowledgeBase(test_tool._knowledge_base_object)

    self._test_console = preg.PregConsole(test_tool)
    self._magic_obj = preg.PregMagics(None)
    self._magic_obj.console = self._test_console
    self._magic_obj.output_writer = self._output_writer

    registry_file_entry = self._GetTestFileEntry([u'NTUSER.DAT'])
    self._registry_helper = preg.PregRegistryHelper(
        registry_file_entry, u'OS', test_tool._knowledge_base_object)

    self._test_console.AddRegistryHelper(self._registry_helper)
    self._test_console.LoadRegistryFile(0)
    setattr(self._test_console, '_output_writer', self._output_writer)

  def tearDown(self):
    """Tears down the needed ojects after a test."""
    self._registry_helper.Close()

  def testHiveActions(self):
    """Test the HiveAction function."""
    self._magic_obj.HiveActions(u'list')
    output = self._output_writer.ReadOutput()

    registry_file_path = self._GetTestFilePath([u'NTUSER.DAT'])
    # TODO: output is a binary string, correct the expected output.
    expected_output = (
        u'Index Hive [collector]\n0     *{0:s} [OS]\n\n'
        u'To open a Registry file, use: hive open INDEX\n').format(
            registry_file_path)

    self.assertEqual(output, expected_output)

  def testMagicClass(self):
    """Test the magic class functions."""
    self.assertEqual(self._registry_helper.name, u'NTUSER.DAT')
    # Change directory and verify it worked.
    registry_key_path = (
        u'HKEY_CURRENT_USER\\Software\\JavaSoft\\Java Update\\Policy')
    self._magic_obj.ChangeDirectory(registry_key_path)

    registry_key = self._test_console._CommandGetCurrentKey()
    self.assertIsNotNone(registry_key)
    self.assertEqual(registry_key.path, registry_key_path)

    current_key = self._registry_helper.GetCurrentRegistryKey()
    self.assertIsNotNone(current_key)
    self.assertEqual(current_key.path, registry_key_path)

    # List the directory content.
    self._magic_obj.ListDirectoryContent(u'')
    expected_output = (
        b'-r-xr-xr-x                            [REG_SZ]  LastUpdateBeginTime\n'
        b'-r-xr-xr-x                            [REG_SZ]  '
        b'LastUpdateFinishTime\n'
        b'-r-xr-xr-x                            [REG_SZ]  VersionXmlURL\n')
    output = self._output_writer.ReadOutput()
    self.assertEqual(output, expected_output)

    # Parse the current key.
    self._magic_obj.ParseCurrentKey(u'')
    partial_string = (
        u'LastUpdateFinishTime : [REG_SZ] Tue, 04 Aug 2009 15:18:35 GMT')
    output = self._output_writer.ReadOutput()
    self.assertTrue(partial_string in output)

    # Parse using a plugin.
    self._magic_obj.ParseWithPlugin(u'userassist')

    expected_string = (
        b'UEME_RUNPIDL:%csidl2%\\BCWipe 3.0\\BCWipe Task Manager.lnk')
    output = self._output_writer.ReadOutput()
    self.assertIn(expected_string, output)

    self._magic_obj.PrintCurrentWorkingDirectory(u'')

    current_directory = (
        b'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\'
        b'Explorer\\UserAssist\\{75048700-EF1F-11D0-9888-006097DEACF9}\n')

    output = self._output_writer.ReadOutput()
    self.assertEqual(current_directory, output)

  def testTopLevelMethods(self):
    """Test few of the top level methods in the preg module."""
    # Open a Registry key using the magic class.
    registry_key_path = (
        u'HKEY_CURRENT_USER\\Software\\JavaSoft\\Java Update\\Policy')
    self._magic_obj.ChangeDirectory(registry_key_path)

    registry_key = self._test_console._CommandGetCurrentKey()
    self.assertIsNotNone(registry_key)
    self.assertEqual(registry_key.path, registry_key_path)

    current_key = self._registry_helper.GetCurrentRegistryKey()
    self.assertIsNotNone(current_key)
    self.assertEqual(current_key.path, registry_key_path)

    # Change back to the base key.
    self._magic_obj.ChangeDirectory(u'')
    registry_key = self._test_console._CommandGetCurrentKey()
    self.assertEqual(registry_key.path, u'HKEY_CURRENT_USER')


if __name__ == '__main__':
  unittest.main()
