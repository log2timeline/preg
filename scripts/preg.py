#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Interactive Windows Registry analysis tool.

preg is an interactive Windows Registry analysis tool that utilizes
plaso Windows Registry parser plugins, dfwinreg Windows Registry and
dfvfs storage media image capabilities.
"""

from __future__ import print_function
from __future__ import unicode_literals

import locale
import sys

import IPython

from dfvfs.lib import definitions as dfvfs_definitions

# pylint: disable=import-error,no-name-in-module,ungrouped-imports
try:
  # Support version 1.x of IPython.
  from IPython.terminal.embed import InteractiveShellEmbed
except ImportError:
  from IPython.frontend.terminal.embed import InteractiveShellEmbed

from IPython.config.loader import Config
from IPython.core import magic

from plaso.cli import tools as cli_tools
from plaso.cli import views as cli_views
from plaso.lib import errors
from plaso.lib import timelib

from l2tpreg import helper
from l2tpreg import hexdump
from l2tpreg import plugin_list
from l2tpreg import preg_tool


# Older versions of IPython don't have a version_info attribute.
if getattr(IPython, 'version_info', (0, 0, 0)) < (1, 2, 1):
  raise ImportWarning(
      'Preg requires at least IPython version 1.2.1.')


@magic.magics_class
class PregMagics(magic.Magics):
  """Preg iPython magics."""

  # Needed to give the magic class access to the front end tool
  # for processing and formatting.
  console = None

  REGISTRY_KEY_PATH_SEPARATOR = '\\'

  # TODO: move into helper.
  REGISTRY_FILE_BASE_PATH = '\\'

  # TODO: Use the output writer from the tool.
  output_writer = cli_tools.StdoutOutputWriter()

  def _HiveActionList(self, unused_line):
    """Handles the hive list action.

    Args:
      line (str): command line provide via the console.
    """
    self.console.PrintRegistryFileList()
    self.output_writer.Write('\n')
    self.output_writer.Write(
        'To open a Registry file, use: hive open INDEX\n')

  def _HiveActionOpen(self, line):
    """Handles the hive open action.

    Args:
      line (str): command line provide via the console.
    """
    try:
      registry_file_index = int(line[5:], 10)
    except ValueError:
      self.output_writer.Write(
          'Unable to open Registry file, invalid index number.\n')
      return

    try:
      self.console.LoadRegistryFile(registry_file_index)
    except errors.UnableToLoadRegistryHelper as exception:
      self.output_writer.Write(
          'Unable to load hive, with error: {0:s}.\n'.format(exception))
      return

    registry_helper = self.console.current_helper
    self.output_writer.Write('Opening hive: {0:s} [{1:s}]\n'.format(
        registry_helper.path, registry_helper.collector_name))
    self.console.SetPrompt(registry_file_path=registry_helper.path)

  def _HiveActionScan(self, line):
    """Handles the hive scan action.

    Args:
      line (str): command line provide via the console.
    """
    # Line contains: "scan REGISTRY_TYPES" where REGISTRY_TYPES is a comma
    # separated list.
    registry_file_type_string = line[5:]
    if not registry_file_type_string:
      registry_file_types = self.console.preg_tool.GetRegistryTypes()
    else:
      registry_file_types = [
          string.strip() for string in registry_file_type_string.split(',')]

    registry_helpers = self.console.preg_tool.GetRegistryHelpers(
        self.console.preg_tool.artifacts_registry,
        registry_file_types=registry_file_types)

    for registry_helper in registry_helpers:
      self.console.AddRegistryHelper(registry_helper)

    self.console.PrintRegistryFileList()

  def _PrintPluginHelp(self, plugin_object):
    """Prints the help information of a plugin.

    Args:
      plugin_object (WindowsRegistryPlugin): a Windows Registry plugin.
    """
    table_view = cli_views.CLITableView(title=plugin_object.NAME)

    # TODO: replace __doc__ by DESCRIPTION.
    description = plugin_object.__doc__
    table_view.AddRow(['Description', description])
    self.output_writer.Write('\n')

    for registry_key in plugin_object.expanded_keys:
      table_view.AddRow(['Registry Key', registry_key])
    table_view.Write(self.output_writer)

  def _SanitizeKeyPath(self, key_path):
    """Sanitizes a Windows Registry key path.

    Args:
      key_path (str): Windows Registry key path.

    Returns:
      str: sanitized Windows Registry key path.
    """
    key_path = key_path.replace('}', '}}')
    key_path = key_path.replace('{', '{{')
    return key_path.replace('\\', '\\\\')

  @magic.line_magic('cd')
  def ChangeDirectory(self, key_path):
    """Change between Registry keys, like a directory tree.

    The key path can either be an absolute path or a relative one.
    Absolute paths can use '.' and '..' to denote current and parent
    directory/key path. If no key path is set the current key is changed
    to point to the root key.

    Args:
      key_path (str): Windows Registry key path to change to.
    """
    if not self.console and not self.console.IsLoaded():
      return

    registry_helper = self.console.current_helper
    if not registry_helper:
      return

    registry_key = registry_helper.ChangeKeyByPath(key_path)
    if not registry_key:
      self.output_writer.Write(
          'Unable to change to key: {0:s}\n'.format(key_path))
      return

    sanitized_path = self._SanitizeKeyPath(registry_key.path)
    self.console.SetPrompt(
        registry_file_path=registry_helper.path,
        prepend_string=sanitized_path)

  @magic.line_magic('hive')
  def HiveActions(self, line):
    """Handles the hive actions.

    Args:
      line (str): command line provide via the console.
    """
    if line.startswith('list'):
      self._HiveActionList(line)

    elif line.startswith('open ') or line.startswith('load '):
      self._HiveActionOpen(line)

    elif line.startswith('scan'):
      self._HiveActionScan(line)

  @magic.line_magic('ls')
  def ListDirectoryContent(self, line):
    """List all subkeys and values of the current key.

    Args:
      line (str): command line provide via the console.
    """
    if not self.console and not self.console.IsLoaded():
      return

    if 'true' in line.lower():
      verbose = True
    elif '-v' in line.lower():
      verbose = True
    else:
      verbose = False

    sub = []
    current_file = self.console.current_helper
    if not current_file:
      return

    current_key = current_file.GetCurrentRegistryKey()
    for key in current_key.GetSubkeys():
      # TODO: move this construction into a separate function in OutputWriter.
      time_string = timelib.Timestamp.CopyToIsoFormat(
          key.last_written_time)
      time_string, _, _ = time_string.partition('.')

      sub.append(('{0:>19s} {1:>15s}  {2:s}'.format(
          time_string.replace('T', ' '), '[KEY]',
          key.name), True))

    for value in current_key.GetValues():
      if not verbose:
        sub.append(('{0:>19s} {1:>14s}]  {2:s}'.format(
            '', '[' + value.data_type_string, value.name), False))
      else:
        if value.DataIsString():
          value_string = value.GetDataAsObject()

        elif value.DataIsInteger():
          value_string = '{0:d}'.format(value.GetDataAsObject())

        elif value.DataIsMultiString():
          value_string = '{0:s}'.format(''.join(value.GetDataAsObject()))

        elif value.DataIsBinaryData():
          value_string = hexdump.Hexdump.FormatData(
              value.data, maximum_data_size=16)

        else:
          value_string = ''

        sub.append((
            '{0:>19s} {1:>14s}]  {2:<25s}  {3:s}'.format(
                '', '[' + value.data_type_string, value.name, value_string),
            False))

    for entry, subkey in sorted(sub):
      if subkey:
        self.output_writer.Write('dr-xr-xr-x {0:s}\n'.format(entry))
      else:
        self.output_writer.Write('-r-xr-xr-x {0:s}\n'.format(entry))

  @magic.line_magic('parse')
  def ParseCurrentKey(self, line):
    """Parse the current key.

    Args:
      line (str): command line provide via the console.
    """
    if not self.console and not self.console.IsLoaded():
      return

    if 'true' in line.lower():
      verbose = True
    elif '-v' in line.lower():
      verbose = True
    else:
      verbose = False

    current_helper = self.console.current_helper
    if not current_helper:
      return

    current_key = current_helper.GetCurrentRegistryKey()
    parsed_data = self.console.preg_tool.ParseRegistryKey(
        current_key, current_helper)

    self.console.preg_tool.PrintParsedRegistryKey(
        parsed_data, file_entry=current_helper.file_entry, show_hex=verbose)

    # Print a hexadecimal representation of all binary values.
    if verbose:
      header_shown = False
      current_key = current_helper.GetCurrentRegistryKey()
      for value in current_key.GetValues():
        if not value.DataIsBinaryData():
          continue

        if not header_shown:
          table_view = cli_views.CLITableView(
              title='Hexadecimal representation')
          header_shown = True
        else:
          table_view = cli_views.CLITableView()

        table_view.AddRow(['Attribute', value.name])
        table_view.Write(self.output_writer)

        self.console.preg_tool.PrintSeparatorLine()
        self.console.preg_tool.PrintSeparatorLine()

        value_string = hexdump.Hexdump.FormatData(value.data)
        self.output_writer.Write(value_string)
        self.output_writer.Write('\n')
        self.output_writer.Write('+-'*40)
        self.output_writer.Write('\n')

  @magic.line_magic('plugin')
  def ParseWithPlugin(self, line):
    """Parses a Windows Registry key using a specific plugin.

    Args:
      line (str): command line provide via the console.
    """
    if not self.console and not self.console.IsLoaded():
      self.output_writer.Write('No hive loaded, unable to parse.\n')
      return

    current_helper = self.console.current_helper
    if not current_helper:
      return

    if not line:
      self.output_writer.Write('No plugin name added.\n')
      return

    plugin_name = line
    if '-h' in line:
      items = line.split()
      if len(items) != 2:
        self.output_writer.Write('Wrong usage: plugin [-h] PluginName\n')
        return
      if items[0] == '-h':
        plugin_name = items[1]
      else:
        plugin_name = items[0]

    registry_file_type = current_helper.file_type
    registry_plugin_list = self.console.preg_tool.GetWindowsRegistryPlugins()
    plugin_object = registry_plugin_list.GetPluginObjectByName(
        registry_file_type, plugin_name)
    if not plugin_object:
      self.output_writer.Write(
          'No plugin named: {0:s} available for Registry type {1:s}\n'.format(
              plugin_name, registry_file_type))
      return

    key_paths = plugin_list.PluginList.GetKeyPathsFromPlugin(plugin_object)
    if not key_paths:
      self.output_writer.Write(
          'Plugin: {0:s} has no key information.\n'.format(line))
      return

    if '-h' in line:
      self._PrintPluginHelp(plugin_object)
      return

    for key_path in key_paths:
      registry_key = current_helper.GetKeyByPath(key_path)
      if not registry_key:
        self.output_writer.Write('Key: {0:s} not found\n'.format(key_path))
        continue

      # Move the current location to the key to be parsed.
      self.ChangeDirectory(key_path)
      # Parse the key.
      current_key = current_helper.GetCurrentRegistryKey()
      parsed_data = self.console.preg_tool.ParseRegistryKey(
          current_key, current_helper, use_plugins=[plugin_name])
      self.console.preg_tool.PrintParsedRegistryKey(
          parsed_data, file_entry=current_helper.file_entry)

  @magic.line_magic('pwd')
  def PrintCurrentWorkingDirectory(self, unused_line):
    """Print the current path.

    Args:
      line (str): command line provide via the console.
    """
    if not self.console and not self.console.IsLoaded():
      return

    current_helper = self.console.current_helper
    if not current_helper:
      return

    self.output_writer.Write('{0:s}\n'.format(
        current_helper.GetCurrentRegistryPath()))


class PregConsole(object):
  """Preg iPython console."""

  _BASE_FUNCTIONS = [
      ('cd key', 'Navigate the Registry like a directory structure.'),
      ('ls [-v]', (
          'List all subkeys and values of a Registry key. If called as ls '
          'True then values of keys will be included in the output.')),
      ('parse -[v]', 'Parse the current key using all plugins.'),
      ('plugin [-h] plugin_name', (
          'Run a particular key-based plugin on the loaded hive. The correct '
          'Registry key will be loaded, opened and then parsed.')),
      ('get_value value_name', (
          'Get a value from the currently loaded Registry key.')),
      ('get_value_data value_name', (
          'Get a value data from a value stored in the currently loaded '
          'Registry key.')),
      ('get_key', 'Return the currently loaded Registry key.')]

  @property
  def current_helper(self):
    """The currently loaded Registry helper."""
    return self._currently_registry_helper

  def __init__(self, tool):
    """Initialize a console.

    Args:
      tool (PregTool): preg tool.
    """
    super(PregConsole, self).__init__()
    self._currently_registry_helper = None
    self._currently_loaded_helper_path = ''
    self._registry_helpers = {}

    preferred_encoding = locale.getpreferredencoding()
    if not preferred_encoding:
      preferred_encoding = 'utf-8'

    # TODO: Make this configurable, or derive it from the tool.
    self._output_writer = cli_tools.StdoutOutputWriter(
        encoding=preferred_encoding)

    self.preg_tool = tool

  def _CommandGetCurrentKey(self):
    """Retreives the currently loaded Registry key.

    Returns:
      dfwinreg.WinRegistryKey: currently loaded Registry key or None if
          not available.
    """
    return self._currently_registry_helper.GetCurrentRegistryKey()

  def _CommandGetValue(self, value_name):
    """Retrieves a value from the currently loaded Windows Registry key.

    Args:
      value_name (str): name of the value to be retrieved.

    Returns:
      dfwinreg.WinRegistryValue: a Windows Registry value, or None if not
          available.
    """
    current_key = self._currently_registry_helper.GetCurrentRegistryKey()
    if current_key:
      return current_key.GetValueByName(value_name)

  def _CommandGetValueData(self, value_name):
    """Retrieves a value data from the currently loaded Windows Registry key.

    Args:
      value_name (str): name of the value to be retrieved.

    Returns:
      object: Windows Registry value data, or None if not available.
    """
    registry_value = self._CommandGetValue(value_name)
    if registry_value:
      return registry_value.GetDataAsObject()

  def AddRegistryHelper(self, registry_helper):
    """Add a Registry helper to the console object.

    Args:
      registry_helper (PregRegistryHelper): registry helper.

    Raises:
      ValueError: if not Registry helper is supplied or Registry helper is not
          the correct object (instance of PregRegistryHelper).
    """
    if not registry_helper:
      raise ValueError('No Registry helper supplied.')

    if not isinstance(registry_helper, helper.PregRegistryHelper):
      raise ValueError(
          'Object passed in is not an instance of PregRegistryHelper.')

    if registry_helper.path not in self._registry_helpers:
      self._registry_helpers[registry_helper.path] = registry_helper

  def GetConfig(self):
    """Retrieves the iPython configuration.

    Returns:
      IPython.terminal.embed.InteractiveShellEmbed: iPython configuration.
    """
    try:
      # The "get_ipython" function does not exist except within an IPython
      # session.
      return get_ipython()  # pylint: disable=undefined-variable
    except NameError:
      return Config()

  def IsLoaded(self):
    """Checks if a Windows Registry file is loaded.

    Returns:
      bool: True if a Registry helper is currently loaded, False otherwise.
    """
    registry_helper = self._currently_registry_helper
    if not registry_helper:
      return False

    current_key = registry_helper.GetCurrentRegistryKey()
    if hasattr(current_key, 'path'):
      return True

    if registry_helper.name != 'N/A':
      return True

    self._output_writer.Write(
        'No hive loaded, cannot complete action. Use "hive list" '
        'and "hive open" to load a hive.\n')
    return False

  def PrintBanner(self):
    """Writes a banner to the output writer."""
    self._output_writer.Write('\n')
    self._output_writer.Write(
        'Welcome to PREG - home of the Plaso Windows Registry Parsing.\n')

    table_view = cli_views.CLITableView(
        column_names=['Function', 'Description'], title='Available commands')
    for function_name, description in self._BASE_FUNCTIONS:
      table_view.AddRow([function_name, description])
    table_view.Write(self._output_writer)

    if len(self._registry_helpers) == 1:
      self.LoadRegistryFile(0)
      registry_helper = self._currently_registry_helper
      self._output_writer.Write(
          'Opening hive: {0:s} [{1:s}]\n'.format(
              registry_helper.path, registry_helper.collector_name))
      self.SetPrompt(registry_file_path=registry_helper.path)

    # TODO: make sure to limit number of characters per line of output.
    registry_helper = self._currently_registry_helper
    if registry_helper and registry_helper.name != 'N/A':
      self._output_writer.Write(
          'Registry file: {0:s} [{1:s}] is available and loaded.\n'.format(
              registry_helper.name, registry_helper.path))

    else:
      self._output_writer.Write('More than one Registry file ready for use.\n')
      self._output_writer.Write('\n')
      self.PrintRegistryFileList()
      self._output_writer.Write('\n')
      self._output_writer.Write((
          'Use "hive open INDEX" to load a Registry file and "hive list" to '
          'see a list of available Registry files.\n'))

    self._output_writer.Write('\nHappy command line console fu-ing.')

  def LoadRegistryFile(self, index):
    """Loads a Registry file helper from the list of Registry file helpers.

    Args:
      index (int): index of the Registry helper.

    Raises:
      UnableToLoadRegistryHelper: if the index attempts to load an entry
          that does not exist or if there are no Registry helpers loaded.
    """
    helper_keys = self._registry_helpers.keys()

    if not helper_keys:
      raise errors.UnableToLoadRegistryHelper('No Registry helpers loaded.')

    if index < 0 or index >= len(helper_keys):
      raise errors.UnableToLoadRegistryHelper('Index out of bounds.')

    if self._currently_registry_helper:
      self._currently_registry_helper.Close()

    registry_helper_path = helper_keys[index]
    self._currently_registry_helper = (
        self._registry_helpers[registry_helper_path])
    self._currently_loaded_helper_path = registry_helper_path

    self._currently_registry_helper.Open()

  def PrintRegistryFileList(self):
    """Prints a list of all available registry helpers."""
    if not self._registry_helpers:
      return

    self._output_writer.Write('Index Hive [collector]\n')
    for index, registry_helper in enumerate(self._registry_helpers.values()):
      collector_name = registry_helper.collector_name
      if not collector_name:
        collector_name = 'Currently Allocated'

      if self._currently_loaded_helper_path == registry_helper.path:
        star = '*'
      else:
        star = ''

      self._output_writer.Write('{0:<5d} {1:s}{2:s} [{3:s}]\n'.format(
          index, star, registry_helper.path, collector_name))

  def SetPrompt(
      self, registry_file_path=None, config=None, prepend_string=None):
    """Sets the prompt string on the console.

    Args:
      registry_file_path (Optional[str]): name or path of the Windows Registry
          file.
      config (Optional[IPython.terminal.embed.InteractiveShellEmbed]): iPython
          configuration, where None will attempt to automatically derive
          the configuration.
      prepend_string (Optional[str]): text to prepend in the command prompt.
    """
    if registry_file_path is None:
      path_string = 'Unknown Registry file loaded'
    else:
      path_string = registry_file_path

    prompt_strings = [
        r'[{color.LightBlue}\T{color.Normal}]',
        r'{color.LightPurple} ',
        path_string,
        r'\n{color.Normal}']
    if prepend_string is not None:
      prompt_strings.append('{0:s} '.format(prepend_string))
    prompt_strings.append(r'[{color.Red}\#{color.Normal}] \$ ')

    if config is None:
      ipython_config = self.GetConfig()
    else:
      ipython_config = config

    try:
      ipython_config.PromptManager.in_template = r''.join(prompt_strings)
    except AttributeError:
      ipython_config.prompt_manager.in_template = r''.join(prompt_strings)

  def Run(self):
    """Runs the interactive console."""
    source_type = self.preg_tool.source_type
    if source_type == dfvfs_definitions.SOURCE_TYPE_FILE:
      registry_file_types = []
    elif self.preg_tool.registry_file:
      registry_file_types = [self.preg_tool.registry_file]
    else:
      # No Registry type specified use all available types instead.
      registry_file_types = self.preg_tool.GetRegistryTypes()

    registry_helpers = self.preg_tool.GetRegistryHelpers(
        self.preg_tool.artifacts_registry,
        plugin_names=self.preg_tool.plugin_names,
        registry_file_types=registry_file_types)

    for registry_helper in registry_helpers:
      self.AddRegistryHelper(registry_helper)

    # Adding variables in scope.
    namespace = {}

    namespace.update(globals())
    namespace.update({
        'console': self,
        'get_current_key': self._CommandGetCurrentKey,
        'get_key': self._CommandGetCurrentKey,
        'get_value': self. _CommandGetValue,
        'get_value_data': self. _CommandGetValueData,
        'tool': self.preg_tool})

    ipshell_config = self.GetConfig()

    if len(self._registry_helpers) == 1:
      self.LoadRegistryFile(0)

    registry_helper = self._currently_registry_helper

    if registry_helper:
      registry_file_path = registry_helper.name
    else:
      registry_file_path = 'NO HIVE LOADED'

    self.SetPrompt(registry_file_path=registry_file_path, config=ipshell_config)

    # Starting the shell.
    ipshell = InteractiveShellEmbed(
        user_ns=namespace, config=ipshell_config, banner1='', exit_msg='')
    ipshell.confirm_exit = False

    self.PrintBanner()

    # Adding "magic" functions.
    ipshell.register_magics(PregMagics)
    PregMagics.console = self

    # Set autocall to two, making parenthesis not necessary when calling
    # function names (although they can be used and are necessary sometimes,
    # like in variable assignments, etc).
    ipshell.autocall = 2

    # Registering command completion for the magic commands.
    ipshell.set_hook(
        'complete_command', CommandCompleterCd, str_key='%cd')
    ipshell.set_hook(
        'complete_command', CommandCompleterVerbose, str_key='%ls')
    ipshell.set_hook(
        'complete_command', CommandCompleterVerbose, str_key='%parse')
    ipshell.set_hook(
        'complete_command', CommandCompleterPlugins, str_key='%plugin')

    ipshell()


# Completer commands need to be top level methods or directly callable
# and cannot be part of a class that needs to be initialized.
def CommandCompleterCd(console, unused_core_completer):
  """Command completer function for cd.

  Args:
    console: IPython shell object (instance of InteractiveShellEmbed).
  """
  return_list = []

  namespace = getattr(console, 'user_ns', {})
  magic_class = namespace.get('PregMagics', None)

  if not magic_class:
    return return_list

  if not magic_class.console.IsLoaded():
    return return_list

  registry_helper = magic_class.console.current_helper
  current_key = registry_helper.GetCurrentRegistryKey()
  for key in current_key.GetSubkeys():
    return_list.append(key.name)

  return return_list


# Completer commands need to be top level methods or directly callable
# and cannot be part of a class that needs to be initialized.
def CommandCompleterPlugins(console, core_completer):
  """Command completer function for plugins.

  Args:
    console: IPython shell object (instance of InteractiveShellEmbed).
    core_completer: IPython completer object (instance of completer.Bunch).

  Returns:
    A list of command options.
  """
  namespace = getattr(console, 'user_ns', {})
  magic_class = namespace.get('PregMagics', None)

  if not magic_class:
    return []

  if not magic_class.console.IsLoaded():
    return []

  command_options = []
  if not '-h' in core_completer.line:
    command_options.append('-h')

  registry_helper = magic_class.console.current_helper
  registry_file_type = registry_helper.file_type

  registry_plugin_list = console.preg_tool.GetWindowsRegistryPlugins()
  # TODO: refactor this into PluginsList.
  for plugin_cls in registry_plugin_list.GetKeyPlugins(registry_file_type):
    if plugin_cls.NAME == 'winreg_default':
      continue
    command_options.append(plugin_cls.NAME)

  return command_options


# Completer commands need to be top level methods or directly callable
# and cannot be part of a class that needs to be initialized.
def CommandCompleterVerbose(unused_console, core_completer):
  """Command completer function for verbose output.

  Args:
    core_completer: IPython completer object (instance of completer.Bunch).

  Returns:
    A list of command options.
  """
  if '-v' in core_completer.line:
    return []

  return ['-v']


def Main():
  """Run the tool."""
  tool = preg_tool.PregTool()

  if not tool.ParseArguments():
    return False

  if tool.run_mode == tool.RUN_MODE_LIST_PLUGINS:
    tool.ListPluginInformation()
  elif tool.run_mode == tool.RUN_MODE_REG_KEY:
    tool.RunModeRegistryKey()
  elif tool.run_mode == tool.RUN_MODE_REG_PLUGIN:
    tool.RunModeRegistryPlugin()
  elif tool.run_mode == tool.RUN_MODE_REG_FILE:
    tool.RunModeRegistryFile()
  elif tool.run_mode == tool.RUN_MODE_CONSOLE:
    preg_console = PregConsole(tool)
    preg_console.Run()

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
