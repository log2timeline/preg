# -*- coding: utf-8 -*-
"""Preg tool."""

from __future__ import print_function
from __future__ import unicode_literals

import argparse
import logging
import os
import textwrap

import pysmdev  # pylint: disable=wrong-import-order

from dfvfs.helpers import file_system_searcher
from dfvfs.helpers import windows_path_resolver
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.path import factory as path_spec_factory
from dfvfs.resolver import resolver as path_spec_resolver
from dfvfs.volume import tsk_volume_system

from plaso.lib import loggers
from plaso.cli import storage_media_tool
from plaso.cli import views as cli_views
from plaso.cli.helpers import manager as helpers_manager
from plaso.containers import sessions
from plaso.engine import knowledge_base
from plaso.lib import definitions as plaso_definitions
from plaso.lib import errors
from plaso.lib import py2to3
from plaso.lib import timelib
from plaso.parsers import manager as parsers_manager
from plaso.parsers import mediator as parsers_mediator
from plaso.parsers import winreg_plugins  # pylint: disable=unused-import
from plaso.preprocessors import manager as preprocess_manager
# TODO: refactor usage of fake storage.
from plaso.storage.fake import writer as fake_storage_writer

from l2tpreg import definitions
from l2tpreg import helper
from l2tpreg import hexdump
from l2tpreg import plugin_list


class PregTool(storage_media_tool.StorageMediaTool):
  """Preg CLI tool.

  Attributes:
    plugin_names (list[str]): names of selected Windows Registry plugins
        to be used.
    registry_file (str): path to a Windows Registry file or a Registry file
        type, e.g. NTUSER, SOFTWARE, etc.
    run_mode (str): the run mode of the tool, determines if the tool should
        be running in a plugin mode, parsing an entire Registry file, being
        run in a console, etc.
    source_type (str): dfVFS source type indicator for the source file.
  """

  # Assign a default value to font align length.
  _DEFAULT_FORMAT_ALIGN_LENGTH = 15

  _SOURCE_OPTION = 'image'

  _WINDOWS_DIRECTORIES = frozenset([
      'C:\\Windows',
      'C:\\WINNT',
      'C:\\WTSRV',
      'C:\\WINNT35',
  ])

  NAME = 'preg'

  DESCRIPTION = textwrap.dedent('\n'.join([
      'preg is a Windows Registry parser using the plaso Registry plugins ',
      'and storage media image parsing capabilities.',
      '',
      'It uses the back-end libraries of plaso to read raw image files and',
      'extract Registry files from VSS and restore points and then runs the',
      'Registry plugins of plaso against the Registry hive and presents it',
      'in a textual format.']))

  EPILOG = textwrap.dedent('\n'.join([
      '',
      'Example usage:',
      '',
      'Parse the SOFTWARE hive from an image:',
      ('  preg.py [--vss] [--vss-stores VSS_STORES] -i IMAGE_PATH '
       '[-o OFFSET] -c SOFTWARE'),
      '',
      'Parse an userassist key within an extracted hive:',
      '  preg.py -p userassist MYNTUSER.DAT',
      '',
      'Parse the run key from all Registry keys (in vss too):',
      '  preg.py --vss -i IMAGE_PATH [-o OFFSET] -p run',
      '',
      'Open up a console session for the SYSTEM hive inside an image:',
      '  preg.py -i IMAGE_PATH [-o OFFSET] -c SYSTEM',
      '']))

  # Define the different run modes.
  RUN_MODE_CONSOLE = 1
  RUN_MODE_LIST_PLUGINS = 2
  RUN_MODE_REG_FILE = 3
  RUN_MODE_REG_PLUGIN = 4
  RUN_MODE_REG_KEY = 5

  _EXCLUDED_ATTRIBUTE_NAMES = frozenset([
      'data_type',
      'display_name',
      'filename',
      'inode',
      'parser',
      'pathspec',
      'tag',
      'timestamp'])

  def __init__(self, input_reader=None, output_writer=None):
    """Initializes the CLI tool.

    Args:
      input_reader (Optional[InputReader]): input reader, where None indicates
          that the stdin input reader should be used.
      output_writer (Optional[OutputWriter]): output writer, where None
          indicates that the stdout output writer should be used.
    """
    super(PregTool, self).__init__(
        input_reader=input_reader, output_writer=output_writer)
    self._artifacts_registry = None
    self._key_path = None
    self._knowledge_base = knowledge_base.KnowledgeBase()
    self._mount_path_spec = None
    self._parse_restore_points = False
    self._path_resolvers = []
    self._preprocess_completed = False
    self._quiet = False
    self._registry_files = []
    self._registry_plugin_list = self.GetWindowsRegistryPlugins()
    self._single_file = False
    self._source_path = None
    self._source_path_specs = []
    self._verbose_output = False
    self._windows_directory = ''

    self.plugin_names = []
    self.registry_file = ''
    self.run_mode = None
    self.source_type = None

  @property
  def artifacts_registry(self):
    """artifacts.ArtifactDefinitionsRegistry: artifact definitions registry."""
    return self._artifacts_registry

  def _CreateWindowsPathResolver(
      self, file_system, mount_point, environment_variables):
    """Creates a Windows path resolver and sets the evironment variables.

    Args:
      file_system (dfvfs.FileSytem): file system.
      mount_point (dfvfs.PathSpec): mount point path specification.
      environment_variables (list[EnvironmentVariableArtifact]): environment
          variables.

    Returns:
      dfvfs.WindowsPathResolver: Windows path resolver.
    """
    if environment_variables is None:
      environment_variables = []

    path_resolver = windows_path_resolver.WindowsPathResolver(
        file_system, mount_point)

    for environment_variable in environment_variables:
      name = environment_variable.name.lower()
      if name != 'systemroot':
        continue

      path_resolver.SetEnvironmentVariable(
          environment_variable.name, environment_variable.value)

    return path_resolver

  def _ExpandKeysRedirect(self, keys):
    """Expands Windows Registry key paths with their redirect equivalents.

    Args:
      keys (list[str]): Windows Registry key paths.
    """
    for key in keys:
      if key.startswith('\\Software') and 'Wow6432Node' not in key:
        _, first, second = key.partition('\\Software')
        keys.append('{0:s}\\Wow6432Node{1:s}'.format(first, second))

  def _GetEventDataHexDump(
      self, event, before=0, maximum_number_of_lines=20):
    """Returns a hexadecimal representation of the event data.

     This function creates a hexadecimal string representation based on
     the event data described by the event object.

    Args:
      event (EventObject): event.
      before (Optional[int]): number of bytes to include in the output before
          the event.
      maximum_number_of_lines (Optional[int]): maximum number of lines to
          include in the output.

    Returns:
      str: hexadecimal representation of the event data.
    """
    if not event:
      return 'Missing event.'

    if not hasattr(event, 'pathspec'):
      return 'Event has no path specification.'

    try:
      file_entry = path_spec_resolver.Resolver.OpenFileEntry(event.pathspec)
    except IOError as exception:
      return 'Unable to open file with error: {0:s}'.format(exception)

    offset = getattr(event, 'offset', 0)
    if offset - before > 0:
      offset -= before

    file_object = file_entry.GetFileObject()
    file_object.seek(offset, os.SEEK_SET)
    data_size = maximum_number_of_lines * 16
    data = file_object.read(data_size)
    file_object.close()

    return hexdump.Hexdump.FormatData(data)

  def _GetFormatString(self, event):
    """Retrieves the format string for a given event object.

    Args:
      event (EventObject): event.

    Returns:
      str: format string.
    """
    # Go through the attributes and see if there is an attribute
    # value that is longer than the default font align length, and adjust
    # it accordingly if found.
    if hasattr(event, 'regvalue'):
      attributes = event.regvalue.keys()
    else:
      attribute_names = set(event.GetAttributeNames())
      attributes = attribute_names.difference(
          self._EXCLUDED_ATTRIBUTE_NAMES)

    align_length = self._DEFAULT_FORMAT_ALIGN_LENGTH
    for attribute in attributes:
      if attribute is None:
        attribute = ''

      attribute_len = len(attribute)
      if attribute_len > align_length and attribute_len < 30:
        align_length = len(attribute)

    # Create the format string that will be used, using variable length
    # font align length (calculated in the prior step).
    return '{{0:>{0:d}s}} : {{1!s}}'.format(align_length)

  def _GetRegistryFilePaths(self, registry_file_types):
    """Retrieves Windows Registry file paths.

    If the Windows Registry file type is not set this functions attempts
    to determine it based on the presence of specific Windows Registry keys.

    Args:
      registry_file_types (set[str]): Windows Registry file types, such as
          "NTUSER", "SOFTWARE".

    Returns:
      list[str]: paths of Windows Registry files.
    """
    restore_path = ''
    if self._parse_restore_points:
      restore_path = (
          '\\System Volume Information\\_restore.+\\RP[0-9]+\\snapshot\\')

    paths = []
    for registry_file_type in registry_file_types:
      if registry_file_type == definitions.REGISTRY_FILE_TYPE_NTUSER:
        paths.append('%UserProfile%\\NTUSER.DAT')
        if restore_path:
          paths.append('{0:s}\\_REGISTRY_USER_NTUSER_.+'.format(restore_path))

      elif registry_file_type == definitions.REGISTRY_FILE_TYPE_SAM:
        paths.append('%SystemRoot%\\System32\\config\\SAM')
        if restore_path:
          paths.append('{0:s}\\_REGISTRY_MACHINE_SAM'.format(restore_path))

      elif registry_file_type == definitions.REGISTRY_FILE_TYPE_SECURITY:
        paths.append('%SystemRoot%\\System32\\config\\SECURITY')
        if restore_path:
          paths.append(
              '{0:s}\\_REGISTRY_MACHINE_SECURITY'.format(restore_path))

      elif registry_file_type == definitions.REGISTRY_FILE_TYPE_SOFTWARE:
        paths.append('%SystemRoot%\\System32\\config\\SOFTWARE')
        if restore_path:
          paths.append(
              '{0:s}\\_REGISTRY_MACHINE_SOFTWARE'.format(restore_path))

      elif registry_file_type == definitions.REGISTRY_FILE_TYPE_SYSTEM:
        paths.append('%SystemRoot%\\System32\\config\\SYSTEM')
        if restore_path:
          paths.append('{0:s}\\_REGISTRY_MACHINE_SYSTEM'.format(restore_path))

      elif registry_file_type == definitions.REGISTRY_FILE_TYPE_USRCLASS:
        paths.append(
            '%UserProfile%\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat')
        if restore_path:
          paths.append(
              '{0:s}\\_REGISTRY_USER_USRCLASS_.+'.format(restore_path))

    return paths

  # TODO: refactor this function. Current implementation is too complex.
  # TODO: make method protected.
  def GetRegistryHelpers(
      self, artifacts_registry, registry_file_types=None, plugin_names=None,
      codepage='cp1252'):
    """Retrieves discovered Windows Registry helpers.

    Args:
    artifacts_registry (artifacts.ArtifactDefinitionsRegistry]): artifact
        definitions registry.
      registry_file_types (Optional[list[str]]): of Windows Registry file types,
          for example "NTUSER" or "SAM" that should be included.
      plugin_names (Optional[str]): names of the plugins or an empty string for
          all the plugins.
      codepage (str): codepage of the Windows Registry file.

    Returns:
      list[PregRegistryHelper]: Windows Registry helpers.

    Raises:
      ValueError: If neither registry_file_types nor plugin name is passed
          as a parameter.
    """
    if registry_file_types is None and plugin_names is None:
      raise ValueError(
          'Missing registry_file_types or plugin_name value.')

    if plugin_names is None:
      plugin_names = []
    else:
      plugin_names = [plugin_name.lower() for plugin_name in plugin_names]

    # TODO: use non-preprocess collector with filter to collect Registry files.
    if not self._single_file and not self._preprocess_completed:
      file_system, mount_point = self._GetSourceFileSystem(
          self._source_path_specs[0])
      try:
        preprocess_manager.PreprocessPluginsManager.RunPlugins(
            artifacts_registry, file_system, mount_point,
            self._knowledge_base)
        self._preprocess_completed = True
      finally:
        file_system.Close()

    # TODO: fix issue handling Windows paths
    if registry_file_types is None:
      registry_file_types = []

    types_from_plugins = (
        self._registry_plugin_list.GetRegistryTypesFromPlugins(plugin_names))
    registry_file_types.extend(types_from_plugins)

    if self._single_file:
      paths = [self._source_path]

    else:
      types = set()
      if registry_file_types:
        for registry_file_type in registry_file_types:
          types.add(registry_file_type.upper())
      else:
        for plugin_name in plugin_names:
          types.update(self._registry_plugin_list.GetRegistryTypes(plugin_name))

      paths = self._GetRegistryFilePaths(types)

    self._knowledge_base.SetCodepage(codepage)

    helpers_list = []
    for path in paths:
      for registry_helper in self._GetRegistryHelperFromPath(path, codepage):
        helpers_list.append(registry_helper)

    return helpers_list

  def _GetRegistryHelperFromPath(self, path, codepage):
    """Retrieves a Windows Registry helper from a path.

    Given a path to a Windows Registry file this function goes through
    all the discovered source path specifications (instances of dfvfs.PathSpec)
    and extracts Windows Registry helpers based on the supplied path.

    Args:
      path (str): path of the Windows Registry file.
      codepage (str): codepage of the Windows Registry file.

    Yields:
      PregRegistryHelper: Windows Registry helper.
    """
    environment_variables = self._knowledge_base.GetEnvironmentVariables()

    for source_path_spec in self._source_path_specs:
      if source_path_spec.type_indicator == dfvfs_definitions.TYPE_INDICATOR_OS:
        file_entry = path_spec_resolver.Resolver.OpenFileEntry(source_path_spec)
        if file_entry.IsFile():
          yield helper.PregRegistryHelper(file_entry, 'OS', codepage=codepage)
          continue

        # TODO: Change this into an actual mount point path spec.
        self._mount_path_spec = source_path_spec

      collector_name = source_path_spec.type_indicator
      parent_path_spec = getattr(source_path_spec, 'parent', None)
      if parent_path_spec and parent_path_spec.type_indicator == (
          dfvfs_definitions.TYPE_INDICATOR_VSHADOW):
        vss_store = getattr(parent_path_spec, 'store_index', 0)
        collector_name = 'VSS Store: {0:d}'.format(vss_store)

      file_system, mount_point = self._GetSourceFileSystem(source_path_spec)

      try:
        path_resolver = self._CreateWindowsPathResolver(
            file_system, mount_point, environment_variables)

        if path.startswith('%UserProfile%\\'):
          searcher = file_system_searcher.FileSystemSearcher(
              file_system, mount_point)

          user_profiles = []
          # TODO: determine the users path properly instead of relying on
          # common defaults. Note that these paths are language dependent.
          for user_path in ('/Documents and Settings/.+', '/Users/.+'):
            find_spec = file_system_searcher.FindSpec(
                location_regex=user_path, case_sensitive=False)
            for path_spec in searcher.Find(find_specs=[find_spec]):
              location = getattr(path_spec, 'location', None)
              if location:
                if location.startswith('/'):
                  location = '\\'.join(location.split('/'))
                user_profiles.append(location)

          for user_profile in user_profiles:
            path_resolver.SetEnvironmentVariable('UserProfile', user_profile)

            path_spec = path_resolver.ResolvePath(path)
            if not path_spec:
              continue

            file_entry = file_system.GetFileEntryByPathSpec(path_spec)
            if not file_entry:
              continue

            yield helper.PregRegistryHelper(
                file_entry, collector_name, codepage=codepage)

        else:
          path_spec = path_resolver.ResolvePath(path)
          if not path_spec:
            continue

          file_entry = file_system.GetFileEntryByPathSpec(path_spec)
          if not file_entry:
            continue

          yield helper.PregRegistryHelper(
              file_entry, collector_name, codepage=codepage)

      finally:
        file_system.Close()

  # TODO: remove after refactoring.
  def _GetRegistryPlugins(self, filter_string):
    """Retrieves the Windows Registry plugins based on a filter string.

    Args:
      filter_string (str): name of the plugin or an empty string for all
          the plugins.

    Returns:
      list[plaso.RegistryPlugin]: Windows Registry plugins.
    """
    return self._registry_plugin_list.GetRegistryPlugins(filter_string)

  # TODO: remove after refactoring.
  def _GetRegistryPluginsFromRegistryType(self, registry_file_type):
    """Retrieves the Windows Registry plugins based on a Registry type.

    Args:
      registry_file_type (str): Windows Registry file type, such as "NTUSER",
          "SOFTWARE".

    Returns:
      list[plaso.RegistryPlugin]: Windows Registry plugins.
    """
    return self._registry_plugin_list.GetRegistryPluginsFromRegistryType(
        registry_file_type)

  def _GetRegistryTypes(self, filter_string):
    """Retrieves the Windows Registry types based on a filter string.

    Args:
      filter_string (str): name of the plugin or an empty string for all
          the plugins.

    Returns:
      list[str]: Windows Registry types.
    """
    return self._registry_plugin_list.GetRegistryTypes(filter_string)

  # TODO: refactor, this is a duplicate of the function in engine.
  def _GetSourceFileSystem(self, source_path_spec, resolver_context=None):
    """Retrieves the file system of the source.

    The mount point path specification refers to either a directory or
    a volume on storage media device or image. It is needed by the dfVFS
    file system searcher (instance of dfvfs.FileSystemSearcher) to indicate
    the base location of the file system.

    Args:
      source_path_spec (dfvfs.PathSpec): source path specification of
          the file system.
      resolver_context (Optional[dfvfs.Context]): resolver context, where None
          will use the built in context which is not multi process safe. Note
          that every thread or process must have its own resolver context.

    Returns:
      tuple: contains:

      * dfvfs.FileSystem: file system.
      * dfvfs.PathSpec: mount point path specification.

    Raises:
      RuntimeError: if source path specification is not set.
    """
    if not source_path_spec:
      raise RuntimeError('Missing source.')

    file_system = path_spec_resolver.Resolver.OpenFileSystem(
        source_path_spec, resolver_context=resolver_context)

    type_indicator = source_path_spec.type_indicator
    if path_spec_factory.Factory.IsSystemLevelTypeIndicator(type_indicator):
      mount_point = source_path_spec
    else:
      mount_point = source_path_spec.parent

    return file_system, mount_point

  def _GetTSKPartitionIdentifiers(
      self, scan_node, partition_offset=None, partitions=None):
    """Determines the TSK partition identifiers.

    This method first checks for the preferred partition number, then for
    the preferred partition offset and falls back to prompt the user if
    no usable preferences were specified.

    Args:
      scan_node (dfvfs.SourceScanNode): scan node.
      partition_offset (Optional[int]): preferred partition byte offset.
      paritions (Optional[list[str]]): preferred partition identifiers.

    Returns:
      list[str]: partition identifiers.

    Raises:
      RuntimeError: if the volume for a specific identifier cannot be
          retrieved.
      SourceScannerError: if the format of or within the source
          is not supported or the the scan node is invalid.
    """
    if not scan_node or not scan_node.path_spec:
      raise errors.SourceScannerError('Invalid scan node.')

    volume_system = tsk_volume_system.TSKVolumeSystem()
    volume_system.Open(scan_node.path_spec)

    # TODO: refactor to front-end.
    volume_identifiers = self._source_scanner.GetVolumeIdentifiers(
        volume_system)
    if not volume_identifiers:
      logging.info('No partitions found.')
      return

    # Go over all the detected volume identifiers and only include
    # detected Windows partitions.
    windows_volume_identifiers = self.GetWindowsVolumeIdentifiers(
        scan_node, volume_identifiers)

    if not windows_volume_identifiers:
      logging.error('No Windows partitions discovered.')
      return windows_volume_identifiers

    if partitions == ['all']:
      return windows_volume_identifiers

    partition_string = None
    if partitions:
      partition_string = partitions[0]

    if partition_string is not None and not partition_string.startswith('p'):
      return windows_volume_identifiers

    partition_number = None
    if partition_string:
      try:
        partition_number = int(partition_string[1:], 10)
      except ValueError:
        pass

    if partition_number is not None and partition_number > 0:
      # Plaso uses partition numbers starting with 1 while dfvfs expects
      # the volume index to start with 0.
      volume = volume_system.GetVolumeByIndex(partition_number - 1)
      partition_string = 'p{0:d}'.format(partition_number)
      if volume and partition_string in windows_volume_identifiers:
        return [partition_string]

      logging.warning('No such partition: {0:d}.'.format(partition_number))

    if partition_offset is not None:
      for volume in volume_system.volumes:
        volume_extent = volume.extents[0]
        if volume_extent.offset == partition_offset:
          return [volume.identifier]

      logging.warning(
          'No such partition with offset: {0:d} (0x{0:08x}).'.format(
              partition_offset))

    if len(windows_volume_identifiers) == 1:
      return windows_volume_identifiers

    try:
      selected_volume_identifier = self._PromptUserForPartitionIdentifier(
          volume_system, windows_volume_identifiers)
    except KeyboardInterrupt:
      raise errors.UserAbort('File system scan aborted.')

    if selected_volume_identifier == 'all':
      return windows_volume_identifiers

    return [selected_volume_identifier]

  def _ParseRegistryFile(
      self, registry_helper, key_paths=None, use_plugins=None):
    """Extracts information from a Windows Registry file.

    This function takes a Windows Registry helper (instance of
    PregRegistryHelper) and information about either Windows Registry plugins
    or keys. The function then open the Windows Registry file and runs
    the plugins defined (or all if no plugins are defined) against all the keys
    supplied to it.

    Args:
      registry_helper (PregRegistryHelper): Windows Registry helper.
      key_paths (Optional[list[str]]): Windows Registry keys paths that are
          to be parsed, where None indicates no keys to parse.
      use_plugins (Optional[list[str]]): names of the plugins used to parse
          the Windows Regisry key, where None indicates all plugins to be used.

    Returns:
      dict[str, object]: extracted events per key path. For example: {
          key_path:
              key: a Registry key (instance of dfwinreg.WinRegistryKey)
              subkeys: a list of Registry keys (instance of
                       dfwinreg.WinRegistryKey).
              data:
                plugin: a plugin object (instance of RegistryPlugin)
                  event_objects: List of event objects extracted.

          key_path 2:
              ... }
    """
    if not registry_helper:
      return {}

    try:
      registry_helper.Open()
    except IOError as exception:
      logging.error('Unable to parse Registry file, with error: {0:s}'.format(
          exception))
      return {}

    return_dict = {}
    if key_paths is None:
      key_paths = []

    for key_path in key_paths:
      registry_key = registry_helper.GetKeyByPath(key_path)
      return_dict[key_path] = {'key': registry_key}

      if not registry_key:
        continue

      return_dict[key_path]['subkeys'] = list(registry_key.GetSubkeys())

      return_dict[key_path]['data'] = self.ParseRegistryKey(
          registry_key, registry_helper, use_plugins=use_plugins)

    return return_dict

  # TODO: Improve check and use dfVFS.
  def _PathExists(self, path):
    """Determine if a given file path exists.

    Args:
      path (str): path of the file to check.

    Returns:
      tuple: contains:

      * bool: True if the path exists, False if not.
      * str: reason if path not exists.
    """
    if os.path.exists(path):
      return True, ''

    try:
      if pysmdev.check_device(path):
        return True, ''

    except IOError as exception:
      return False, 'Unable to determine, with error: {0:s}'.format(exception)

    return False, 'Not an existing file.'

  def _PrintEventBody(self, event, file_entry=None, show_hex=False):
    """Writes a list of strings extracted from an event to an output writer.

    Args:
      event (EventObject): event.
      file_entry (Optional[dfvfs.FileEntry]): file entry from which the event
          originated from.
      show_hex (Optional[bool]): True if the hexadecimal representation of
          the event data should be included in the output.
    """
    format_string = self._GetFormatString(event)

    timestamp_description = getattr(
        event, 'timestamp_desc', plaso_definitions.TIME_DESCRIPTION_WRITTEN)

    if timestamp_description != plaso_definitions.TIME_DESCRIPTION_WRITTEN:
      self._output_writer.Write('<{0:s}>\n'.format(timestamp_description))

    if hasattr(event, 'regvalue'):
      attributes = event.regvalue
    else:
      # TODO: Add a function for this to avoid repeating code.
      attribute_names = set(event.GetAttributeNames())
      keys = attribute_names.difference(self._EXCLUDED_ATTRIBUTE_NAMES)
      keys.discard('offset')
      keys.discard('timestamp_desc')
      attributes = {}
      for key in keys:
        attributes[key] = getattr(event, key)

    for attribute, value in attributes.items():
      self._output_writer.Write('\t')
      self._output_writer.Write(format_string.format(attribute, value))
      self._output_writer.Write('\n')

    if show_hex and file_entry:
      event.pathspec = file_entry.path_spec
      hexadecimal_output = self._GetEventDataHexDump(event)

      self.PrintHeader('Hexadecimal output from event.', character='-')
      self._output_writer.Write(hexadecimal_output)
      self._output_writer.Write('\n')

  def _PrintEventHeader(self, event, descriptions, exclude_timestamp):
    """Writes a list of strings that contains a header for the event.

    Args:
      event (EventObject): event.
      descriptions (list[str]): descriptions of the timestamps.
      exclude_timestamp (bool): True if the timestamp should not be included
          in the header.
    """
    format_string = self._GetFormatString(event)

    self._output_writer.Write('Key information.\n')
    if not exclude_timestamp:
      for description in descriptions:
        date_time_string = timelib.Timestamp.CopyToIsoFormat(event.timestamp)
        output_text = format_string.format(description, date_time_string)
        self._output_writer.Write(output_text)
        self._output_writer.Write('\n')

    key_path = getattr(event, 'key_path', None)
    if key_path:
      output_string = format_string.format('Key Path', key_path)
      self._output_writer.Write(output_string)
      self._output_writer.Write('\n')

    if event.timestamp_desc != plaso_definitions.TIME_DESCRIPTION_WRITTEN:
      self._output_writer.Write(format_string.format(
          'Description', event.timestamp_desc))
      self._output_writer.Write('\n')

    self.PrintHeader('Data', character='+')

  def _PrintEventObjectsBasedOnTime(self, events, file_entry, show_hex=False):
    """Write extracted data from a list of event objects to an output writer.

    This function groups together a list of event objects based on timestamps.
    If more than one event are extracted with the same timestamp the timestamp
    itself is not repeated.

    Args:
      events (list[EventObject]): events.
      file_entry (Optional[dfvfs.FileEntry]): file entry from which the event
          originated from.
      show_hex (Optional[bool]): True if the hexadecimal representation of
          the event data should be included in the output.
    """
    events_and_timestamps = {}
    for event in events:
      timestamp = event.timestamp
      _ = events_and_timestamps.setdefault(timestamp, [])
      events_and_timestamps[timestamp].append(event)

    list_of_timestamps = sorted(events_and_timestamps.keys())

    exclude_timestamp_in_header = len(list_of_timestamps) > 1

    first_timestamp = list_of_timestamps[0]
    first_event = events_and_timestamps[first_timestamp][0]
    descriptions = set()
    for event in events_and_timestamps[first_timestamp]:
      descriptions.add(getattr(event, 'timestamp_desc', ''))
    self._PrintEventHeader(
        first_event, list(descriptions), exclude_timestamp_in_header)

    for event_timestamp in list_of_timestamps:
      if exclude_timestamp_in_header:
        date_time_string = timelib.Timestamp.CopyToIsoFormat(event_timestamp)
        output_text = '\n[{0:s}]\n'.format(date_time_string)
        self._output_writer.Write(output_text)

      for event in events_and_timestamps[event_timestamp]:
        self._PrintEventBody(
            event, file_entry=file_entry, show_hex=show_hex)

  def _PrintParsedRegistryFile(self, parsed_data, registry_helper):
    """Write extracted data from a Registry file to an output writer.

    Args:
      parsed_data (dict[str, object]): extracted events per key path.
      registry_helper (PregRegistryHelper): Windows Registry helper.
    """
    self.PrintHeader('Registry File', character='x')
    self._output_writer.Write('\n')
    self._output_writer.Write(
        '{0:>15} : {1:s}\n'.format('Registry file', registry_helper.path))
    self._output_writer.Write(
        '{0:>15} : {1:s}\n'.format(
            'Registry file type', registry_helper.file_type))
    if registry_helper.collector_name:
      self._output_writer.Write(
          '{0:>15} : {1:s}\n'.format(
              'Registry Origin', registry_helper.collector_name))

    self._output_writer.Write('\n\n')

    for key_path, data in iter(parsed_data.items()):
      self._PrintParsedRegistryInformation(
          key_path, data, registry_helper.file_entry)

    self.PrintSeparatorLine()

  def _PrintParsedRegistryInformation(
      self, key_path, parsed_data, file_entry=None):
    """Write extracted data from a Registry key to an output writer.

    Args:
      key_path (str): path of the parsed Windows Registry key.
      parsed_data (dict[str, object]): extracted events per key path.
      file_entry (Optional[dfvfs.FileEntry]): file entry from which the event
          originated from.
    """
    registry_key = parsed_data.get('key', None)
    if registry_key:
      self._output_writer.Write('{0:>15} : {1:s}\n'.format(
          'Key Name', key_path))
    elif not self._quiet:
      self._output_writer.Write('Unable to open key: {0:s}\n'.format(
          key_path))
      return
    else:
      return

    self._output_writer.Write(
        '{0:>15} : {1:d}\n'.format(
            'Subkeys', registry_key.number_of_subkeys))
    self._output_writer.Write('{0:>15} : {1:d}\n'.format(
        'Values', registry_key.number_of_values))
    self._output_writer.Write('\n')

    if self._verbose_output:
      subkeys = parsed_data.get('subkeys', [])
      for subkey in subkeys:
        self._output_writer.Write(
            '{0:>15} : {1:s}\n'.format('Key Name', subkey.path))

    key_data = parsed_data.get('data', None)
    if not key_data:
      return

    self.PrintParsedRegistryKey(
        key_data, file_entry=file_entry, show_hex=self._verbose_output)

  def _ScanFileSystem(self, path_resolver):
    """Scans a file system for the Windows volume.

    Args:
      path_resolver (dfvfs.WindowsPathResolver): the Windos path resolver.

    Returns:
      bool: True if the Windows directory was found, False otherwise.
    """
    result = False

    for windows_path in self._WINDOWS_DIRECTORIES:
      windows_path_spec = path_resolver.ResolvePath(windows_path)

      result = windows_path_spec is not None
      if result:
        self._windows_directory = windows_path
        break

    return result

  def GetWindowsRegistryPlugins(self):
    """Build a list of all available Windows Registry plugins.

    Returns:
      PluginList: Windows Registry plugin list.
    """
    winreg_parser = parsers_manager.ParsersManager.GetParserObjectByName(
        'winreg')
    if not winreg_parser:
      return

    registry_plugin_list = plugin_list.PluginList()
    for _, plugin_class in winreg_parser.GetPlugins():
      registry_plugin_list.AddPlugin(plugin_class)
    return registry_plugin_list

  def GetWindowsVolumeIdentifiers(self, scan_node, volume_identifiers):
    """Determines and returns back a list of Windows volume identifiers.

    Args:
      scan_node (dfvfs.ScanNode): scan node.
      volume_identifiers (list[str]): allowed volume identifiers.

    Returns:
      list[str]: volume identifiers that have Windows partitions.
    """
    windows_volume_identifiers = []
    for sub_node in scan_node.sub_nodes:
      path_spec = getattr(sub_node, 'path_spec', None)
      if not path_spec:
        continue

      type_indicator = path_spec.TYPE_INDICATOR
      if type_indicator != dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION:
        continue

      location = getattr(path_spec, 'location', '')
      if not location:
        continue

      if location.startswith('/'):
        location = location[1:]

      if location not in volume_identifiers:
        continue

      selected_node = sub_node
      while selected_node.sub_nodes:
        selected_node = selected_node.sub_nodes[0]

      file_system = path_spec_resolver.Resolver.OpenFileSystem(
          selected_node.path_spec)
      path_resolver = windows_path_resolver.WindowsPathResolver(
          file_system, selected_node.path_spec)

      if self._ScanFileSystem(path_resolver):
        windows_volume_identifiers.append(location)

    return windows_volume_identifiers

  def ListPluginInformation(self):
    """Lists Registry plugin information."""
    table_view = cli_views.CLITableView(title='Supported Plugins')
    registry_plugin_list = self._registry_plugin_list
    for plugin_class in registry_plugin_list.GetAllPlugins():
      table_view.AddRow([plugin_class.NAME, plugin_class.DESCRIPTION])
    table_view.Write(self._output_writer)

  def ParseArguments(self):
    """Parses the command line arguments.

    Returns:
      bool: True if the arguments were successfully parsed.
    """
    loggers.ConfigureLogging()

    argument_parser = argparse.ArgumentParser(
        description=self.DESCRIPTION, epilog=self.EPILOG, add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    self.AddBasicOptions(argument_parser)

    additional_options = argument_parser.add_argument_group(
        'Additional Options')

    additional_options.add_argument(
        '-r', '--restore-points', '--restore_points',
        dest='restore_points', action='store_true', default=False,
        help='Include restore points in the Registry file locations.')

    self.AddVSSProcessingOptions(additional_options)

    image_options = argument_parser.add_argument_group('Image Options')

    image_options.add_argument(
        '-i', '--image', dest=self._SOURCE_OPTION, action='store',
        type=str, default='', metavar='IMAGE_PATH', help=(
            'If the Registry file is contained within a storage media image, '
            'set this option to specify the path of image file.'))

    self.AddStorageMediaImageOptions(image_options)

    processing_group = argument_parser.add_argument_group(
        'Processing Arguments')

    helpers_manager.ArgumentHelperManager.AddCommandLineArguments(
        processing_group, names=['data_location'])

    extraction_group = argument_parser.add_argument_group(
        'Extraction Arguments')

    helpers_manager.ArgumentHelperManager.AddCommandLineArguments(
        extraction_group, names=['artifact_definitions'])

    info_options = argument_parser.add_argument_group('Informational Options')

    info_options.add_argument(
        '--info', dest='show_info', action='store_true', default=False,
        help='Print out information about supported plugins.')

    info_options.add_argument(
        '-v', '--verbose', dest='verbose', action='store_true',
        default=False, help='Print sub key information.')

    info_options.add_argument(
        '-q', '--quiet', dest='quiet', action='store_true', default=False,
        help='Do not print out key names that the tool was unable to open.')

    mode_options = argument_parser.add_argument_group('Run Mode Options')

    mode_options.add_argument(
        '-c', '--console', dest='console', action='store_true',
        default=False, help=(
            'Drop into a console session Instead of printing output '
            'to STDOUT.'))

    mode_options.add_argument(
        '-k', '--key', dest='key', action='store', default='',
        type=str, metavar='REGISTRY_KEYPATH', help=(
            'A Registry key path that the tool should parse using all '
            'available plugins.'))

    mode_options.add_argument(
        '-p', '--plugins', dest='plugin_names', action='append', default=[],
        type=str, metavar='PLUGIN_NAME', help=(
            'Substring match of the Registry plugin to be used, this '
            'parameter can be repeated to create a list of plugins to be '
            'run against, e.g. "-p userassist -p rdp" or "-p userassist".'))

    argument_parser.add_argument(
        'registry_file', action='store', metavar='REGHIVE', nargs='?',
        help=(
            'The Registry hive to read key from (not needed if running '
            'using a plugin)'))

    try:
      options = argument_parser.parse_args()
    except UnicodeEncodeError:
      # If we get here we are attempting to print help in a non-Unicode
      # terminal.
      self._output_writer.Write('\n')
      self._output_writer.Write(argument_parser.format_help())
      self._output_writer.Write('\n')
      return False

    try:
      self.ParseOptions(options)
    except errors.BadConfigOption as exception:
      logging.error('{0:s}'.format(exception))

      self._output_writer.Write('\n')
      self._output_writer.Write(argument_parser.format_help())
      self._output_writer.Write('\n')

      return False

    return True

  def ParseOptions(self, options):
    """Parses the options.

    Args:
      options (argparse.Namespace): command line arguments.

    Raises:
      BadConfigOption: if the options are invalid.
    """
    if getattr(options, 'show_info', False):
      self.run_mode = self.RUN_MODE_LIST_PLUGINS
      return

    registry_file = getattr(options, 'registry_file', None)
    image = self.ParseStringOption(options, self._SOURCE_OPTION)
    source_path = None
    if image:
      # TODO: refactor, there should be no need for separate code paths.
      source_path = image
      self._single_file = False
    else:
      self._ParseInformationalOptions(options)
      source_path = registry_file
      self._single_file = True

    helpers_manager.ArgumentHelperManager.ParseOptions(
        options, self, names=['data_location'])

    helpers_manager.ArgumentHelperManager.ParseOptions(
        options, self, names=['artifact_definitions'])

    if source_path is None:
      raise errors.BadConfigOption('No source path set.')

    self._source_path = os.path.abspath(source_path)

    if not image and not registry_file:
      raise errors.BadConfigOption('Not enough parameters to proceed.')

    if registry_file:
      if not image and not os.path.isfile(registry_file):
        raise errors.BadConfigOption(
            'Registry file: {0:s} does not exist.'.format(registry_file))

    self._key_path = self.ParseStringOption(options, 'key')
    self._parse_restore_points = getattr(options, 'restore_points', False)

    self._quiet = getattr(options, 'quiet', False)

    self._verbose_output = getattr(options, 'verbose', False)

    if image:
      file_to_check = image
    else:
      file_to_check = registry_file

    is_file, reason = self._PathExists(file_to_check)
    if not is_file:
      raise errors.BadConfigOption(
          'Unable to read the input file with error: {0:s}'.format(reason))

    # TODO: make sure encoded plugin names are handled correctly.
    self.plugin_names = getattr(options, 'plugin_names', [])

    if getattr(options, 'console', False):
      self.run_mode = self.RUN_MODE_CONSOLE
    elif self._key_path and registry_file:
      self.run_mode = self.RUN_MODE_REG_KEY
    elif self.plugin_names:
      self.run_mode = self.RUN_MODE_REG_PLUGIN
    elif registry_file:
      self.run_mode = self.RUN_MODE_REG_FILE
    else:
      raise errors.BadConfigOption(
          'Incorrect usage. You\'ll need to define the path of either '
          'a storage media image or a Windows Registry file.')

    self.registry_file = registry_file

    scan_context = self.ScanSource(self._source_path)
    self.source_type = scan_context.source_type

  def PrintHeader(self, text, character='*'):
    """Prints the header as a line with centered text.

    Args:
      text (str): header text.
      character (Optional[str]): header line character.
    """
    self._output_writer.Write('\n')

    format_string = '{{0:{0:s}^{1:d}}}\n'.format(character, self._LINE_LENGTH)
    header_string = format_string.format(' {0:s} '.format(text))
    self._output_writer.Write(header_string)

  def ParseRegistryKey(self, registry_key, registry_helper, use_plugins=None):
    """Extracts information from a Windows Registry key.

    Parses the Windows Registry key either using the supplied plugin or
    trying against all available plugins.

    Args:
      registry_key (dfwinreg.WinRegistryKey|str): Windows Registry key or
          key path to parse.
      registry_helper (PregRegistryHelper): Windows Registry helper.
      use_plugins (Optional[list[str]]): names of plugin to use, where None
          indicates to use all available plugins.

    Returns:
      dict[str, object]: extracted events per key path. For example: {
          key_path:
              key: a Registry key (instance of dfwinreg.WinRegistryKey)
              subkeys: a list of Registry keys (instance of
                       dfwinreg.WinRegistryKey).
              data:
                plugin: a plugin object (instance of RegistryPlugin)
                  event_objects: List of event objects extracted.

          key_path 2:
              ... }
    """
    if not registry_helper:
      return {}

    if isinstance(registry_key, py2to3.STRING_TYPES):
      registry_key = registry_helper.GetKeyByPath(registry_key)

    if not registry_key:
      return {}

    # TODO: refactor usage of fake storage.
    session = sessions.Session()
    storage_writer = fake_storage_writer.FakeStorageWriter(session)
    storage_writer.Open()

    parser_mediator = parsers_mediator.ParserMediator(
        storage_writer, self._knowledge_base)

    parser_mediator.SetFileEntry(registry_helper.file_entry)

    return_dict = {}
    found_matching_plugin = False
    for plugin_object in self._registry_plugin_list.GetPluginObjects(
        registry_helper.file_type):
      if use_plugins and plugin_object.NAME not in use_plugins:
        continue

      # Check if plugin should be processed.
      can_process = False
      for filter_object in plugin_object.FILTERS:
        if filter_object.Match(registry_key):
          can_process = True
          break

      if not can_process:
        continue

      found_matching_plugin = True
      plugin_object.Process(parser_mediator, registry_key)

      events = list(storage_writer.GetEvents())
      if events:
        return_dict[plugin_object] = events

    if not found_matching_plugin:
      winreg_parser = parsers_manager.ParsersManager.GetParserObjectByName(
          'winreg')
      if not winreg_parser:
        return

      default_plugin_object = winreg_parser.GetPluginObjectByName(
          'winreg_default')

      default_plugin_object.Process(parser_mediator, registry_key)

      events = list(storage_writer.GetEvents())
      if events:
        return_dict[default_plugin_object] = events

    return return_dict

  def PrintParsedRegistryKey(self, key_data, file_entry=None, show_hex=False):
    """Write extracted data returned from ParseRegistryKey to an output writer.

    Args:
      key_data (dict[str, object]): extracted events per key path.
      file_entry (Optional[dfvfs.FileEntry]): file entry from which the event
          originated from.
      show_hex (Optional[bool]): True if the hexadecimal representation of
          the event data should be included in the output.
    """
    self.PrintHeader('Plugins', character='-')
    for plugin, events in iter(key_data.items()):
      # TODO: make this a table view.
      self.PrintHeader('Plugin: {0:s}'.format(plugin.plugin_name))
      self._output_writer.Write('{0:s}\n'.format(plugin.DESCRIPTION))
      if plugin.URLS:
        self._output_writer.Write(
            'Additional information can be found here:\n')

        for url in plugin.URLS:
          self._output_writer.Write('{0:>17s} {1:s}\n'.format('URL :', url))

      if not events:
        continue

      self._PrintEventObjectsBasedOnTime(
          events, file_entry, show_hex=show_hex)

    self.PrintSeparatorLine()
    self._output_writer.Write('\n\n')

  def RunModeRegistryFile(self):
    """Runs against a Registry file.

    Finds and opens all Registry hives as configured in the configuration
    object and determines the type of Registry file opened. Then it will
    load up all the Registry plugins suitable for that particular Registry
    file, find all Registry keys they are able to parse and run through
    them, one by one.
    """
    registry_helpers = self.GetRegistryHelpers(
        self._artifacts_registry, registry_file_types=[self.registry_file])

    for registry_helper in registry_helpers:
      try:
        registry_helper.Open()

        self._PrintParsedRegistryFile({}, registry_helper)
        plugins_to_run = self._GetRegistryPluginsFromRegistryType(
            registry_helper.file_type)

        for plugin in plugins_to_run:
          key_paths = plugin_list.PluginList.GetKeyPathsFromPlugin(plugin)
          self._ExpandKeysRedirect(key_paths)
          for key_path in key_paths:
            key = registry_helper.GetKeyByPath(key_path)
            if not key:
              continue
            parsed_data = self.ParseRegistryKey(
                key, registry_helper, use_plugins=[plugin.NAME])
            self.PrintParsedRegistryKey(
                parsed_data, file_entry=registry_helper.file_entry,
                show_hex=self._verbose_output)
      finally:
        registry_helper.Close()
        self.PrintSeparatorLine()

  def RunModeRegistryKey(self):
    """Runs against a specific Registry key.

    Finds and opens all Registry hives as configured in the configuration
    object and tries to open the Registry key that is stored in the
    configuration object for every detected hive file and parses it using
    all available plugins.
    """
    registry_helpers = self.etRegistryHelpers(
        self._artifacts_registry, plugin_names=self.plugin_names,
        registry_file_types=[self.registry_file])

    key_paths = [self._key_path]

    # Expand the keys paths if there is a need (due to Windows redirect).
    self._ExpandKeysRedirect(key_paths)

    for registry_helper in registry_helpers:
      parsed_data = self._ParseRegistryFile(
          registry_helper, key_paths=key_paths)
      self._PrintParsedRegistryFile(parsed_data, registry_helper)

  def RunModeRegistryPlugin(self):
    """Runs against a set of Registry plugins."""
    # TODO: Add support for splitting the output to separate files based on
    # each plugin name.
    registry_helpers = self.GetRegistryHelpers(
        self._artifacts_registry, plugin_names=self.plugin_names)

    plugins = []
    for plugin_name in self.plugin_names:
      registry_plugin = self._GetRegistryPlugins(plugin_name)
      plugins.extend(registry_plugin)
    plugin_names = [plugin.NAME for plugin in plugins]

    # In order to get all the Registry keys we need to expand them.
    if not registry_helpers:
      return

    registry_helper = registry_helpers[0]
    key_paths = []
    registry_plugin_list = self._registry_plugin_list
    try:
      registry_helper.Open()

      # Get all the appropriate keys from these plugins.
      key_paths = registry_plugin_list.GetKeyPaths(plugin_names=plugin_names)

    finally:
      registry_helper.Close()

    for registry_helper in registry_helpers:
      parsed_data = self._ParseRegistryFile(
          registry_helper, key_paths=key_paths, use_plugins=plugin_names)
      self._PrintParsedRegistryFile(parsed_data, registry_helper)
