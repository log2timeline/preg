#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Parse your Windows Registry files using preg.

preg is a simple Windows Registry parser using the plaso Registry plugins and
image parsing capabilities. It uses the back-end libraries of plaso to read
raw image files and extract Registry files from VSS and restore points and then
runs the Registry plugins of plaso against the Registry hive and presents it
in a textual format.
"""

from __future__ import print_function
import argparse
import locale
import logging
import os
import sys
import textwrap

import IPython
import pysmdev  # pylint: disable=wrong-import-order

from dfvfs.helpers import file_system_searcher
from dfvfs.helpers import windows_path_resolver
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.path import factory as path_spec_factory
from dfvfs.resolver import resolver as path_spec_resolver
from dfvfs.volume import tsk_volume_system

from dfwinreg import registry as dfwinreg_registry

# pylint: disable=import-error
# pylint: disable=no-name-in-module
try:
  # Support version 1.x of IPython.
  from IPython.terminal.embed import InteractiveShellEmbed
except ImportError:
  from IPython.frontend.terminal.embed import InteractiveShellEmbed

from IPython.config.loader import Config
from IPython.core import magic

from plaso.cli import hexdump
from plaso.cli import storage_media_tool
from plaso.cli import tools as cli_tools
from plaso.cli import views as cli_views
from plaso.containers import sessions
from plaso.engine import knowledge_base
from plaso.frontend import extraction_frontend
from plaso.lib import errors
from plaso.lib import eventdata
from plaso.lib import py2to3
from plaso.lib import timelib
from plaso.parsers import mediator as parsers_mediator
from plaso.parsers import manager as parsers_manager
from plaso.parsers import winreg
from plaso.parsers import winreg_plugins  # pylint: disable=unused-import
from plaso.preprocessors import manager as preprocess_manager
# TODO: refactor usage of fake storage.
from plaso.storage import fake_storage


# Older versions of IPython don't have a version_info attribute.
if getattr(IPython, u'version_info', (0, 0, 0)) < (1, 2, 1):
  raise ImportWarning(
      u'Preg requires at least IPython version 1.2.1.')


# The Registry (file) types.
REGISTRY_FILE_TYPE_NTUSER = u'NTUSER'
REGISTRY_FILE_TYPE_SAM = u'SAM'
REGISTRY_FILE_TYPE_SECURITY = u'SECURITY'
REGISTRY_FILE_TYPE_SOFTWARE = u'SOFTWARE'
REGISTRY_FILE_TYPE_SYSTEM = u'SYSTEM'
REGISTRY_FILE_TYPE_UNKNOWN = u'UNKNOWN'
REGISTRY_FILE_TYPE_USRCLASS = u'USRCLASS'

REGISTRY_FILE_TYPES = frozenset([
    REGISTRY_FILE_TYPE_NTUSER,
    REGISTRY_FILE_TYPE_SAM,
    REGISTRY_FILE_TYPE_SECURITY,
    REGISTRY_FILE_TYPE_SOFTWARE,
    REGISTRY_FILE_TYPE_SYSTEM,
    REGISTRY_FILE_TYPE_USRCLASS])


# TODO: add tests for this class.
class PluginList(object):
  """A simple class that stores information about Windows Registry plugins."""

  def __init__(self):
    """Initializes the plugin list object."""
    super(PluginList, self).__init__()
    self._plugins = {}

  def __iter__(self):
    """Return an iterator of all Windows Registry plugins."""
    ret = []
    _ = map(ret.extend, self._plugins.values())
    for item in ret:
      yield item

  def _GetPluginsByType(self, plugins_dict, registry_file_type):
    """Retrieves the Windows Registry plugins of a specific type.

    Args:
      plugins_dict: Dictionary containing the Windows Registry plugins
                    by plugin type.
      registry_file_type: String containing the Windows Registry file type,
                          e.g. NTUSER, SOFTWARE.

    Returns:
      A list containing the Windows Registry plugins (instances of
      RegistryPlugin) for the specific plugin type.
    """
    return plugins_dict.get(
        registry_file_type, []) + plugins_dict.get(u'any', [])

  def AddPlugin(self, plugin_class):
    """Add a Windows Registry plugin to the plugin list.

    Only plugins with full Windows Registry key paths are registered.

    Args:
      plugin_class: The plugin class that is being registered.
    """
    key_paths = []
    registry_file_types = set()
    for registry_key_filter in plugin_class.FILTERS:
      plugin_key_paths = getattr(registry_key_filter, u'key_paths', [])
      for plugin_key_path in plugin_key_paths:
        if plugin_key_path not in key_paths:
          key_paths.append(plugin_key_path)

          if plugin_key_path.startswith(u'HKEY_CURRENT_USER'):
            registry_file_types.add(u'NTUSER')
          elif plugin_key_path.startswith(u'HKEY_LOCAL_MACHINE\\SAM'):
            registry_file_types.add(u'SAM')
          elif plugin_key_path.startswith(u'HKEY_LOCAL_MACHINE\\Software'):
            registry_file_types.add(u'SOFTWARE')
          elif plugin_key_path.startswith(u'HKEY_LOCAL_MACHINE\\System'):
            registry_file_types.add(u'SYSTEM')

    if len(registry_file_types) == 1:
      plugin_type = registry_file_types.pop()
    else:
      plugin_type = u'any'

    if key_paths:
      self._plugins.setdefault(plugin_type, []).append(plugin_class)

  def GetAllPlugins(self):
    """Return all key plugins as a list."""
    ret = []
    _ = map(ret.extend, self._plugins.values())
    return ret

  def GetKeyPaths(self, plugin_names=None):
    """Retrieves a list of Windows Registry key paths.

    Args:
      plugin_names: Optional list of plugin names, if defined only keys from
                    these plugins will be expanded. The default is None which
                    means all key plugins will get expanded keys.

    Returns:
      A set of Windows Registry key paths.
    """
    key_paths = set()
    for plugin_cls in self.GetAllPlugins():
      plugin_object = plugin_cls()

      if plugin_names and plugin_object.NAME not in plugin_names:
        continue

      for key_path in plugin_object.GetKeyPaths():
        key_paths.add(key_path)

    return key_paths

  def GetPluginObjectByName(self, registry_file_type, plugin_name):
    """Creates a new instance of a specific Windows Registry plugin.

    Args:
      registry_file_type: String containing the Windows Registry file type,
                          e.g. NTUSER, SOFTWARE.
      plugin_name: the name of the plugin.

    Returns:
      The Windows Registry plugin (instance of RegistryPlugin) or None.
    """
    # TODO: make this a dict lookup instead of a list iteration.
    for plugin_cls in self.GetPlugins(registry_file_type):
      if plugin_cls.NAME == plugin_name:
        return plugin_cls()

  def GetPluginObjects(self, registry_file_type):
    """Creates new instances of a specific type of Windows Registry plugins.

    Args:
      registry_file_type: String containing the Windows Registry file type,
                          e.g. NTUSER, SOFTWARE.

    Returns:
      A list of Windows Registry plugins (instances of RegistryPlugin).
    """
    return [plugin_cls() for plugin_cls in self.GetPlugins(registry_file_type)]

  def GetPlugins(self, registry_file_type):
    """Retrieves the Windows Registry key-based plugins of a specific type.

    Args:
      registry_file_type: String containing the Windows Registry file type,
                          e.g. NTUSER, SOFTWARE.

    Returns:
      A list containing the Windows Registry plugins (types of
      RegistryPlugin) for the specific plugin type.
    """
    return self._GetPluginsByType(self._plugins, registry_file_type)

  def GetRegistryPlugins(self, filter_string):
    """Retrieves the Windows Registry plugins based on a filter string.

    Args:
      filter_string: string containing the name of the plugin or an empty
                     string for all the plugins.

    Returns:
      A list of Windows Registry plugins (instance of RegistryPlugin).
    """
    if filter_string:
      filter_string = filter_string.lower()

    plugins_to_run = []
    for plugins_per_type in iter(self._plugins.values()):
      for plugin in plugins_per_type:
        # Note that this method also matches on parts of the plugin name.
        if not filter_string or filter_string in plugin.NAME.lower():
          plugins_to_run.append(plugin)

    return plugins_to_run

  def GetRegistryTypes(self, filter_string):
    """Retrieves the Windows Registry types based on a filter string.

    Args:
      filter_string: string containing the name of the plugin or an empty
                     string for all the plugins.

    Returns:
      A list of Windows Registry types.
    """
    if filter_string:
      filter_string = filter_string.lower()

    registry_file_types = set()
    for plugin_type, plugins_per_type in iter(self._plugins.items()):
      for plugin in plugins_per_type:
        if not filter_string or filter_string == plugin.NAME.lower():
          if plugin_type == u'any':
            registry_file_types.update(REGISTRY_FILE_TYPES)

          else:
            registry_file_types.add(plugin_type)

    return list(registry_file_types)

  def GetRegistryTypesFromPlugins(self, plugin_names):
    """Return a list of Registry types extracted from a list of plugin names.

    Args:
      plugin_names: a list of plugin names.

    Returns:
      A list of Registry types extracted from the supplied plugins.
    """
    if not plugin_names:
      return []

    registry_file_types = set()
    for plugin_type, plugins_per_type in iter(self._plugins.items()):
      for plugin in plugins_per_type:
        if plugin.NAME.lower() in plugin_names:
          # If a plugin is available for every Registry type
          # we need to make sure all Registry files are included.
          if plugin_type == u'any':
            registry_file_types.update(REGISTRY_FILE_TYPES)

          else:
            registry_file_types.add(plugin_type)

    return list(registry_file_types)

  def GetRegistryPluginsFromRegistryType(self, registry_file_type):
    """Retrieves the Windows Registry plugins based on a Registry type.

    Args:
      registry_file_type: the Windows Registry files type string or an empty
                          string for all the plugins.

    Returns:
      A list of Windows Registry plugins (instance of RegistryPlugin).
    """
    if registry_file_type:
      registry_file_type = registry_file_type.upper()

    plugins_to_run = []
    for plugin_type, plugins_per_type in iter(self._plugins.items()):
      if not registry_file_type or plugin_type in [u'any', registry_file_type]:
        plugins_to_run.extend(plugins_per_type)

    return plugins_to_run


class PregFrontend(extraction_frontend.ExtractionFrontend):
  """Class that implements the preg front-end.

  Attributes:
    knowledge_base_object: the knowledge base object (instance
                           of KnowledgeBase).
  """

  def __init__(self):
    """Initializes the front-end object."""
    super(PregFrontend, self).__init__()
    self._mount_path_spec = None
    self._parse_restore_points = False
    self._preprocess_completed = False
    self._registry_files = []
    self._registry_plugin_list = self.GetWindowsRegistryPlugins()
    self._single_file = False
    self._source_path = None
    self._source_path_specs = []

    self.knowledge_base_object = None

  @property
  def registry_plugin_list(self):
    """The Windows Registry plugin list (instance of PluginList)."""
    return self._registry_plugin_list

  def _CreateWindowsPathResolver(
      self, file_system, mount_point, environment_variables):
    """Create a Windows path resolver and sets the evironment variables.

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
      if name != u'systemroot':
        continue

      path_resolver.SetEnvironmentVariable(
          environment_variable.name, environment_variable.value)

    return path_resolver

  def _GetRegistryHelperFromPath(self, path, codepage):
    """Return a Registry helper object from a path.

    Given a path to a Registry file this function goes through
    all the discovered source path specifications (instance of PathSpec)
    and extracts Registry helper objects based on the supplied
    path.

    Args:
      path: the path filter to a Registry file.
      codepage: the codepage used for the Registry file.

    Yields:
      A Registry helper object (instance of PregRegistryHelper).
    """
    environment_variables = self.knowledge_base_object.GetEnvironmentVariables()

    for source_path_spec in self._source_path_specs:
      if source_path_spec.type_indicator == dfvfs_definitions.TYPE_INDICATOR_OS:
        file_entry = path_spec_resolver.Resolver.OpenFileEntry(source_path_spec)
        if file_entry.IsFile():
          yield PregRegistryHelper(
              file_entry, u'OS', self.knowledge_base_object, codepage=codepage)
          continue

        # TODO: Change this into an actual mount point path spec.
        self._mount_path_spec = source_path_spec

      collector_name = source_path_spec.type_indicator
      parent_path_spec = getattr(source_path_spec, u'parent', None)
      if parent_path_spec and parent_path_spec.type_indicator == (
          dfvfs_definitions.TYPE_INDICATOR_VSHADOW):
        vss_store = getattr(parent_path_spec, u'store_index', 0)
        collector_name = u'VSS Store: {0:d}'.format(vss_store)

      file_system, mount_point = self._GetSourceFileSystem(source_path_spec)

      try:
        path_resolver = self._CreateWindowsPathResolver(
            file_system, mount_point, environment_variables)

        if path.startswith(u'%UserProfile%\\'):
          searcher = file_system_searcher.FileSystemSearcher(
              file_system, mount_point)

          user_profiles = []
          # TODO: determine the users path properly instead of relying on
          # common defaults. Note that these paths are language dependent.
          for user_path in (u'/Documents and Settings/.+', u'/Users/.+'):
            find_spec = file_system_searcher.FindSpec(
                location_regex=user_path, case_sensitive=False)
            for path_spec in searcher.Find(find_specs=[find_spec]):
              location = getattr(path_spec, u'location', None)
              if location:
                if location.startswith(u'/'):
                  location = u'\\'.join(location.split(u'/'))
                user_profiles.append(location)

          for user_profile in user_profiles:
            path_resolver.SetEnvironmentVariable(u'UserProfile', user_profile)

            path_spec = path_resolver.ResolvePath(path)
            if not path_spec:
              continue

            file_entry = file_system.GetFileEntryByPathSpec(path_spec)
            if not file_entry:
              continue

            yield PregRegistryHelper(
                file_entry, collector_name, self.knowledge_base_object,
                codepage=codepage)

        else:
          path_spec = path_resolver.ResolvePath(path)
          if not path_spec:
            continue

          file_entry = file_system.GetFileEntryByPathSpec(path_spec)
          if not file_entry:
            continue

          yield PregRegistryHelper(
              file_entry, collector_name, self.knowledge_base_object,
              codepage=codepage)

      finally:
        file_system.Close()

  # TODO: refactor, this is a duplicate of the function in engine.
  def _GetSourceFileSystem(self, source_path_spec, resolver_context=None):
    """Retrieves the file system of the source.

    The mount point path specification refers to either a directory or
    a volume on storage media device or image. It is needed by the dfVFS
    file system searcher (instance of FileSystemSearcher) to indicate
    the base location of the file system.

    Args:
      source_path_spec: The source path specification (instance of
                        dfvfs.PathSpec) of the file system.
      resolver_context: Optional resolver context (instance of dfvfs.Context).
                        The default is None which will use the built in context
                        which is not multi process safe. Note that every thread
                        or process must have its own resolver context.

    Returns:
      A tuple of the file system (instance of dfvfs.FileSystem) and
      the mount point path specification (instance of path.PathSpec).

    Raises:
      RuntimeError: if source path specification is not set.
    """
    if not source_path_spec:
      raise RuntimeError(u'Missing source.')

    file_system = path_spec_resolver.Resolver.OpenFileSystem(
        source_path_spec, resolver_context=resolver_context)

    type_indicator = source_path_spec.type_indicator
    if path_spec_factory.Factory.IsSystemLevelTypeIndicator(type_indicator):
      mount_point = source_path_spec
    else:
      mount_point = source_path_spec.parent

    return file_system, mount_point

  def ExpandKeysRedirect(self, keys):
    """Expands a list of Registry key paths with their redirect equivalents.

    Args:
      keys: a list of Windows Registry key paths.
    """
    for key in keys:
      if key.startswith(u'\\Software') and u'Wow6432Node' not in key:
        _, first, second = key.partition(u'\\Software')
        keys.append(u'{0:s}\\Wow6432Node{1:s}'.format(first, second))

  def GetRegistryFilePaths(self, registry_file_types):
    """Returns a list of Windows Registry file paths.

    If the Windows Registry file type is not set this functions attempts
    to determine it based on the presence of specific Registry keys.

    Args:
      registry_file_types: a set of Windows Registry file type strings.

    Returns:
      A list of path of Windows Registry files.
    """
    if self._parse_restore_points:
      restore_path = (
          u'\\System Volume Information\\_restore.+\\RP[0-9]+\\snapshot\\')
    else:
      restore_path = u''

    paths = []
    for registry_file_type in registry_file_types:
      if registry_file_type == REGISTRY_FILE_TYPE_NTUSER:
        paths.append(u'%UserProfile%\\NTUSER.DAT')
        if restore_path:
          paths.append(u'{0:s}\\_REGISTRY_USER_NTUSER_.+'.format(restore_path))

      elif registry_file_type == REGISTRY_FILE_TYPE_SAM:
        paths.append(u'%SystemRoot%\\System32\\config\\SAM')
        if restore_path:
          paths.append(u'{0:s}\\_REGISTRY_MACHINE_SAM'.format(restore_path))

      elif registry_file_type == REGISTRY_FILE_TYPE_SECURITY:
        paths.append(u'%SystemRoot%\\System32\\config\\SECURITY')
        if restore_path:
          paths.append(
              u'{0:s}\\_REGISTRY_MACHINE_SECURITY'.format(restore_path))

      elif registry_file_type == REGISTRY_FILE_TYPE_SOFTWARE:
        paths.append(u'%SystemRoot%\\System32\\config\\SOFTWARE')
        if restore_path:
          paths.append(
              u'{0:s}\\_REGISTRY_MACHINE_SOFTWARE'.format(restore_path))

      elif registry_file_type == REGISTRY_FILE_TYPE_SYSTEM:
        paths.append(u'%SystemRoot%\\System32\\config\\SYSTEM')
        if restore_path:
          paths.append(u'{0:s}\\_REGISTRY_MACHINE_SYSTEM'.format(restore_path))

      elif registry_file_type == REGISTRY_FILE_TYPE_USRCLASS:
        paths.append(
            u'%UserProfile%\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat')
        if restore_path:
          paths.append(
              u'{0:s}\\_REGISTRY_USER_USRCLASS_.+'.format(restore_path))

    return paths

  # TODO: refactor this function. Current implementation is too complex.
  def GetRegistryHelpers(
      self, registry_file_types=None, plugin_names=None, codepage=u'cp1252'):
    """Returns a list of discovered Registry helpers.

    Args:
      registry_file_types: optional list of Windows Registry file types,
                           e.g.: NTUSER, SAM, etc that should be included.
      plugin_names: optional list of strings containing the name of the
                    plugin(s) or an empty string for all the types. The default
                    is None.
      codepage: the codepage used for the Registry file.

    Returns:
      A list of Registry helper objects (instance of PregRegistryHelper).

    Raises:
      ValueError: If neither registry_file_types nor plugin name is passed
                  as a parameter.
    """
    if registry_file_types is None and plugin_names is None:
      raise ValueError(
          u'Missing registry_file_types or plugin_name value.')

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
            file_system, mount_point, self.knowledge_base_object)
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

      paths = self.GetRegistryFilePaths(types)

    self.knowledge_base_object.SetCodepage(codepage)

    registry_helpers = []
    for path in paths:
      for helper in self._GetRegistryHelperFromPath(path, codepage):
        registry_helpers.append(helper)

    return registry_helpers

  # TODO: remove after refactoring.
  def GetRegistryPlugins(self, filter_string):
    """Retrieves the Windows Registry plugins based on a filter string.

    Args:
      filter_string: string containing the name of the plugin or an empty
                     string for all the plugins.

    Returns:
      A list of Windows Registry plugins (instance of RegistryPlugin).
    """
    return self._registry_plugin_list.GetRegistryPlugins(filter_string)

  # TODO: remove after refactoring.
  def GetRegistryPluginsFromRegistryType(self, registry_file_type):
    """Retrieves the Windows Registry plugins based on a Registry type.

    Args:
      registry_file_type: the Windows Registry files type string.

    Returns:
      A list of Windows Registry plugins (instance of RegistryPlugin).
    """
    return self._registry_plugin_list.GetRegistryPluginsFromRegistryType(
        registry_file_type)

  def GetRegistryTypes(self, filter_string):
    """Retrieves the Windows Registry types based on a filter string.

    Args:
      filter_string: string containing the name of the plugin or an empty
                     string for all the plugins.

    Returns:
      A list of Windows Registry types.
    """
    return self._registry_plugin_list.GetRegistryTypes(filter_string)

  def GetWindowsRegistryPlugins(self):
    """Build a list of all available Windows Registry plugins.

    Returns:
      A plugins list (instance of PluginList).
    """
    winreg_parser = parsers_manager.ParsersManager.GetParserObjectByName(
        u'winreg')
    if not winreg_parser:
      return

    plugins_list = PluginList()
    for _, plugin_class in winreg_parser.GetPlugins():
      plugins_list.AddPlugin(plugin_class)
    return plugins_list

  def ParseRegistryFile(
      self, registry_helper, key_paths=None, use_plugins=None):
    """Extracts events from a Registry file.

    This function takes a Registry helper object (instance of
    PregRegistryHelper) and information about either Registry plugins or keys.
    The function then opens up the Registry file and runs the plugins defined
    (or all if no plugins are defined) against all the keys supplied to it.

    Args:
      registry_helper: Registry helper object (instance of PregRegistryHelper)
      key_paths: optional list of Registry keys paths that are to be parsed.
                 The default is None, which results in no keys parsed.
      use_plugins: optional list of plugins used to parse the key. The
                   default is None, in which case all plugins are used.

    Returns:
      A dict that contains the following structure:
          key_path:
              key: a Registry key (instance of dfwinreg.WinRegistryKey)
              subkeys: a list of Registry keys (instance of
                       dfwinreg.WinRegistryKey).
              data:
                plugin: a plugin object (instance of RegistryPlugin)
                  event_objects: List of event objects extracted.

          key_path 2:
              ...
      Or an empty dict on error.
    """
    if not registry_helper:
      return {}

    try:
      registry_helper.Open()
    except IOError as exception:
      logging.error(u'Unable to parse Registry file, with error: {0:s}'.format(
          exception))
      return {}

    return_dict = {}
    if key_paths is None:
      key_paths = []

    for key_path in key_paths:
      registry_key = registry_helper.GetKeyByPath(key_path)
      return_dict[key_path] = {u'key': registry_key}

      if not registry_key:
        continue

      return_dict[key_path][u'subkeys'] = list(registry_key.GetSubkeys())

      return_dict[key_path][u'data'] = self.ParseRegistryKey(
          registry_key, registry_helper, use_plugins=use_plugins)

    return return_dict

  def ParseRegistryKey(self, registry_key, registry_helper, use_plugins=None):
    """Parse a single Registry key and return parsed information.

    Parses the Registry key either using the supplied plugin or trying against
    all available plugins.

    Args:
      registry_key: the Registry key to parse (instance of
                    dfwinreg.WinRegistryKey or a string containing key path).
      registry_helper: the Registry helper object (instance of
                       PregRegistryHelper).
      use_plugins: optional list of plugin names to use. The default is None
                   which uses all available plugins.

    Returns:
      A dictionary with plugin objects as keys and extracted event objects from
      each plugin as values or an empty dict on error.
    """
    if not registry_helper:
      return {}

    if isinstance(registry_key, py2to3.STRING_TYPES):
      registry_key = registry_helper.GetKeyByPath(registry_key)

    if not registry_key:
      return {}

    # TODO: refactor usage of fake storage.
    session = sessions.Session()
    storage_writer = fake_storage.FakeStorageWriter(session)
    storage_writer.Open()

    parser_mediator = parsers_mediator.ParserMediator(
        storage_writer, self.knowledge_base_object)

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
      if storage_writer.events:
        return_dict[plugin_object] = storage_writer.events

    if not found_matching_plugin:
      winreg_parser = parsers_manager.ParsersManager.GetParserObjectByName(
          u'winreg')
      if not winreg_parser:
        return
      default_plugin_object = winreg_parser.GetPluginObjectByName(
          u'winreg_default')

      default_plugin_object.Process(parser_mediator, registry_key)
      if storage_writer.events:
        return_dict[default_plugin_object] = storage_writer.events

    return return_dict

  def SetSingleFile(self, single_file=False):
    """Sets the single file processing parameter.

    Args:
      single_file: boolean value, if set to True the tool treats the
                   source as a single file input, otherwise as a storage
                   media format.
    """
    self._single_file = single_file

  def SetSourcePath(self, source_path):
    """Sets the source path.

    Args:
      source_path: the filesystem path to the disk image.
    """
    self._source_path = source_path

  def SetSourcePathSpecs(self, source_path_specs):
    """Sets the source path resolver.

    Args:
      source_path_specs: list of source path specifications (instance
                         of PathSpec).
    """
    self._source_path_specs = source_path_specs

  def SetKnowledgeBase(self, knowledge_base_object):
    """Sets the knowledge base object for the front end.

    Args:
      knowledge_base_object: the knowledge base object (instance
                             of KnowledgeBase).
    """
    self.knowledge_base_object = knowledge_base_object


class PregRegistryHelper(object):
  """Class that defines few helper functions for Registry operations.

  Attributes:
    file_entry: file entry object (instance of dfvfs.FileEntry).
  """

  _KEY_PATHS_PER_REGISTRY_TYPE = {
      REGISTRY_FILE_TYPE_NTUSER: frozenset([
          u'\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer']),
      REGISTRY_FILE_TYPE_SAM: frozenset([
          u'\\SAM\\Domains\\Account\\Users']),
      REGISTRY_FILE_TYPE_SECURITY: frozenset([
          u'\\Policy\\PolAdtEv']),
      REGISTRY_FILE_TYPE_SOFTWARE: frozenset([
          u'\\Microsoft\\Windows\\CurrentVersion\\App Paths']),
      REGISTRY_FILE_TYPE_SYSTEM: frozenset([
          u'\\Select']),
      REGISTRY_FILE_TYPE_USRCLASS: frozenset([
          u'\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion']),
  }

  def __init__(
      self, file_entry, collector_name, knowledge_base_object,
      codepage=u'cp1252'):
    """Initialize the Registry helper.

    Args:
      file_entry: file entry object (instance of dfvfs.FileEntry).
      collector_name: the name of the collector, eg. TSK.
      knowledge_base_object: A knowledge base object (instance of
                             KnowledgeBase), which contains information from
                             the source data needed for parsing.
      codepage: optional codepage value used for the Registry file. The default
                is cp1252.
    """
    super(PregRegistryHelper, self).__init__()
    self._codepage = codepage
    self._collector_name = collector_name
    self._currently_registry_key = None
    self._key_path_prefix = None
    self._knowledge_base_object = knowledge_base_object
    self._registry_file = None
    self._registry_file_name = None
    self._registry_file_type = REGISTRY_FILE_TYPE_UNKNOWN
    self._win_registry = None

    self.file_entry = file_entry

  def __enter__(self):
    """Make usable with "with" statement."""
    return self

  def __exit__(self, unused_type, unused_value, unused_traceback):
    """Make usable with "with" statement."""
    self.Close()

  @property
  def collector_name(self):
    """The name of the collector used to discover the Registry file."""
    return self._collector_name

  @property
  def file_type(self):
    """The Registry file type."""
    return self._registry_file_type

  @property
  def name(self):
    """The name of the Registry file."""
    return self._registry_file_name

  @property
  def path(self):
    """The file path of the Registry file."""
    path_spec = getattr(self.file_entry, u'path_spec', None)
    if not path_spec:
      return u'N/A'

    return getattr(path_spec, u'location', u'N/A')

  @property
  def root_key(self):
    """The root key of the Registry file or None."""
    if self._registry_file:
      return self._registry_file.GetRootKey()

  def _Reset(self):
    """Reset all attributes of the Registry helper."""
    self._currently_registry_key = None
    self._key_path_prefix = None
    self._registry_file = None
    self._registry_file_name = None
    self._registry_file_type = REGISTRY_FILE_TYPE_UNKNOWN

  def ChangeKeyByPath(self, key_path):
    """Changes the current key defined by the Registry key path.

    Args:
      key_path: string containing an absolute or relative Registry key path.

    Returns:
      The key (instance of dfwinreg.WinRegistryKey) if available or
      None otherwise.
    """
    if key_path == u'.':
      return self._currently_registry_key

    path_segments = []

    # If the key path is relative to the root key add the key path prefix.
    if not key_path or key_path.startswith(u'\\'):
      path_segments.append(self._key_path_prefix)

      # If no key path was provided then change to the root key.
      if not key_path:
        path_segments.append(u'\\')

    else:
      key_path_upper = key_path.upper()
      if not key_path_upper.startswith(u'HKEY_'):
        current_path = getattr(self._currently_registry_key, u'path', None)
        if current_path:
          path_segments.append(current_path)

    path_segments.append(key_path)

    # Split all the path segments based on the path (segment) separator.
    path_segments = [
        segment.split(u'\\') for segment in path_segments]

    # Flatten the sublists into one list.
    path_segments = [
        element for sublist in path_segments for element in sublist]

    # Remove empty and current ('.') path segments.
    path_segments = [
        segment for segment in path_segments
        if segment not in [None, u'', u'.']]

    # Remove parent ('..') path segments.
    index = 0
    while index < len(path_segments):
      if path_segments[index] == u'..':
        path_segments.pop(index)
        index -= 1

        if index > 0:
          path_segments.pop(index)
          index -= 1

      index += 1

    key_path = u'\\'.join(path_segments)
    return self.GetKeyByPath(key_path)

  def Close(self):
    """Closes the helper."""
    self._Reset()

  def GetCurrentRegistryKey(self):
    """Return the currently Registry key."""
    return self._currently_registry_key

  def GetCurrentRegistryPath(self):
    """Return the Registry key path or None."""
    return getattr(self._currently_registry_key, u'path', None)

  def GetKeyByPath(self, key_path):
    """Retrieves a specific key defined by the Registry key path.

    Args:
      key_path: a Windows Registry key path relative to the root key of
                the file or relative to the root of the Windows Registry.

    Returns:
      The key (instance of dfwinreg.WinRegistryKey) if available or
      None otherwise.
    """
    registry_key = self._win_registry.GetKeyByPath(key_path)
    if not registry_key:
      return

    self._currently_registry_key = registry_key
    return registry_key

  def GetRegistryFileType(self, registry_file):
    """Determines the Windows Registry type based on keys present in the file.

    Args:
      registry_file: the Windows Registry file object (instance of
                     WinRegistryFile).

    Returns:
      The Windows Registry file type, e.g. NTUSER, SOFTWARE.
    """
    registry_file_type = REGISTRY_FILE_TYPE_UNKNOWN
    for registry_file_type, key_paths in iter(
        self._KEY_PATHS_PER_REGISTRY_TYPE.items()):

      # If all key paths are found we consider the file to match a certain
      # Registry type.
      match = True
      for key_path in key_paths:
        registry_key = registry_file.GetKeyByPath(key_path)
        if not registry_key:
          match = False

      if match:
        break

    return registry_file_type

  def Open(self):
    """Opens a Windows Registry file.

    Raises:
      IOError: if the Windows Registry file cannot be opened.
    """
    if self._registry_file:
      raise IOError(u'Registry file already open.')

    file_object = self.file_entry.GetFileObject()
    if not file_object:
      logging.error(
          u'Unable to open Registry file: {0:s} [{1:s}]'.format(
              self.path, self._collector_name))
      raise IOError(u'Unable to open Registry file.')

    win_registry_reader = winreg.FileObjectWinRegistryFileReader()
    self._registry_file = win_registry_reader.Open(file_object)
    if not self._registry_file:
      file_object.close()

      logging.error(
          u'Unable to open Registry file: {0:s} [{1:s}]'.format(
              self.path, self._collector_name))
      raise IOError(u'Unable to open Registry file.')

    self._win_registry = dfwinreg_registry.WinRegistry()
    self._key_path_prefix = self._win_registry.GetRegistryFileMapping(
        self._registry_file)
    self._win_registry.MapFile(self._key_path_prefix, self._registry_file)

    self._registry_file_name = self.file_entry.name
    self._registry_file_type = self.GetRegistryFileType(self._registry_file)

    # Retrieve the Registry file root key because the Registry helper
    # expects self._currently_registry_key to be set after
    # the Registry file is opened.
    self._currently_registry_key = self._registry_file.GetRootKey()


class PregTool(storage_media_tool.StorageMediaTool):
  """Class that implements the preg CLI tool.

  Attributes:
    plugin_names: a list containing names of selected Windows Registry plugins
                  to be used, defaults to an empty list.
    registry_file: a string containing the path to a Windows Registry file or
                   a Registry file type, e.g. NTUSER, SOFTWARE, etc.
    run_mode: the run mode of the tool, determines if the tool should
              be running in a plugin mode, parsing an entire Registry file,
              being run in a console, etc.
    source_type: dfVFS source type indicator for the source file.
  """

  # Assign a default value to font align length.
  _DEFAULT_FORMAT_ALIGN_LENGTH = 15

  _SOURCE_OPTION = u'image'

  _WINDOWS_DIRECTORIES = frozenset([
      u'C:\\Windows',
      u'C:\\WINNT',
      u'C:\\WTSRV',
      u'C:\\WINNT35',
  ])

  NAME = u'preg'

  DESCRIPTION = textwrap.dedent(u'\n'.join([
      u'preg is a Windows Registry parser using the plaso Registry plugins ',
      u'and storage media image parsing capabilities.',
      u'',
      u'It uses the back-end libraries of plaso to read raw image files and',
      u'extract Registry files from VSS and restore points and then runs the',
      u'Registry plugins of plaso against the Registry hive and presents it',
      u'in a textual format.']))

  EPILOG = textwrap.dedent(u'\n'.join([
      u'',
      u'Example usage:',
      u'',
      u'Parse the SOFTWARE hive from an image:',
      (u'  preg.py [--vss] [--vss-stores VSS_STORES] -i IMAGE_PATH '
       u'[-o OFFSET] -c SOFTWARE'),
      u'',
      u'Parse an userassist key within an extracted hive:',
      u'  preg.py -p userassist MYNTUSER.DAT',
      u'',
      u'Parse the run key from all Registry keys (in vss too):',
      u'  preg.py --vss -i IMAGE_PATH [-o OFFSET] -p run',
      u'',
      u'Open up a console session for the SYSTEM hive inside an image:',
      u'  preg.py -i IMAGE_PATH [-o OFFSET] -c SYSTEM',
      u'']))

  # Define the different run modes.
  RUN_MODE_CONSOLE = 1
  RUN_MODE_LIST_PLUGINS = 2
  RUN_MODE_REG_FILE = 3
  RUN_MODE_REG_PLUGIN = 4
  RUN_MODE_REG_KEY = 5

  _EXCLUDED_ATTRIBUTE_NAMES = frozenset([
      u'data_type',
      u'display_name',
      u'filename',
      u'inode',
      u'parser',
      u'pathspec',
      u'tag',
      u'timestamp'])

  def __init__(self, input_reader=None, output_writer=None):
    """Initializes the CLI tool object.

    Args:
      input_reader: optional input reader (instance of InputReader).
                    The default is None which indicates the use of the stdin
                    input reader.
      output_writer: optional output writer (instance of OutputWriter).
                     The default is None which indicates the use of the stdout
                     output writer.
    """
    super(PregTool, self).__init__(
        input_reader=input_reader, output_writer=output_writer)
    self._front_end = PregFrontend()
    self._key_path = None
    self._knowledge_base_object = knowledge_base.KnowledgeBase()
    self._quiet = False
    self._parse_restore_points = False
    self._path_resolvers = []
    self._verbose_output = False
    self._windows_directory = u''

    self.plugin_names = []
    self.registry_file = u''
    self.run_mode = None
    self.source_type = None

  def _GetEventDataHexDump(
      self, event_object, before=0, maximum_number_of_lines=20):
    """Returns a hexadecimal representation of the event data.

     This function creates a hexadecimal string representation based on
     the event data described by the event object.

    Args:
      event_object: The event object (instance of EventObject).
      before: Optional number of bytes to include in the output before
              the event.
      maximum_number_of_lines: Optional maximum number of lines to include
                               in the output.

    Returns:
      A string that contains the hexadecimal representation of the event data.
    """
    if not event_object:
      return u'Missing event object.'

    if not hasattr(event_object, u'pathspec'):
      return u'Event object has no path specification.'

    try:
      file_entry = path_spec_resolver.Resolver.OpenFileEntry(
          event_object.pathspec)
    except IOError as exception:
      return u'Unable to open file with error: {0:s}'.format(exception)

    offset = getattr(event_object, u'offset', 0)
    if offset - before > 0:
      offset -= before

    file_object = file_entry.GetFileObject()
    file_object.seek(offset, os.SEEK_SET)
    data_size = maximum_number_of_lines * 16
    data = file_object.read(data_size)
    file_object.close()

    return hexdump.Hexdump.FormatData(data)

  def _GetFormatString(self, event_object):
    """Retrieves the format string for a given event object.

    Args:
      event_object: an event object (instance of EventObject).

    Returns:
      A string containing the format string.
    """
    # Go through the attributes and see if there is an attribute
    # value that is longer than the default font align length, and adjust
    # it accordingly if found.
    if hasattr(event_object, u'regvalue'):
      attributes = event_object.regvalue.keys()
    else:
      attribute_names = set(event_object.GetAttributeNames())
      attributes = attribute_names.difference(
          self._EXCLUDED_ATTRIBUTE_NAMES)

    align_length = self._DEFAULT_FORMAT_ALIGN_LENGTH
    for attribute in attributes:
      if attribute is None:
        attribute = u''

      attribute_len = len(attribute)
      if attribute_len > align_length and attribute_len < 30:
        align_length = len(attribute)

    # Create the format string that will be used, using variable length
    # font align length (calculated in the prior step).
    return u'{{0:>{0:d}s}} : {{1!s}}'.format(align_length)

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
      raise errors.SourceScannerError(u'Invalid scan node.')

    volume_system = tsk_volume_system.TSKVolumeSystem()
    volume_system.Open(scan_node.path_spec)

    # TODO: refactor to front-end.
    volume_identifiers = self._source_scanner.GetVolumeIdentifiers(
        volume_system)
    if not volume_identifiers:
      logging.info(u'No partitions found.')
      return

    # Go over all the detected volume identifiers and only include
    # detected Windows partitions.
    windows_volume_identifiers = self.GetWindowsVolumeIdentifiers(
        scan_node, volume_identifiers)

    if not windows_volume_identifiers:
      logging.error(u'No Windows partitions discovered.')
      return windows_volume_identifiers

    if partitions == [u'all']:
      return windows_volume_identifiers

    partition_string = None
    if partitions:
      partition_string = partitions[0]

    if partition_string is not None and not partition_string.startswith(u'p'):
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
      partition_string = u'p{0:d}'.format(partition_number)
      if volume and partition_string in windows_volume_identifiers:
        return [partition_string]

      logging.warning(u'No such partition: {0:d}.'.format(partition_number))

    if partition_offset is not None:
      for volume in volume_system.volumes:
        volume_extent = volume.extents[0]
        if volume_extent.offset == partition_offset:
          return [volume.identifier]

      logging.warning(
          u'No such partition with offset: {0:d} (0x{0:08x}).'.format(
              partition_offset))

    if len(windows_volume_identifiers) == 1:
      return windows_volume_identifiers

    try:
      selected_volume_identifier = self._PromptUserForPartitionIdentifier(
          volume_system, windows_volume_identifiers)
    except KeyboardInterrupt:
      raise errors.UserAbort(u'File system scan aborted.')

    if selected_volume_identifier == u'all':
      return windows_volume_identifiers

    return [selected_volume_identifier]

  # TODO: Improve check and use dfVFS.
  def _PathExists(self, file_path):
    """Determine if a given file path exists as a file, directory or a device.

    Args:
      file_path: string denoting the file path that needs checking.

    Returns:
      A tuple, a boolean indicating whether or not the path exists and
      a string that contains the reason, if any, why this was not
      determined to be a file.
    """
    if os.path.exists(file_path):
      return True, u''

    try:
      if pysmdev.check_device(file_path):
        return True, u''
    except IOError as exception:
      return False, u'Unable to determine, with error: {0:s}'.format(exception)

    return False, u'Not an existing file.'

  def _PrintEventBody(self, event_object, file_entry=None, show_hex=False):
    """Writes a list of strings extracted from an event to an output writer.

    Args:
      event_object: event object (instance of EventObject).
      file_entry: optional file entry object (instance of dfvfs.FileEntry)
                  that the event originated from. Default is None.
      show_hex: optional boolean to indicate that the hexadecimal representation
                of the event should be included in the output.
    """
    format_string = self._GetFormatString(event_object)

    timestamp_description = getattr(
        event_object, u'timestamp_desc', eventdata.EventTimestamp.WRITTEN_TIME)

    if timestamp_description != eventdata.EventTimestamp.WRITTEN_TIME:
      self._output_writer.Write(u'<{0:s}>\n'.format(timestamp_description))

    if hasattr(event_object, u'regvalue'):
      attributes = event_object.regvalue
    else:
      # TODO: Add a function for this to avoid repeating code.
      attribute_names = set(event_object.GetAttributeNames())
      keys = attribute_names.difference(self._EXCLUDED_ATTRIBUTE_NAMES)
      keys.discard(u'offset')
      keys.discard(u'timestamp_desc')
      attributes = {}
      for key in keys:
        attributes[key] = getattr(event_object, key)

    for attribute, value in attributes.items():
      self._output_writer.Write(u'\t')
      self._output_writer.Write(format_string.format(attribute, value))
      self._output_writer.Write(u'\n')

    if show_hex and file_entry:
      event_object.pathspec = file_entry.path_spec
      hexadecimal_output = self._GetEventDataHexDump(event_object)

      self.PrintHeader(u'Hexadecimal output from event.', character=u'-')
      self._output_writer.Write(hexadecimal_output)
      self._output_writer.Write(u'\n')

  def _PrintEventHeader(self, event_object, descriptions, exclude_timestamp):
    """Writes a list of strings that contains a header for the event.

    Args:
      event_object: event object (instance of EventObject).
      descriptions: list of strings describing the value of the header
                    timestamp.
      exclude_timestamp: boolean. If it is set to True the method
                         will not include the timestamp in the header.
    """
    format_string = self._GetFormatString(event_object)

    self._output_writer.Write(u'Key information.\n')
    if not exclude_timestamp:
      for description in descriptions:
        self._output_writer.Write(format_string.format(
            description, timelib.Timestamp.CopyToIsoFormat(
                event_object.timestamp)))
        self._output_writer.Write(u'\n')

    key_path = getattr(event_object, u'key_path', None)
    if key_path:
      output_string = format_string.format(u'Key Path', key_path)
      self._output_writer.Write(output_string)
      self._output_writer.Write(u'\n')

    if event_object.timestamp_desc != eventdata.EventTimestamp.WRITTEN_TIME:
      self._output_writer.Write(format_string.format(
          u'Description', event_object.timestamp_desc))
      self._output_writer.Write(u'\n')

    self.PrintHeader(u'Data', character=u'+')

  def _PrintEventObjectsBasedOnTime(
      self, event_objects, file_entry, show_hex=False):
    """Write extracted data from a list of event objects to an output writer.

    This function groups together a list of event objects based on timestamps.
    If more than one event are extracted with the same timestamp the timestamp
    itself is not repeated.

    Args:
      event_objects: list of event objects (instance of EventObject).
      file_entry: optional file entry object (instance of dfvfs.FileEntry).
                  Defaults to None.
      show_hex: optional boolean to indicate that the hexadecimal representation
                of the event should be included in the output.
    """
    event_objects_and_timestamps = {}
    for event_object in event_objects:
      timestamp = event_object.timestamp
      _ = event_objects_and_timestamps.setdefault(timestamp, [])
      event_objects_and_timestamps[timestamp].append(event_object)

    list_of_timestamps = sorted(event_objects_and_timestamps.keys())

    if len(list_of_timestamps) > 1:
      exclude_timestamp_in_header = True
    else:
      exclude_timestamp_in_header = False

    first_timestamp = list_of_timestamps[0]
    first_event = event_objects_and_timestamps[first_timestamp][0]
    descriptions = set()
    for event_object in event_objects_and_timestamps[first_timestamp]:
      descriptions.add(getattr(event_object, u'timestamp_desc', u''))
    self._PrintEventHeader(
        first_event, list(descriptions), exclude_timestamp_in_header)

    for event_timestamp in list_of_timestamps:
      if exclude_timestamp_in_header:
        date_time_string = timelib.Timestamp.CopyToIsoFormat(event_timestamp)
        output_text = u'\n[{0:s}]\n'.format(date_time_string)
        self._output_writer.Write(output_text)

      for event_object in event_objects_and_timestamps[event_timestamp]:
        self._PrintEventBody(
            event_object, file_entry=file_entry, show_hex=show_hex)

  def _PrintParsedRegistryFile(self, parsed_data, registry_helper):
    """Write extracted data from a Registry file to an output writer.

    Args:
      parsed_data: dict object returned from ParseRegisterFile.
      registry_helper: Registry file object (instance of PregRegistryHelper).
    """
    self.PrintHeader(u'Registry File', character=u'x')
    self._output_writer.Write(u'\n')
    self._output_writer.Write(
        u'{0:>15} : {1:s}\n'.format(u'Registry file', registry_helper.path))
    self._output_writer.Write(
        u'{0:>15} : {1:s}\n'.format(
            u'Registry file type', registry_helper.file_type))
    if registry_helper.collector_name:
      self._output_writer.Write(
          u'{0:>15} : {1:s}\n'.format(
              u'Registry Origin', registry_helper.collector_name))

    self._output_writer.Write(u'\n\n')

    for key_path, data in iter(parsed_data.items()):
      self._PrintParsedRegistryInformation(
          key_path, data, registry_helper.file_entry)

    self.PrintSeparatorLine()

  def _PrintParsedRegistryInformation(
      self, key_path, parsed_data, file_entry=None):
    """Write extracted data from a Registry key to an output writer.

    Args:
      key_path: path of the parsed Registry key.
      parsed_data: dict object returned from ParseRegisterFile.
      file_entry: optional file entry object (instance of dfvfs.FileEntry).
    """
    registry_key = parsed_data.get(u'key', None)
    if registry_key:
      self._output_writer.Write(u'{0:>15} : {1:s}\n'.format(
          u'Key Name', key_path))
    elif not self._quiet:
      self._output_writer.Write(u'Unable to open key: {0:s}\n'.format(
          key_path))
      return
    else:
      return

    self._output_writer.Write(
        u'{0:>15} : {1:d}\n'.format(
            u'Subkeys', registry_key.number_of_subkeys))
    self._output_writer.Write(u'{0:>15} : {1:d}\n'.format(
        u'Values', registry_key.number_of_values))
    self._output_writer.Write(u'\n')

    if self._verbose_output:
      subkeys = parsed_data.get(u'subkeys', [])
      for subkey in subkeys:
        self._output_writer.Write(
            u'{0:>15} : {1:s}\n'.format(u'Key Name', subkey.path))

    key_data = parsed_data.get(u'data', None)
    if not key_data:
      return

    self.PrintParsedRegistryKey(
        key_data, file_entry=file_entry, show_hex=self._verbose_output)

  def _ScanFileSystem(self, path_resolver):
    """Scans a file system for the Windows volume.

    Args:
      path_resolver: the path resolver (instance of dfvfs.WindowsPathResolver).

    Returns:
      True if the Windows directory was found, False otherwise.
    """
    result = False

    for windows_path in self._WINDOWS_DIRECTORIES:
      windows_path_spec = path_resolver.ResolvePath(windows_path)

      result = windows_path_spec is not None
      if result:
        self._windows_directory = windows_path
        break

    return result

  def PrintHeader(self, text, character=u'*'):
    """Prints the header as a line with centered text.

    Args:
      text: The header text.
      character: Optional header line character.
    """
    self._output_writer.Write(u'\n')

    format_string = u'{{0:{0:s}^{1:d}}}\n'.format(character, self._LINE_LENGTH)
    header_string = format_string.format(u' {0:s} '.format(text))
    self._output_writer.Write(header_string)

  def PrintParsedRegistryKey(self, key_data, file_entry=None, show_hex=False):
    """Write extracted data returned from ParseRegistryKey to an output writer.

    Args:
      key_data: dict object returned from ParseRegisterKey.
      file_entry: optional file entry object (instance of dfvfs.FileEntry).
      show_hex: optional boolean to indicate that the hexadecimal representation
                of the event should be included in the output.
    """
    self.PrintHeader(u'Plugins', character=u'-')
    for plugin, event_objects in iter(key_data.items()):
      # TODO: make this a table view.
      self.PrintHeader(u'Plugin: {0:s}'.format(plugin.plugin_name))
      self._output_writer.Write(u'{0:s}\n'.format(plugin.DESCRIPTION))
      if plugin.URLS:
        self._output_writer.Write(
            u'Additional information can be found here:\n')

        for url in plugin.URLS:
          self._output_writer.Write(u'{0:>17s} {1:s}\n'.format(u'URL :', url))

      if not event_objects:
        continue

      self._PrintEventObjectsBasedOnTime(
          event_objects, file_entry, show_hex=show_hex)

    self.PrintSeparatorLine()
    self._output_writer.Write(u'\n\n')

  def GetWindowsRegistryPlugins(self):
    """Build a list of all available Windows Registry plugins.

    Returns:
      A plugins list (instance of PluginList).
    """
    return self._front_end.GetWindowsRegistryPlugins()

  def GetWindowsVolumeIdentifiers(self, scan_node, volume_identifiers):
    """Determines and returns back a list of Windows volume identifiers.

    Args:
      scan_node: the scan node (instance of dfvfs.ScanNode).
      volume_identifiers: list of allowed volume identifiers.

    Returns:
      A list of volume identifiers that have Windows partitions.
    """
    windows_volume_identifiers = []
    for sub_node in scan_node.sub_nodes:
      path_spec = getattr(sub_node, u'path_spec', None)
      if not path_spec:
        continue

      type_indicator = path_spec.TYPE_INDICATOR
      if type_indicator != dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION:
        continue

      location = getattr(path_spec, u'location', u'')
      if not location:
        continue

      if location.startswith(u'/'):
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
    table_view = cli_views.CLITableView(title=u'Supported Plugins')
    plugin_list = self._front_end.registry_plugin_list
    for plugin_class in plugin_list.GetAllPlugins():
      table_view.AddRow([plugin_class.NAME, plugin_class.DESCRIPTION])
    table_view.Write(self._output_writer)

  def ParseArguments(self):
    """Parses the command line arguments.

    Returns:
      A boolean value indicating the arguments were successfully parsed.
    """
    self._ConfigureLogging()

    argument_parser = argparse.ArgumentParser(
        description=self.DESCRIPTION, epilog=self.EPILOG, add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    self.AddBasicOptions(argument_parser)

    additional_options = argument_parser.add_argument_group(
        u'Additional Options')

    additional_options.add_argument(
        u'-r', u'--restore-points', u'--restore_points',
        dest=u'restore_points', action=u'store_true', default=False,
        help=u'Include restore points in the Registry file locations.')

    self.AddVSSProcessingOptions(additional_options)

    image_options = argument_parser.add_argument_group(u'Image Options')

    image_options.add_argument(
        u'-i', u'--image', dest=self._SOURCE_OPTION, action=u'store',
        type=str, default=u'', metavar=u'IMAGE_PATH', help=(
            u'If the Registry file is contained within a storage media image, '
            u'set this option to specify the path of image file.'))

    self.AddStorageMediaImageOptions(image_options)

    info_options = argument_parser.add_argument_group(u'Informational Options')

    info_options.add_argument(
        u'--info', dest=u'show_info', action=u'store_true', default=False,
        help=u'Print out information about supported plugins.')

    info_options.add_argument(
        u'-v', u'--verbose', dest=u'verbose', action=u'store_true',
        default=False, help=u'Print sub key information.')

    info_options.add_argument(
        u'-q', u'--quiet', dest=u'quiet', action=u'store_true', default=False,
        help=u'Do not print out key names that the tool was unable to open.')

    mode_options = argument_parser.add_argument_group(u'Run Mode Options')

    mode_options.add_argument(
        u'-c', u'--console', dest=u'console', action=u'store_true',
        default=False, help=(
            u'Drop into a console session Instead of printing output '
            u'to STDOUT.'))

    mode_options.add_argument(
        u'-k', u'--key', dest=u'key', action=u'store', default=u'',
        type=str, metavar=u'REGISTRY_KEYPATH', help=(
            u'A Registry key path that the tool should parse using all '
            u'available plugins.'))

    mode_options.add_argument(
        u'-p', u'--plugins', dest=u'plugin_names', action=u'append', default=[],
        type=str, metavar=u'PLUGIN_NAME', help=(
            u'Substring match of the Registry plugin to be used, this '
            u'parameter can be repeated to create a list of plugins to be '
            u'run against, e.g. "-p userassist -p rdp" or "-p userassist".'))

    argument_parser.add_argument(
        u'registry_file', action=u'store', metavar=u'REGHIVE', nargs=u'?',
        help=(
            u'The Registry hive to read key from (not needed if running '
            u'using a plugin)'))

    try:
      options = argument_parser.parse_args()
    except UnicodeEncodeError:
      # If we get here we are attempting to print help in a non-Unicode
      # terminal.
      self._output_writer.Write(u'\n')
      self._output_writer.Write(argument_parser.format_help())
      self._output_writer.Write(u'\n')
      return False

    try:
      self.ParseOptions(options)
    except errors.BadConfigOption as exception:
      logging.error(u'{0:s}'.format(exception))

      self._output_writer.Write(u'\n')
      self._output_writer.Write(argument_parser.format_help())
      self._output_writer.Write(u'\n')

      return False

    return True

  def ParseOptions(self, options):
    """Parses the options.

    Args:
      options: the command line arguments (instance of argparse.Namespace).

    Raises:
      BadConfigOption: if the options are invalid.
    """
    if getattr(options, u'show_info', False):
      self.run_mode = self.RUN_MODE_LIST_PLUGINS
      return

    registry_file = getattr(options, u'registry_file', None)
    image = self.ParseStringOption(options, self._SOURCE_OPTION)
    source_path = None
    if image:
      # TODO: refactor, there should be no need for separate code paths.
      super(PregTool, self).ParseOptions(options)
      source_path = image
      self._front_end.SetSingleFile(False)
    else:
      self._ParseInformationalOptions(options)
      source_path = registry_file
      self._front_end.SetSingleFile(True)

    if source_path is None:
      raise errors.BadConfigOption(u'No source path set.')

    self._front_end.SetSourcePath(source_path)
    self._source_path = os.path.abspath(source_path)

    if not image and not registry_file:
      raise errors.BadConfigOption(u'Not enough parameters to proceed.')

    if registry_file:
      if not image and not os.path.isfile(registry_file):
        raise errors.BadConfigOption(
            u'Registry file: {0:s} does not exist.'.format(registry_file))

    self._key_path = self.ParseStringOption(options, u'key')
    self._parse_restore_points = getattr(options, u'restore_points', False)

    self._quiet = getattr(options, u'quiet', False)

    self._verbose_output = getattr(options, u'verbose', False)

    if image:
      file_to_check = image
    else:
      file_to_check = registry_file

    is_file, reason = self._PathExists(file_to_check)
    if not is_file:
      raise errors.BadConfigOption(
          u'Unable to read the input file with error: {0:s}'.format(reason))

    # TODO: make sure encoded plugin names are handled correctly.
    self.plugin_names = getattr(options, u'plugin_names', [])

    self._front_end.SetKnowledgeBase(self._knowledge_base_object)

    if getattr(options, u'console', False):
      self.run_mode = self.RUN_MODE_CONSOLE
    elif self._key_path and registry_file:
      self.run_mode = self.RUN_MODE_REG_KEY
    elif self.plugin_names:
      self.run_mode = self.RUN_MODE_REG_PLUGIN
    elif registry_file:
      self.run_mode = self.RUN_MODE_REG_FILE
    else:
      raise errors.BadConfigOption(
          u'Incorrect usage. You\'ll need to define the path of either '
          u'a storage media image or a Windows Registry file.')

    self.registry_file = registry_file

    scan_context = self.ScanSource()
    self.source_type = scan_context.source_type
    self._front_end.SetSourcePathSpecs(self._source_path_specs)

  def RunModeRegistryFile(self):
    """Run against a Registry file.

    Finds and opens all Registry hives as configured in the configuration
    object and determines the type of Registry file opened. Then it will
    load up all the Registry plugins suitable for that particular Registry
    file, find all Registry keys they are able to parse and run through
    them, one by one.
    """
    registry_helpers = self._front_end.GetRegistryHelpers(
        registry_file_types=[self.registry_file])

    for registry_helper in registry_helpers:
      try:
        registry_helper.Open()

        self._PrintParsedRegistryFile({}, registry_helper)
        plugins_to_run = self._front_end.GetRegistryPluginsFromRegistryType(
            registry_helper.file_type)

        for plugin in plugins_to_run:
          key_paths = plugin.GetKeyPaths()
          self._front_end.ExpandKeysRedirect(key_paths)
          for key_path in key_paths:
            key = registry_helper.GetKeyByPath(key_path)
            if not key:
              continue
            parsed_data = self._front_end.ParseRegistryKey(
                key, registry_helper, use_plugins=[plugin.NAME])
            self.PrintParsedRegistryKey(
                parsed_data, file_entry=registry_helper.file_entry,
                show_hex=self._verbose_output)
      finally:
        registry_helper.Close()
        self.PrintSeparatorLine()

  def RunModeRegistryKey(self):
    """Run against a specific Registry key.

    Finds and opens all Registry hives as configured in the configuration
    object and tries to open the Registry key that is stored in the
    configuration object for every detected hive file and parses it using
    all available plugins.
    """
    registry_helpers = self._front_end.GetRegistryHelpers(
        registry_file_types=[self.registry_file],
        plugin_names=self.plugin_names)

    key_paths = [self._key_path]

    # Expand the keys paths if there is a need (due to Windows redirect).
    self._front_end.ExpandKeysRedirect(key_paths)

    for registry_helper in registry_helpers:
      parsed_data = self._front_end.ParseRegistryFile(
          registry_helper, key_paths=key_paths)
      self._PrintParsedRegistryFile(parsed_data, registry_helper)

  def RunModeRegistryPlugin(self):
    """Run against a set of Registry plugins."""
    # TODO: Add support for splitting the output to separate files based on
    # each plugin name.
    registry_helpers = self._front_end.GetRegistryHelpers(
        plugin_names=self.plugin_names)

    plugins = []
    for plugin_name in self.plugin_names:
      plugins.extend(self._front_end.GetRegistryPlugins(plugin_name))
    plugin_list = [plugin.NAME for plugin in plugins]

    # In order to get all the Registry keys we need to expand them.
    if not registry_helpers:
      return

    registry_helper = registry_helpers[0]
    key_paths = []
    plugins_list = self._front_end.registry_plugin_list
    try:
      registry_helper.Open()

      # Get all the appropriate keys from these plugins.
      key_paths = plugins_list.GetKeyPaths(plugin_names=plugin_list)

    finally:
      registry_helper.Close()

    for registry_helper in registry_helpers:
      parsed_data = self._front_end.ParseRegistryFile(
          registry_helper, key_paths=key_paths, use_plugins=plugin_list)
      self._PrintParsedRegistryFile(parsed_data, registry_helper)


@magic.magics_class
class PregMagics(magic.Magics):
  """Class that implements the iPython console magic functions."""

  # Needed to give the magic class access to the front end tool
  # for processing and formatting.
  console = None

  REGISTRY_KEY_PATH_SEPARATOR = u'\\'

  # TODO: move into helper.
  REGISTRY_FILE_BASE_PATH = u'\\'

  # TODO: Use the output writer from the tool.
  output_writer = cli_tools.StdoutOutputWriter()

  def _HiveActionList(self, unused_line):
    """Handles the hive list action.

    Args:
      line: the command line provide via the console.
    """
    self.console.PrintRegistryFileList()
    self.output_writer.Write(u'\n')
    self.output_writer.Write(
        u'To open a Registry file, use: hive open INDEX\n')

  def _HiveActionOpen(self, line):
    """Handles the hive open action.

    Args:
      line: the command line provide via the console.
    """
    try:
      registry_file_index = int(line[5:], 10)
    except ValueError:
      self.output_writer.Write(
          u'Unable to open Registry file, invalid index number.\n')
      return

    try:
      self.console.LoadRegistryFile(registry_file_index)
    except errors.UnableToLoadRegistryHelper as exception:
      self.output_writer.Write(
          u'Unable to load hive, with error: {0:s}.\n'.format(exception))
      return

    registry_helper = self.console.current_helper
    self.output_writer.Write(u'Opening hive: {0:s} [{1:s}]\n'.format(
        registry_helper.path, registry_helper.collector_name))
    self.console.SetPrompt(registry_file_path=registry_helper.path)

  def _HiveActionScan(self, line):
    """Handles the hive scan action.

    Args:
      line: the command line provide via the console.
    """
    # Line contains: "scan REGISTRY_TYPES" where REGISTRY_TYPES is a comma
    # separated list.
    registry_file_type_string = line[5:]
    if not registry_file_type_string:
      registry_file_types = self.console.preg_front_end.GetRegistryTypes()
    else:
      registry_file_types = [
          string.strip() for string in registry_file_type_string.split(u',')]

    registry_helpers = self.console.preg_front_end.GetRegistryHelpers(
        registry_file_types=registry_file_types)

    for registry_helper in registry_helpers:
      self.console.AddRegistryHelper(registry_helper)

    self.console.PrintRegistryFileList()

  def _PrintPluginHelp(self, plugin_object):
    """Prints the help information of a plugin.

    Args:
      plugin_object: a Windows Registry plugin object (instance of
                     WindowsRegistryPlugin).
    """
    table_view = cli_views.CLITableView(title=plugin_object.NAME)

    # TODO: replace __doc__ by DESCRIPTION.
    description = plugin_object.__doc__
    table_view.AddRow([u'Description', description])
    self.output_writer.Write(u'\n')

    for registry_key in plugin_object.expanded_keys:
      table_view.AddRow([u'Registry Key', registry_key])
    table_view.Write(self._output_writer)

  def _SanitizeKeyPath(self, key_path):
    """Sanitizes a Windows Registry key path.

    Args:
      key_path: a string containing a Registry key path.

    Returns:
      A string containing the sanitized Registry key path.
    """
    key_path = key_path.replace(u'}', u'}}')
    key_path = key_path.replace(u'{', u'{{')
    return key_path.replace(u'\\', u'\\\\')

  @magic.line_magic(u'cd')
  def ChangeDirectory(self, key_path):
    """Change between Registry keys, like a directory tree.

    The key path can either be an absolute path or a relative one.
    Absolute paths can use '.' and '..' to denote current and parent
    directory/key path. If no key path is set the current key is changed
    to point to the root key.

    Args:
      key_path: path to the key to traverse to.
    """
    if not self.console and not self.console.IsLoaded():
      return

    registry_helper = self.console.current_helper
    if not registry_helper:
      return

    registry_key = registry_helper.ChangeKeyByPath(key_path)
    if not registry_key:
      self.output_writer.Write(
          u'Unable to change to key: {0:s}\n'.format(key_path))
      return

    sanitized_path = self._SanitizeKeyPath(registry_key.path)
    self.console.SetPrompt(
        registry_file_path=registry_helper.path,
        prepend_string=sanitized_path)

  @magic.line_magic(u'hive')
  def HiveActions(self, line):
    """Handles the hive actions.

    Args:
      line: the command line provide via the console.
    """
    if line.startswith(u'list'):
      self._HiveActionList(line)

    elif line.startswith(u'open ') or line.startswith(u'load '):
      self._HiveActionOpen(line)

    elif line.startswith(u'scan'):
      self._HiveActionScan(line)

  @magic.line_magic(u'ls')
  def ListDirectoryContent(self, line):
    """List all subkeys and values of the current key."""
    if not self.console and not self.console.IsLoaded():
      return

    if u'true' in line.lower():
      verbose = True
    elif u'-v' in line.lower():
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
      time_string, _, _ = time_string.partition(u'.')

      sub.append((u'{0:>19s} {1:>15s}  {2:s}'.format(
          time_string.replace(u'T', u' '), u'[KEY]',
          key.name), True))

    for value in current_key.GetValues():
      if not verbose:
        sub.append((u'{0:>19s} {1:>14s}]  {2:s}'.format(
            u'', u'[' + value.data_type_string, value.name), False))
      else:
        if value.DataIsString():
          value_string = value.GetDataAsObject()

        elif value.DataIsInteger():
          value_string = u'{0:d}'.format(value.GetDataAsObject())

        elif value.DataIsMultiString():
          value_string = u'{0:s}'.format(u''.join(value.GetDataAsObject()))

        elif value.DataIsBinaryData():
          value_string = hexdump.Hexdump.FormatData(
              value.data, maximum_data_size=16)

        else:
          value_string = u''

        sub.append((
            u'{0:>19s} {1:>14s}]  {2:<25s}  {3:s}'.format(
                u'', u'[' + value.data_type_string, value.name, value_string),
            False))

    for entry, subkey in sorted(sub):
      if subkey:
        self.output_writer.Write(u'dr-xr-xr-x {0:s}\n'.format(entry))
      else:
        self.output_writer.Write(u'-r-xr-xr-x {0:s}\n'.format(entry))

  @magic.line_magic(u'parse')
  def ParseCurrentKey(self, line):
    """Parse the current key."""
    if not self.console and not self.console.IsLoaded():
      return

    if u'true' in line.lower():
      verbose = True
    elif u'-v' in line.lower():
      verbose = True
    else:
      verbose = False

    current_helper = self.console.current_helper
    if not current_helper:
      return

    current_key = current_helper.GetCurrentRegistryKey()
    parsed_data = self.console.preg_front_end.ParseRegistryKey(
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
              title=u'Hexadecimal representation')
          header_shown = True
        else:
          table_view = cli_views.CLITableView()

        table_view.AddRow([u'Attribute', value.name])
        table_view.Write(self.output_writer)

        self.console.preg_tool.PrintSeparatorLine()
        self.console.preg_tool.PrintSeparatorLine()

        value_string = hexdump.Hexdump.FormatData(value.data)
        self.output_writer.Write(value_string)
        self.output_writer.Write(u'\n')
        self.output_writer.Write(u'+-'*40)
        self.output_writer.Write(u'\n')

  @magic.line_magic(u'plugin')
  def ParseWithPlugin(self, line):
    """Parse a Registry key using a specific plugin."""
    if not self.console and not self.console.IsLoaded():
      self._output_writer.Write(u'No hive loaded, unable to parse.\n')
      return

    current_helper = self.console.current_helper
    if not current_helper:
      return

    if not line:
      self.output_writer.Write(u'No plugin name added.\n')
      return

    plugin_name = line
    if u'-h' in line:
      items = line.split()
      if len(items) != 2:
        self.output_writer.Write(u'Wrong usage: plugin [-h] PluginName\n')
        return
      if items[0] == u'-h':
        plugin_name = items[1]
      else:
        plugin_name = items[0]

    registry_file_type = current_helper.file_type
    plugins_list = self.console.preg_tool.GetWindowsRegistryPlugins()
    plugin_object = plugins_list.GetPluginObjectByName(
        registry_file_type, plugin_name)
    if not plugin_object:
      self.output_writer.Write(
          u'No plugin named: {0:s} available for Registry type {1:s}\n'.format(
              plugin_name, registry_file_type))
      return

    key_paths = plugin_object.GetKeyPaths()
    if not key_paths:
      self.output_writer.Write(
          u'Plugin: {0:s} has no key information.\n'.format(line))
      return

    if u'-h' in line:
      self._PrintPluginHelp(plugin_object)
      return

    for key_path in key_paths:
      registry_key = current_helper.GetKeyByPath(key_path)
      if not registry_key:
        self.output_writer.Write(u'Key: {0:s} not found\n'.format(key_path))
        continue

      # Move the current location to the key to be parsed.
      self.ChangeDirectory(key_path)
      # Parse the key.
      current_key = current_helper.GetCurrentRegistryKey()
      parsed_data = self.console.preg_front_end.ParseRegistryKey(
          current_key, current_helper, use_plugins=[plugin_name])
      self.console.preg_tool.PrintParsedRegistryKey(
          parsed_data, file_entry=current_helper.file_entry)

  @magic.line_magic(u'pwd')
  def PrintCurrentWorkingDirectory(self, unused_line):
    """Print the current path."""
    if not self.console and not self.console.IsLoaded():
      return

    current_helper = self.console.current_helper
    if not current_helper:
      return

    self.output_writer.Write(u'{0:s}\n'.format(
        current_helper.GetCurrentRegistryPath()))


class PregConsole(object):
  """Class that implements the preg iPython console."""

  _BASE_FUNCTIONS = [
      (u'cd key', u'Navigate the Registry like a directory structure.'),
      (u'ls [-v]', (
          u'List all subkeys and values of a Registry key. If called as ls '
          u'True then values of keys will be included in the output.')),
      (u'parse -[v]', u'Parse the current key using all plugins.'),
      (u'plugin [-h] plugin_name', (
          u'Run a particular key-based plugin on the loaded hive. The correct '
          u'Registry key will be loaded, opened and then parsed.')),
      (u'get_value value_name', (
          u'Get a value from the currently loaded Registry key.')),
      (u'get_value_data value_name', (
          u'Get a value data from a value stored in the currently loaded '
          u'Registry key.')),
      (u'get_key', u'Return the currently loaded Registry key.')]

  @property
  def current_helper(self):
    """The currently loaded Registry helper."""
    return self._currently_registry_helper

  def __init__(self, preg_tool):
    """Initialize the console object.

    Args:
      preg_tool: a preg tool object (instance of PregTool).
    """
    super(PregConsole, self).__init__()
    self._currently_registry_helper = None
    self._currently_loaded_helper_path = u''
    self._registry_helpers = {}

    preferred_encoding = locale.getpreferredencoding()
    if not preferred_encoding:
      preferred_encoding = u'utf-8'

    # TODO: Make this configurable, or derive it from the tool.
    self._output_writer = cli_tools.StdoutOutputWriter(
        encoding=preferred_encoding)

    self.preg_tool = preg_tool
    self.preg_front_end = getattr(preg_tool, u'_front_end', None)

  def _CommandGetCurrentKey(self):
    """Command function to retrieve the currently loaded Registry key.

    Returns:
      The currently loaded Registry key (instance of dfwinreg.WinRegistryKey)
      or None if there is no loaded key.
    """
    registry_helper = self._currently_registry_helper
    return registry_helper.GetCurrentRegistryKey()

  def _CommandGetValue(self, value_name):
    """Return a value object from the currently loaded Registry key.

    Args:
      value_name: string containing the name of the value to be retrieved.

    Returns:
      The Registry value (instance of dfwinreg.WinRegistryValue) if it exists,
      None if either there is no currently loaded Registry key or if the value
      does not exist.
    """
    registry_helper = self._currently_registry_helper

    current_key = registry_helper.GetCurrentRegistryKey()
    if not current_key:
      return

    return current_key.GetValueByName(value_name)

  def _CommandGetValueData(self, value_name):
    """Return the value data from a value in the currently loaded Registry key.

    Args:
      value_name: string containing the name of the value to be retrieved.

    Returns:
      The data from a Registry value if it exists, None if either there is no
      currently loaded Registry key or if the value does not exist.
    """
    registry_value = self._CommandGetValue(value_name)
    if not registry_value:
      return

    return registry_value.GetDataAsObject()

  def _CommandGetRangeForAllLoadedHives(self):
    """Return a range or a list of all loaded hives."""
    return range(0, self._CommandGetTotalNumberOfLoadedHives())

  def _CommandGetTotalNumberOfLoadedHives(self):
    """Return the total number of Registry hives that are loaded."""
    return len(self._registry_helpers)

  def AddRegistryHelper(self, registry_helper):
    """Add a Registry helper to the console object.

    Args:
      registry_helper: registry helper object (instance of PregRegistryHelper)

    Raises:
      ValueError: if not Registry helper is supplied or Registry helper is not
                  the correct object (instance of PregRegistryHelper).
    """
    if not registry_helper:
      raise ValueError(u'No Registry helper supplied.')

    if not isinstance(registry_helper, PregRegistryHelper):
      raise ValueError(
          u'Object passed in is not an instance of PregRegistryHelper.')

    if registry_helper.path not in self._registry_helpers:
      self._registry_helpers[registry_helper.path] = registry_helper

  def GetConfig(self):
    """Retrieves the iPython config.

    Returns:
      The IPython config object (instance of
      IPython.terminal.embed.InteractiveShellEmbed)
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
      True if a Registry helper is currently loaded and ready
      to be used, otherwise False is returned.
    """
    registry_helper = self._currently_registry_helper
    if not registry_helper:
      return False

    current_key = registry_helper.GetCurrentRegistryKey()
    if hasattr(current_key, u'path'):
      return True

    if registry_helper.name != u'N/A':
      return True

    self._output_writer.Write(
        u'No hive loaded, cannot complete action. Use "hive list" '
        u'and "hive open" to load a hive.\n')
    return False

  def PrintBanner(self):
    """Writes a banner to the output writer."""
    self._output_writer.Write(u'\n')
    self._output_writer.Write(
        u'Welcome to PREG - home of the Plaso Windows Registry Parsing.\n')

    table_view = cli_views.CLITableView(
        column_names=[u'Function', u'Description'], title=u'Available commands')
    for function_name, description in self._BASE_FUNCTIONS:
      table_view.AddRow([function_name, description])
    table_view.Write(self._output_writer)

    if len(self._registry_helpers) == 1:
      self.LoadRegistryFile(0)
      registry_helper = self._currently_registry_helper
      self._output_writer.Write(
          u'Opening hive: {0:s} [{1:s}]\n'.format(
              registry_helper.path, registry_helper.collector_name))
      self.SetPrompt(registry_file_path=registry_helper.path)

    # TODO: make sure to limit number of characters per line of output.
    registry_helper = self._currently_registry_helper
    if registry_helper and registry_helper.name != u'N/A':
      self._output_writer.Write(
          u'Registry file: {0:s} [{1:s}] is available and loaded.\n'.format(
              registry_helper.name, registry_helper.path))

    else:
      self._output_writer.Write(u'More than one Registry file ready for use.\n')
      self._output_writer.Write(u'\n')
      self.PrintRegistryFileList()
      self._output_writer.Write(u'\n')
      self._output_writer.Write((
          u'Use "hive open INDEX" to load a Registry file and "hive list" to '
          u'see a list of available Registry files.\n'))

    self._output_writer.Write(u'\nHappy command line console fu-ing.')

  def LoadRegistryFile(self, index):
    """Load a Registry file helper from the list of Registry file helpers.

    Args:
      index: index into the list of available Registry helpers.

    Raises:
      UnableToLoadRegistryHelper: if the index attempts to load an entry
                                  that does not exist or if there are no
                                  Registry helpers loaded.
    """
    helper_keys = self._registry_helpers.keys()

    if not helper_keys:
      raise errors.UnableToLoadRegistryHelper(u'No Registry helpers loaded.')

    if index < 0 or index >= len(helper_keys):
      raise errors.UnableToLoadRegistryHelper(u'Index out of bounds.')

    if self._currently_registry_helper:
      self._currently_registry_helper.Close()

    registry_helper_path = helper_keys[index]
    self._currently_registry_helper = (
        self._registry_helpers[registry_helper_path])
    self._currently_loaded_helper_path = registry_helper_path

    self._currently_registry_helper.Open()

  def PrintRegistryFileList(self):
    """Write a list of all available registry helpers to an output writer."""
    if not self._registry_helpers:
      return

    self._output_writer.Write(u'Index Hive [collector]\n')
    for index, registry_helper in enumerate(self._registry_helpers.values()):
      collector_name = registry_helper.collector_name
      if not collector_name:
        collector_name = u'Currently Allocated'

      if self._currently_loaded_helper_path == registry_helper.path:
        star = u'*'
      else:
        star = u''

      self._output_writer.Write(u'{0:<5d} {1:s}{2:s} [{3:s}]\n'.format(
          index, star, registry_helper.path, collector_name))

  def SetPrompt(
      self, registry_file_path=None, config=None, prepend_string=None):
    """Sets the prompt string on the console.

    Args:
      registry_file_path: optional hive name or path of the Registry file. The
                          default is None which sets the value to a string
                          indicating an unknown Registry file.
      config: optional IPython configuration object (instance of
              IPython.terminal.embed.InteractiveShellEmbed).
              and an attempt to automatically derive the config is done.
      prepend_string: optional string that can be injected into the prompt
                      just prior to the command count.
    """
    if registry_file_path is None:
      path_string = u'Unknown Registry file loaded'
    else:
      path_string = registry_file_path

    prompt_strings = [
        r'[{color.LightBlue}\T{color.Normal}]',
        r'{color.LightPurple} ',
        path_string,
        r'\n{color.Normal}']
    if prepend_string is not None:
      prompt_strings.append(u'{0:s} '.format(prepend_string))
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
      registry_file_types = self.preg_front_end.GetRegistryTypes()

    registry_helpers = self.preg_front_end.GetRegistryHelpers(
        registry_file_types=registry_file_types,
        plugin_names=self.preg_tool.plugin_names)

    for registry_helper in registry_helpers:
      self.AddRegistryHelper(registry_helper)

    # Adding variables in scope.
    namespace = {}

    namespace.update(globals())
    namespace.update({
        u'console': self,
        u'front_end': self.preg_front_end,
        u'get_current_key': self._CommandGetCurrentKey,
        u'get_key': self._CommandGetCurrentKey,
        u'get_value': self. _CommandGetValue,
        u'get_value_data': self. _CommandGetValueData,
        u'number_of_hives': self._CommandGetTotalNumberOfLoadedHives,
        u'range_of_hives': self._CommandGetRangeForAllLoadedHives,
        u'tool': self.preg_tool})

    ipshell_config = self.GetConfig()

    if len(self._registry_helpers) == 1:
      self.LoadRegistryFile(0)

    registry_helper = self._currently_registry_helper

    if registry_helper:
      registry_file_path = registry_helper.name
    else:
      registry_file_path = u'NO HIVE LOADED'

    self.SetPrompt(registry_file_path=registry_file_path, config=ipshell_config)

    # Starting the shell.
    ipshell = InteractiveShellEmbed(
        user_ns=namespace, config=ipshell_config, banner1=u'', exit_msg=u'')
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
        u'complete_command', CommandCompleterCd, str_key=u'%cd')
    ipshell.set_hook(
        u'complete_command', CommandCompleterVerbose, str_key=u'%ls')
    ipshell.set_hook(
        u'complete_command', CommandCompleterVerbose, str_key=u'%parse')
    ipshell.set_hook(
        u'complete_command', CommandCompleterPlugins, str_key=u'%plugin')

    ipshell()


# Completer commands need to be top level methods or directly callable
# and cannot be part of a class that needs to be initialized.
def CommandCompleterCd(console, unused_core_completer):
  """Command completer function for cd.

  Args:
    console: IPython shell object (instance of InteractiveShellEmbed).
  """
  return_list = []

  namespace = getattr(console, u'user_ns', {})
  magic_class = namespace.get(u'PregMagics', None)

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
  namespace = getattr(console, u'user_ns', {})
  magic_class = namespace.get(u'PregMagics', None)

  if not magic_class:
    return []

  if not magic_class.console.IsLoaded():
    return []

  command_options = []
  if not u'-h' in core_completer.line:
    command_options.append(u'-h')

  registry_helper = magic_class.console.current_helper
  registry_file_type = registry_helper.file_type

  plugins_list = console.preg_tool.GetWindowsRegistryPlugins()
  # TODO: refactor this into PluginsList.
  for plugin_cls in plugins_list.GetKeyPlugins(registry_file_type):
    if plugin_cls.NAME == u'winreg_default':
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
  if u'-v' in core_completer.line:
    return []

  return [u'-v']


def Main():
  """Run the tool."""
  tool = PregTool()

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
