# -*- coding: utf-8 -*-
"""Preg plaso front-end."""

from __future__ import print_function
from __future__ import unicode_literals

import logging

from dfvfs.helpers import file_system_searcher
from dfvfs.helpers import windows_path_resolver
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.path import factory as path_spec_factory
from dfvfs.resolver import resolver as path_spec_resolver

from plaso.containers import sessions
from plaso.lib import py2to3
from plaso.parsers import mediator as parsers_mediator
from plaso.parsers import manager as parsers_manager
from plaso.parsers import winreg_plugins  # pylint: disable=unused-import
from plaso.preprocessors import manager as preprocess_manager
# TODO: refactor usage of fake storage.
from plaso.storage import fake_storage

from l2tpreg import definitions
from l2tpreg import helper
from l2tpreg import plugin_list


class PregFrontend(object):
  """Preg front-end.

  Attributes:
    knowledge_base_object (plaso.KnowledgeBase): knowledge base.
  """

  def __init__(self):
    """Initializes a preg front-end."""
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
    """PluginList: Windows Registry plugin list."""
    return self._registry_plugin_list

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
    environment_variables = self.knowledge_base_object.GetEnvironmentVariables()

    for source_path_spec in self._source_path_specs:
      if source_path_spec.type_indicator == dfvfs_definitions.TYPE_INDICATOR_OS:
        file_entry = path_spec_resolver.Resolver.OpenFileEntry(source_path_spec)
        if file_entry.IsFile():
          yield helper.PregRegistryHelper(
              file_entry, 'OS', self.knowledge_base_object, codepage=codepage)
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
                file_entry, collector_name, self.knowledge_base_object,
                codepage=codepage)

        else:
          path_spec = path_resolver.ResolvePath(path)
          if not path_spec:
            continue

          file_entry = file_system.GetFileEntryByPathSpec(path_spec)
          if not file_entry:
            continue

          yield helper.PregRegistryHelper(
              file_entry, collector_name, self.knowledge_base_object,
              codepage=codepage)

      finally:
        file_system.Close()

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

  def ExpandKeysRedirect(self, keys):
    """Expands Windows Registry key paths with their redirect equivalents.

    Args:
      keys (list[str]): Windows Registry key paths.
    """
    for key in keys:
      if key.startswith('\\Software') and 'Wow6432Node' not in key:
        _, first, second = key.partition('\\Software')
        keys.append('{0:s}\\Wow6432Node{1:s}'.format(first, second))

  def GetRegistryFilePaths(self, registry_file_types):
    """Retrieves Windows Registry file paths.

    If the Windows Registry file type is not set this functions attempts
    to determine it based on the presence of specific Windows Registry keys.

    Args:
      registry_file_types (set[str]): Windows Registry file types, such as
          "NTUSER", "SOFTWARE".

    Returns:
      list[str]: paths of Windows Registry files.
    """
    if self._parse_restore_points:
      restore_path = (
          '\\System Volume Information\\_restore.+\\RP[0-9]+\\snapshot\\')
    else:
      restore_path = ''

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
            self.knowledge_base_object)
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

    helpers_list = []
    for path in paths:
      for registry_helper in self._GetRegistryHelperFromPath(path, codepage):
        helpers_list.append(registry_helper)

    return helpers_list

  # TODO: remove after refactoring.
  def GetRegistryPlugins(self, filter_string):
    """Retrieves the Windows Registry plugins based on a filter string.

    Args:
      filter_string (str): name of the plugin or an empty string for all
          the plugins.

    Returns:
      list[plaso.RegistryPlugin]: Windows Registry plugins.
    """
    return self._registry_plugin_list.GetRegistryPlugins(filter_string)

  # TODO: remove after refactoring.
  def GetRegistryPluginsFromRegistryType(self, registry_file_type):
    """Retrieves the Windows Registry plugins based on a Registry type.

    Args:
      registry_file_type (str): Windows Registry file type, such as "NTUSER",
          "SOFTWARE".

    Returns:
      list[plaso.RegistryPlugin]: Windows Registry plugins.
    """
    return self._registry_plugin_list.GetRegistryPluginsFromRegistryType(
        registry_file_type)

  def GetRegistryTypes(self, filter_string):
    """Retrieves the Windows Registry types based on a filter string.

    Args:
      filter_string (str): name of the plugin or an empty string for all
          the plugins.

    Returns:
      list[str]: Windows Registry types.
    """
    return self._registry_plugin_list.GetRegistryTypes(filter_string)

  def GetWindowsRegistryPlugins(self):
    """Retrieves a list of all available Windows Registry plugins.

    Returns:
      PluginList: Windows Registry plugins list.
    """
    winreg_parser = parsers_manager.ParsersManager.GetParserObjectByName(
        'winreg')
    if not winreg_parser:
      return

    registry_plugin_list = plugin_list.PluginList()
    for _, plugin_class in winreg_parser.GetPlugins():
      registry_plugin_list.AddPlugin(plugin_class)
    return registry_plugin_list

  def ParseRegistryFile(
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

  def SetSingleFile(self, single_file=False):
    """Sets the single file processing parameter.

    Args:
      single_file (Optional[bool]): True if source is a single file input,
          False otherwise for example if source is a storage media format.
    """
    self._single_file = single_file

  def SetSourcePath(self, source_path):
    """Sets the source path.

    Args:
      source_path (str): path of the source.
    """
    self._source_path = source_path

  def SetSourcePathSpecs(self, source_path_specs):
    """Sets the source path specifications.

    Args:
      source_path_specs (list[dfvfs.PathSpec]): source path specifications.
    """
    self._source_path_specs = source_path_specs

  def SetKnowledgeBase(self, knowledge_base_object):
    """Sets the knowledge base.

    Args:
      knowledge_base_object (plaso.KnowledgeBase): knowledge base.
    """
    self.knowledge_base_object = knowledge_base_object
