# -*- coding: utf-8 -*-
"""List of plaso Windows Registry plugins."""

from l2tpreg import definitions


class PluginList(object):
  """Windows Registry plugin list."""

  def __init__(self):
    """Initializes a plugin list."""
    super(PluginList, self).__init__()
    self._plugins = {}

  def __iter__(self):
    """Returns an iterator of all Windows Registry plugins."""
    ret = []
    _ = map(ret.extend, self._plugins.values())
    for item in ret:
      yield item

  def _GetPluginsByType(self, plugins_dict, registry_file_type):
    """Retrieves the Windows Registry plugins of a specific type.

    Args:
      plugins_dict (dict[str, list[plaso.WindowsRegistryPlugin]): Windows
          Registry plugins by plugin type.
      registry_file_type (str): Windows Registry file type, such as "NTUSER",
          "SOFTWARE".

    Returns:
      list[plaso.WindowsRegistryPlugin]: Windows Registry plugins for the
          specific Windows Registry file type.
    """
    return plugins_dict.get(
        registry_file_type, []) + plugins_dict.get(u'any', [])

  def AddPlugin(self, plugin_class):
    """Adds a Windows Registry plugin to the list.

    Only plugins with full Windows Registry key paths are added.

    Args:
      plugin_class (type): plugin class that is being added.
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
    """Rerieves all plugins.

    Returns:
      list[plaso.WindowsRegistryPlugin]: all plugins.
    """
    plugins = []
    _ = map(plugins.extend, self._plugins.values())
    return plugins

  def GetKeyPaths(self, plugin_names=None):
    """Retrieves a list of Windows Registry key paths.

    Args:
      plugin_names (Optional[list[str]]): plugin names, if defined only keys
          from these plugins will be expanded. None means all key plugins will
          get expanded keys.

    Returns:
      set[str]: Windows Registry key paths.
    """
    key_paths = set()
    for plugin_cls in self.GetAllPlugins():
      if plugin_names and plugin_cls.NAME not in plugin_names:
        continue

      plugin_key_paths = PluginList.GetKeyPathsFromPlugin(plugin_cls)
      key_paths = key_paths.union(plugin_key_paths)

    return key_paths

  @classmethod
  def GetKeyPathsFromPlugin(cls, plugin_cls):
    """Retrieves a list of Windows Registry key paths from a plugin.

    Args:
      plugin_cls (type): Windows Registry plugin.

    Returns:
      list[str]: Windows Registry key paths.
    """
    key_paths = []
    for registry_key_filter in plugin_cls.FILTERS:
      plugin_key_paths = getattr(registry_key_filter, u'key_paths', [])
      for plugin_key_path in plugin_key_paths:
        if plugin_key_path not in key_paths:
          key_paths.append(plugin_key_path)

    return sorted(key_paths)

  def GetPluginObjectByName(self, registry_file_type, plugin_name):
    """Retrieves a specific Windows Registry plugin.

    Args:
      registry_file_type (str): Windows Registry file type, such as "NTUSER",
          "SOFTWARE".
      plugin_name (str): name of the plugin.

    Returns:
      plaso.WindowsRegistryPlugin: Windows Registry plugin or None.
    """
    # TODO: make this a dict lookup instead of a list iteration.
    for plugin_cls in self.GetPlugins(registry_file_type):
      if plugin_cls.NAME == plugin_name:
        return plugin_cls()

  def GetPluginObjects(self, registry_file_type):
    """Creates new instances of a specific type of Windows Registry plugins.

    Args:
      registry_file_type (str): Windows Registry file type, such as "NTUSER",
          "SOFTWARE".

    Returns:
      list[plaso.WindowsRegistryPlugin]: Windows Registry plugins.
    """
    return [plugin_cls() for plugin_cls in self.GetPlugins(registry_file_type)]

  def GetPlugins(self, registry_file_type):
    """Retrieves the Windows Registry key-based plugins of a specific type.

    Args:
      registry_file_type (str): Windows Registry file type, such as "NTUSER",
          "SOFTWARE".

    Returns:
      list[plaso.WindowsRegistryPlugin]: Windows Registry plugins for
          the specific plugin type.
    """
    return self._GetPluginsByType(self._plugins, registry_file_type)

  def GetRegistryPlugins(self, filter_string):
    """Retrieves the Windows Registry plugins based on a filter string.

    Args:
      filter_string (str): name of the plugin or an empty string for
          all the plugins.

    Returns:
      list[plaso.WindowsRegistryPlugin]: Windows Registry plugins.
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
      filter_string (str): name of the plugin or an empty string for
          all the plugins.

    Returns:
      list[str]: Windows Registry types of the corresponding plugins.
    """
    if filter_string:
      filter_string = filter_string.lower()

    registry_file_types = set()
    for plugin_type, plugins_per_type in iter(self._plugins.items()):
      for plugin in plugins_per_type:
        if not filter_string or filter_string == plugin.NAME.lower():
          if plugin_type == u'any':
            registry_file_types.update(definitions.REGISTRY_FILE_TYPES)

          else:
            registry_file_types.add(plugin_type)

    return list(registry_file_types)

  def GetRegistryTypesFromPlugins(self, plugin_names):
    """Retrieves the Registry types based on plugin names.

    Args:
      plugin_names (list[str]): plugin names.

    Returns:
      list[str]: Windows Registry types of the corresponding plugins.
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
            registry_file_types.update(definitions.REGISTRY_FILE_TYPES)

          else:
            registry_file_types.add(plugin_type)

    return list(registry_file_types)

  def GetRegistryPluginsFromRegistryType(self, registry_file_type):
    """Retrieves the Windows Registry plugins based on a Registry type.

    Args:
      registry_file_type (str): Windows Registry file type, such as "NTUSER",
          "SOFTWARE".

    Returns:
      list[str]: Windows Registry types of the corresponding plugins.
    """
    if registry_file_type:
      registry_file_type = registry_file_type.upper()

    plugins_to_run = []
    for plugin_type, plugins_per_type in iter(self._plugins.items()):
      if not registry_file_type or plugin_type in (u'any', registry_file_type):
        plugins_to_run.extend(plugins_per_type)

    return plugins_to_run
