# -*- coding: utf-8 -*-
"""Windows Registry helper."""

from __future__ import unicode_literals

import logging

from dfwinreg import registry as dfwinreg_registry

from plaso.parsers import winreg

from l2tpreg import definitions


class PregRegistryHelper(object):
  """Windows Registry helper.

  Attributes:
    file_entry (dfvfs.FileEntry): file entry.
  """

  _KEY_PATHS_PER_REGISTRY_TYPE = {
      definitions.REGISTRY_FILE_TYPE_NTUSER: frozenset([
          '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer']),
      definitions.REGISTRY_FILE_TYPE_SAM: frozenset([
          '\\SAM\\Domains\\Account\\Users']),
      definitions.REGISTRY_FILE_TYPE_SECURITY: frozenset([
          '\\Policy\\PolAdtEv']),
      definitions.REGISTRY_FILE_TYPE_SOFTWARE: frozenset([
          '\\Microsoft\\Windows\\CurrentVersion\\App Paths']),
      definitions.REGISTRY_FILE_TYPE_SYSTEM: frozenset([
          '\\Select']),
      definitions.REGISTRY_FILE_TYPE_USRCLASS: frozenset([
          '\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion']),
  }

  def __init__(
      self, file_entry, collector_name, codepage='cp1252'):
    """Initialize a Windows Registry helper.

    Args:
      file_entry (dfvfs.FileEntry): file entry.
      collector_name (str0: name of the collector, for example "TSK".
      codepage (Optional[str]): codepage value used for the Windows Registry
          file.
    """
    super(PregRegistryHelper, self).__init__()
    self._codepage = codepage
    self._collector_name = collector_name
    self._currently_registry_key = None
    self._key_path_prefix = None
    self._registry_file = None
    self._registry_file_name = None
    self._registry_file_type = definitions.REGISTRY_FILE_TYPE_UNKNOWN
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
    """str: name of the collector used to discover the Windows Registry file."""
    return self._collector_name

  @property
  def file_type(self):
    """str: Windows Registry file type."""
    return self._registry_file_type

  @property
  def name(self):
    """str: name of the Windows Registry file."""
    return self._registry_file_name

  @property
  def path(self):
    """str: path of the Windows Registry file."""
    path_spec = getattr(self.file_entry, 'path_spec', None)
    if not path_spec:
      return 'N/A'

    return getattr(path_spec, 'location', 'N/A')

  @property
  def root_key(self):
    """dfwinreg.WinRegistryKey: root key of Windows Registry file."""
    if self._registry_file:
      return self._registry_file.GetRootKey()

  def _Reset(self):
    """Resets all attributes of the Registry helper."""
    self._currently_registry_key = None
    self._key_path_prefix = None
    self._registry_file = None
    self._registry_file_name = None
    self._registry_file_type = definitions.REGISTRY_FILE_TYPE_UNKNOWN

  def ChangeKeyByPath(self, key_path):
    """Changes the current key defined by the path.

    Args:
      key_path (str): absolute or relative Windows Registry key path.

    Returns:
      dfwinreg.WinRegistryKey: key or None if not available.
    """
    if key_path == '.':
      return self._currently_registry_key

    path_segments = []

    # If the key path is relative to the root key add the key path prefix.
    if not key_path or key_path.startswith('\\'):
      path_segments.append(self._key_path_prefix)

      # If no key path was provided then change to the root key.
      if not key_path:
        path_segments.append('\\')

    else:
      key_path_upper = key_path.upper()
      if not key_path_upper.startswith('HKEY_'):
        current_path = getattr(self._currently_registry_key, 'path', None)
        if current_path:
          path_segments.append(current_path)

    path_segments.append(key_path)

    # Split all the path segments based on the path (segment) separator.
    path_segments = [
        segment.split('\\') for segment in path_segments]

    # Flatten the sublists into one list.
    path_segments = [
        element for sublist in path_segments for element in sublist]

    # Remove empty and current ('.') path segments.
    path_segments = [
        segment for segment in path_segments
        if segment not in [None, '', '.']]

    # Remove parent ('..') path segments.
    index = 0
    while index < len(path_segments):
      if path_segments[index] == '..':
        path_segments.pop(index)
        index -= 1

        if index > 0:
          path_segments.pop(index)
          index -= 1

      index += 1

    key_path = '\\'.join(path_segments)
    return self.GetKeyByPath(key_path)

  def Close(self):
    """Closes the helper."""
    self._Reset()

  def GetCurrentRegistryKey(self):
    """Retrieves the currently Windows Registry key.

    Returns:
      dfwinreg.WinRegistryKey: current Windows Registry key.
    """
    return self._currently_registry_key

  def GetCurrentRegistryPath(self):
    """Retrieves the currently key path.

    Returns:
      str: current key path.
    """
    return getattr(self._currently_registry_key, 'path', None)

  def GetKeyByPath(self, key_path):
    """Retrieves a specific key defined by the Registry key path.

    Args:
      key_path (str): key path relative to the root key of the Windows Registry
          file or relative to the root of the Windows Registry.

    Returns:
      dfwinreg.WinRegistryKey: key or None if not available.
    """
    registry_key = self._win_registry.GetKeyByPath(key_path)
    if not registry_key:
      return

    self._currently_registry_key = registry_key
    return registry_key

  def GetRegistryFileType(self, registry_file):
    """Determines the Windows Registry type based on keys present in the file.

    Args:
      registry_file (dfwinreg.WinRegistryFile): Windows Registry file.

    Returns:
      str: Windows Registry file type, such as "NTUSER", "SOFTWARE".
    """
    registry_file_type = definitions.REGISTRY_FILE_TYPE_UNKNOWN
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
      raise IOError('Registry file already open.')

    file_object = self.file_entry.GetFileObject()
    if not file_object:
      logging.error(
          'Unable to open Registry file: {0:s} [{1:s}]'.format(
              self.path, self._collector_name))
      raise IOError('Unable to open Registry file.')

    win_registry_reader = winreg.FileObjectWinRegistryFileReader()
    self._registry_file = win_registry_reader.Open(file_object)
    if not self._registry_file:
      file_object.close()

      logging.error(
          'Unable to open Registry file: {0:s} [{1:s}]'.format(
              self.path, self._collector_name))
      raise IOError('Unable to open Registry file.')

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
