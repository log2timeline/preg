# -*- coding: utf-8 -*-
"""Shared functions and classes for testing."""

from __future__ import unicode_literals

import io
import os
import sys
import unittest

from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.path import factory as path_spec_factory
from dfvfs.resolver import resolver as path_spec_resolver

from plaso.cli import tools


def skipUnlessHasTestFile(path_segments):  # pylint: disable=invalid-name
  """Decorator to skip a test if the test file does not exist.

  Args:
    path_segments (list[str]): path segments inside the test data directory.

  Returns:
    function: to invoke.
  """
  fail_unless_has_test_file = getattr(
      unittest, 'fail_unless_has_test_file', False)

  path = os.path.join('test_data', *path_segments)
  if fail_unless_has_test_file or os.path.exists(path):
    return lambda function: function

  if sys.version_info[0] < 3:
    path = path.encode('utf-8')

  # Note that the message should be of type str which is different for
  # different versions of Python.
  return unittest.skip('missing test file: {0:s}'.format(path))


def GetTestFilePath(path_segments):
  """Retrieves the path of a test file in the test data directory.

  Args:
    path_segments (list[str]): path segments inside the test data directory.

  Returns:
    str: path of the test file.
  """
  # Note that we need to pass the individual path segments to os.path.join
  # and not a list.
  return os.path.join(os.getcwd(), 'test_data', *path_segments)


class BaseTestCase(unittest.TestCase):
  """The base test case."""

  _DATA_PATH = os.path.join(os.getcwd(), 'data')
  _TEST_DATA_PATH = os.path.join(os.getcwd(), 'test_data')

  # Show full diff results, part of TestCase so does not follow our naming
  # conventions.
  maxDiff = None

  def _GetTestFileEntry(self, path_segments):
    """Creates a file entry that references a file in the test data directory.

    Args:
      path_segments (list[str]): path segments inside the test data directory.

    Returns:
      dfvfs.FileEntry: file entry.
    """
    path = self._GetTestFilePath(path_segments)
    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=path)
    return path_spec_resolver.Resolver.OpenFileEntry(path_spec)

  def _GetTestFilePath(self, path_segments):
    """Retrieves the path of a test file in the test data directory.

    Args:
      path_segments (list[str]): path segments inside the test data directory.

    Returns:
      str: path of the test file.
    """
    # Note that we need to pass the individual path segments to os.path.join
    # and not a list.
    return os.path.join(self._TEST_DATA_PATH, *path_segments)

  def _GetTestFilePathSpec(self, path_segments):
    """Retrieves a path specification of a test file in the test data directory.

    Args:
      path_segments (list[str]): components of a path to a test file, relative
          to the test_data directory.

    Returns:
      dfvfs.PathSpec: path specification.
    """
    path = self._GetTestFilePath(path_segments)
    return path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=path)


class TestOptions(object):
  """Test options."""


class TestOutputWriter(tools.FileObjectOutputWriter):
  """Test output writer."""

  def __init__(self, encoding='utf-8'):
    """Initializes the output writer object.

    Args:
      encoding (Optional[str]): output encoding.
    """
    file_object = io.BytesIO()
    super(TestOutputWriter, self).__init__(file_object, encoding=encoding)
    self._read_offset = 0

  def ReadOutput(self):
    """Reads the newly added output data.

    Returns:
      bytes: encoded output data.
    """
    self._file_object.seek(self._read_offset, os.SEEK_SET)
    output_data = self._file_object.read()
    self._read_offset = self._file_object.tell()

    return output_data


class CLIToolTestCase(BaseTestCase):
  """Unit test case for a CLI tool."""

  def _RunArgparseFormatHelp(self, argument_parser):
    """Runs argparse.format_help() with test conditions.

    Args:
      argument_parser (argparse.ArgumentParser): argument parser.

    Returns:
      bytes: output of argparse.format_help().
    """
    columns_environment_variable = os.environ.get('COLUMNS', None)
    os.environ['COLUMNS'] = '80'

    try:
      output = argument_parser.format_help()
    finally:
      if columns_environment_variable:
        os.environ['COLUMNS'] = columns_environment_variable
      else:
        del os.environ['COLUMNS']

    return output
