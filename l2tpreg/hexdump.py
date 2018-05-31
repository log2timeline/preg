# -*- coding: utf-8 -*-
"""Binary data in hexadecimal (hexdump) formatter."""

from __future__ import unicode_literals

from l2tpreg import py2to3


class Hexdump(object):
  """Binary data in hexadecimal (hexdump) formatter."""

  _HEXDUMP_CHARACTER_MAP = [
      '.' if byte < 0x20 or byte > 0x7e else chr(byte) for byte in range(256)]

  @classmethod
  def _FormatDataInHexadecimal(cls, data):
    """Formats data in a hexadecimal representation in groups of 16 bytes.

    Repeated blocks of the same 16 bytes are represented by "...".

    Args:
      data (bytes): data.

    Returns:
      str: hexadecimal representation of the data in groups of 16 bytes.
    """
    in_group = False
    previous_hexadecimal_string = None

    lines = []
    data_size = len(data)
    for block_index in range(0, data_size, 16):
      data_string = data[block_index:block_index + 16]

      hexadecimal_byte_values = []
      printable_values = []
      for byte_value in data_string:
        if isinstance(byte_value, py2to3.STRING_TYPES):
          byte_value = ord(byte_value)

        hexadecimal_byte_value = '{0:02x}'.format(byte_value)
        hexadecimal_byte_values.append(hexadecimal_byte_value)

        printable_value = cls._HEXDUMP_CHARACTER_MAP[byte_value]
        printable_values.append(printable_value)

      remaining_size = 16 - len(data_string)
      if remaining_size == 0:
        whitespace = ''
      elif remaining_size >= 8:
        whitespace = ' ' * ((3 * remaining_size) - 1)
      else:
        whitespace = ' ' * (3 * remaining_size)

      hexadecimal_string_part1 = ' '.join(hexadecimal_byte_values[0:8])
      hexadecimal_string_part2 = ' '.join(hexadecimal_byte_values[8:16])
      hexadecimal_string = '{0:s}  {1:s}{2:s}'.format(
          hexadecimal_string_part1, hexadecimal_string_part2, whitespace)

      if (previous_hexadecimal_string is not None and
          previous_hexadecimal_string == hexadecimal_string and
          block_index + 16 < data_size):

        if not in_group:
          in_group = True

          lines.append('...')

      else:
        printable_string = ''.join(printable_values)

        lines.append('0x{0:08x}  {1:s}  {2:s}'.format(
            block_index, hexadecimal_string, printable_string))

        in_group = False
        previous_hexadecimal_string = hexadecimal_string

    lines.extend(['', ''])
    return '\n'.join(lines)

  @classmethod
  def FormatData(cls, data, data_offset=0, maximum_data_size=None):
    """Formats binary data in hexadecimal representation.

    All ASCII characters in the hexadecimal representation (hexdump) are
    translated back to their character representation.

    Args:
      data (bytes): data.
      data_offset (Optional[int]): offset within the data to start formatting.
      maximum_data_size (Optional[int]): maximum size of the data to format,
          where None represents all of the data.

    Returns:
      str: hexadecimal representation of the data.
    """
    data_size = len(data)
    if maximum_data_size is not None and maximum_data_size < data_size:
      data_size = maximum_data_size

    return cls._FormatDataInHexadecimal(data[data_offset:data_size])
