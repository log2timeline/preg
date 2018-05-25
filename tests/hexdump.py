#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the binary data in hexadecimal (hexdump) formatter."""

import unittest

from l2tpreg import hexdump

from tests import test_lib


class HexdumpTests(test_lib.BaseTestCase):
  """Tests for the binary data in hexadecimal (hexdump) formatter."""

  def testFormatDataInHexadecimal(self):
    """Tests the _FormatDataInHexadecimal function."""
    data = b'\x00\x01\x02\x03\x04\x05\x06'
    expected_formatted_data = (
        '0x00000000  00 01 02 03 04 05 06                              '
        '.......\n'
        '\n')
    formatted_data = hexdump.Hexdump._FormatDataInHexadecimal(data)
    self.assertEqual(formatted_data, expected_formatted_data)

    data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09'
    expected_formatted_data = (
        '0x00000000  00 01 02 03 04 05 06 07  08 09                    '
        '..........\n'
        '\n')
    formatted_data = hexdump.Hexdump._FormatDataInHexadecimal(data)
    self.assertEqual(formatted_data, expected_formatted_data)

    data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
    expected_formatted_data = (
        '0x00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  '
        '................\n'
        '\n')
    formatted_data = hexdump.Hexdump._FormatDataInHexadecimal(data)
    self.assertEqual(formatted_data, expected_formatted_data)

    data = (
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f')
    expected_formatted_data = (
        '0x00000000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  '
        '................\n'
        '...\n'
        '0x00000020  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  '
        '................\n'
        '\n')
    formatted_data = hexdump.Hexdump._FormatDataInHexadecimal(data)
    self.assertEqual(formatted_data, expected_formatted_data)

  # TODO: add tests for FormatData


if __name__ == '__main__':
  unittest.main()
