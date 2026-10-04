"""eSIM IoT Profile Download Skill 单元测试"""

import unittest
from src.utils import (
    bytes_to_hex, hex_to_bytes, digits_to_bcd,
    sw_to_string, is_success, needs_fetch, has_more_data,
    chunk_bytes, validate_iccid, validate_eid, validate_matching_id,
)


class TestBytesToHex(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(bytes_to_hex(b'\x01\x02\x0a\xff'), "01020AFF")
    
    def test_empty(self):
        self.assertEqual(bytes_to_hex(b''), "")


class TestHexToBytes(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(hex_to_bytes("01020AFF"), b'\x01\x02\x0a\xff')
    
    def test_with_whitespace(self):
        self.assertEqual(hex_to_bytes("01 02 0A FF"), b'\x01\x02\x0a\xff')


class TestDigitsToBcd(unittest.TestCase):
    def test_even_length(self):
        self.assertEqual(digits_to_bcd("1234567890"), b'\x12\x34\x56\x78\x90')
    
    def test_odd_length(self):
        result = digits_to_bcd("12345")
        self.assertEqual(result, b'\x12\x34\x5f')


class TestSwFunctions(unittest.TestCase):
    def test_sw_to_string(self):
        self.assertEqual(sw_to_string(0x90, 0x00), "9000")
        self.assertEqual(sw_to_string(0x91, 0x50), "9150")
    
    def test_is_success(self):
        self.assertTrue(is_success(0x90, 0x00))
        self.assertFalse(is_success(0x91, 0x00))
    
    def test_needs_fetch(self):
        self.assertTrue(needs_fetch(0x91, 0x00))
        self.assertFalse(needs_fetch(0x90, 0x00))
    
    def test_has_more_data(self):
        self.assertTrue(has_more_data(0x61, 0x00))
        self.assertFalse(has_more_data(0x90, 0x00))


class TestChunkBytes(unittest.TestCase):
    def test_basic(self):
        data = b'\x01\x02\x03\x04\x05\x06'
        chunks = chunk_bytes(data, 2)
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[0], b'\x01\x02')
        self.assertEqual(chunks[1], b'\x03\x04')
        self.assertEqual(chunks[2], b'\x05\x06')
    
    def test_partial_last_chunk(self):
        data = b'\x01\x02\x03\x04\x05'
        chunks = chunk_bytes(data, 2)
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[2], b'\x05')


class TestValidators(unittest.TestCase):
    def test_validate_iccid(self):
        self.assertTrue(validate_iccid("8929901012345678905"))
        self.assertFalse(validate_iccid("123"))
        self.assertFalse(validate_iccid("ABC"))
    
    def test_validate_eid(self):
        self.assertTrue(validate_eid("89049032123451234512345678901235"))
        self.assertFalse(validate_eid("123"))
        self.assertFalse(validate_eid("ABCDEF" + "0" * 26))
    
    def test_validate_matching_id(self):
        self.assertTrue(validate_matching_id("04386-AGYFT-A74Y8-3F815"))
        self.assertTrue(validate_matching_id("abc123"))
        self.assertFalse(validate_matching_id(""))
        self.assertFalse(validate_matching_id("a" * 33))


if __name__ == '__main__':
    unittest.main()
