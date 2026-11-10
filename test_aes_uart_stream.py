#!/usr/bin/env python3
"""
Unit and integration tests for aes_uart_stream.py
Tests key parsing, PKCS#7 padding, file streaming, mock FPGA hardware, and roundtrip integrity.
"""

import os
import io
import tempfile
import unittest
from aes_uart_stream import (
    parse_key,
    pkcs7_pad,
    pkcs7_unpad,
    software_aes_ecb_encrypt,
    software_aes_ecb_decrypt,
    AESUartEncryptor,
    BLOCK_SIZE,
)


class MockFPGAUart:
    """Simulates the FPGA UART Encryptor in software."""

    def __init__(self, send_banner=True):
        self.in_buf = bytearray()
        self.out_buf = bytearray()
        self.is_open = True
        if send_banner:
            banner = (
                b"AES-UART ready (8-N-1).\r\n"
                b"Send 16 raw key bytes, then 16 raw plaintext bytes.\r\n"
            )
            self.out_buf.extend(banner)

    @property
    def in_waiting(self):
        return len(self.out_buf)

    def reset_input_buffer(self):
        self.out_buf.clear()

    def reset_output_buffer(self):
        self.in_buf.clear()

    def write(self, data: bytes):
        self.in_buf.extend(data)
        # Every 32 bytes (16-byte key + 16-byte plaintext), process AES encryption
        while len(self.in_buf) >= 32:
            key = bytes(self.in_buf[:16])
            plain = bytes(self.in_buf[16:32])
            del self.in_buf[:32]

            # Hardware AES encrypts block
            cipher = software_aes_ecb_encrypt(key, plain)
            self.out_buf.extend(cipher)

    def read(self, size: int = 1) -> bytes:
        size = min(size, len(self.out_buf))
        res = bytes(self.out_buf[:size])
        del self.out_buf[:size]
        return res

    def flush(self):
        pass

    def close(self):
        self.is_open = False


class TestAesUartStream(unittest.TestCase):

    def test_key_parsing(self):
        # 32 hex chars
        k1 = parse_key("2b7e151628aed2a6abf7158809cf4f3c")
        self.assertEqual(k1, bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))

        # 32 hex chars with spaces and 0x
        k2 = parse_key("0x2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c")
        self.assertEqual(k2, bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))

        # 16-char ASCII string
        k3 = parse_key("SixteenByteKey12")
        self.assertEqual(k3, b"SixteenByteKey12")

        # Invalid length
        with self.assertRaises(ValueError):
            parse_key("TooShortKey")

    def test_pkcs7_padding(self):
        # Length 0 -> 16 bytes of 0x10
        self.assertEqual(pkcs7_pad(b""), b"\x10" * 16)
        self.assertEqual(pkcs7_unpad(pkcs7_pad(b"")), b"")

        # Length 1 -> 15 bytes of 0x0f
        data1 = b"A"
        padded1 = pkcs7_pad(data1)
        self.assertEqual(len(padded1), 16)
        self.assertEqual(pkcs7_unpad(padded1), data1)

        # Length 16 -> 16 bytes of 0x10 added (total 32)
        data16 = b"1234567890abcdef"
        padded16 = pkcs7_pad(data16)
        self.assertEqual(len(padded16), 32)
        self.assertEqual(pkcs7_unpad(padded16), data16)

        # Arbitrary length 47 bytes
        data47 = os.urandom(47)
        self.assertEqual(pkcs7_unpad(pkcs7_pad(data47)), data47)

    def test_mock_fpga_single_block_nist(self):
        # NIST Test Vector 1
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plain = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected_cipher = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

        mock_ser = MockFPGAUart(send_banner=True)
        encryptor = AESUartEncryptor(port="MOCK", ser_instance=mock_ser)
        encryptor.sync_startup()

        cipher_out = encryptor.encrypt_block(key, plain)
        self.assertEqual(cipher_out, expected_cipher)

    def test_file_streaming_multi_block(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        # Create a temporary file with non-block-aligned random data (e.g. 1025 bytes = 65 blocks)
        test_data = os.urandom(1025)

        with tempfile.TemporaryDirectory() as tmpdir:
            in_file = os.path.join(tmpdir, "input.bin")
            out_file = os.path.join(tmpdir, "output.enc")
            dec_file = os.path.join(tmpdir, "decrypted.bin")

            with open(in_file, "wb") as f:
                f.write(test_data)

            mock_ser = MockFPGAUart(send_banner=True)
            encryptor = AESUartEncryptor(port="MOCK", ser_instance=mock_ser)
            encryptor.sync_startup()

            stats = encryptor.encrypt_file(
                input_file=in_file,
                output_file=out_file,
                key=key,
                pad=True,
                verify=True
            )

            self.assertEqual(stats["original_size"], 1025)
            self.assertEqual(stats["total_blocks"], 65)  # ceil(1026/16) with PKCS#7 = 65 blocks = 1040 bytes
            self.assertEqual(stats["encrypted_size"], 1040)
            self.assertTrue(stats["verified"])

            # Verify roundtrip decryption
            with open(out_file, "rb") as f:
                encrypted_bytes = f.read()

            decrypted_padded = software_aes_ecb_decrypt(key, encrypted_bytes)
            decrypted_data = pkcs7_unpad(decrypted_padded)

            self.assertEqual(decrypted_data, test_data)


if __name__ == "__main__":
    unittest.main()
