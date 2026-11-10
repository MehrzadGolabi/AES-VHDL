#!/usr/bin/env python3
"""
AES-128 UART File Streaming & Encryption Tool
Pairs with the FPGA AES-128 UART Top-Level Encryptor.

Protocol:
  1. Optional startup: FPGA sends boot banner on power-on.
  2. For each 16-byte block:
     - Host sends: 16 bytes AES Key
     - Host sends: 16 bytes Plaintext
     - FPGA responds: 16 bytes Ciphertext
"""

import os
import sys
import time
import argparse
from typing import Optional, Callable

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("Error: pyserial is required. Install via: pip install pyserial", file=sys.stderr)
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


BLOCK_SIZE = 16  # AES block size in bytes (128 bits)


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Apply PKCS#7 padding to data."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Remove PKCS#7 padding from data."""
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding byte.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding sequence.")
    return data[:-pad_len]


def software_aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Software reference AES-128-ECB encryption for verification."""
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography library not installed.")
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def software_aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Software reference AES-128-ECB decryption."""
    if not HAS_CRYPTOGRAPHY:
        raise RuntimeError("cryptography library not installed.")
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def parse_key(key_str: str) -> bytes:
    """
    Parse a key argument from hex string (32 hex characters)
    or a 16-character ASCII string.
    """
    cleaned = key_str.strip().replace(" ", "").replace("0x", "")
    if len(cleaned) == 32:
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            pass
    raw = key_str.encode('utf-8')
    if len(raw) == 16:
        return raw
    raise ValueError(
        f"Key must be exactly 16 bytes (or 32 hex characters). Provided length: {len(key_str)}"
    )


class AESUartEncryptor:
    """Client for streaming data through the FPGA UART AES encryptor."""

    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 2.0, ser_instance=None):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        if ser_instance is not None:
            self.ser = ser_instance
        else:
            self.ser = serial.Serial(
                port=port,
                baudrate=baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=timeout
            )

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def sync_startup(self, drain_timeout: float = 0.5):
        """
        Drain any power-up banner data from the receive buffer.
        """
        time.sleep(0.1)
        # Flush serial buffers
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        # Read any remaining bytes until silent
        start_time = time.time()
        while time.time() - start_time < drain_timeout:
            if self.ser.in_waiting > 0:
                self.ser.read(self.ser.in_waiting)
                start_time = time.time()
            time.sleep(0.02)

    def encrypt_block(self, key: bytes, plaintext_block: bytes) -> bytes:
        """
        Encrypt a single 16-byte block using the FPGA encryptor.
        Transmits: key (16 bytes) then plaintext (16 bytes)
        Receives: ciphertext (16 bytes)
        """
        if len(key) != BLOCK_SIZE:
            raise ValueError(f"Key must be {BLOCK_SIZE} bytes.")
        if len(plaintext_block) != BLOCK_SIZE:
            raise ValueError(f"Plaintext block must be {BLOCK_SIZE} bytes.")

        # Send Key + Plaintext (32 bytes total)
        payload = key + plaintext_block
        self.ser.write(payload)
        self.ser.flush()

        # Read 16 bytes of ciphertext
        ciphertext = self.ser.read(BLOCK_SIZE)
        if len(ciphertext) != BLOCK_SIZE:
            raise TimeoutError(
                f"UART timeout: expected {BLOCK_SIZE} bytes ciphertext, received {len(ciphertext)} bytes."
            )
        return ciphertext

    def encrypt_file(
        self,
        input_file: str,
        output_file: str,
        key: bytes,
        pad: bool = True,
        verify: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> dict:
        """
        Stream a file through the FPGA UART encryptor.
        
        Args:
            input_file: Path to plaintext file to encrypt.
            output_file: Path where ciphertext will be saved.
            key: 16-byte AES key.
            pad: Whether to apply PKCS#7 padding.
            verify: If True, verify each block against software AES-128-ECB.
            progress_callback: Optional fn(blocks_done, total_blocks).
        """
        if not os.path.isfile(input_file):
            raise FileNotFoundError(f"Input file not found: {input_file}")

        file_size = os.path.getsize(input_file)
        with open(input_file, "rb") as f_in:
            data = f_in.read()

        if pad:
            data = pkcs7_pad(data, BLOCK_SIZE)
        else:
            if len(data) % BLOCK_SIZE != 0:
                raise ValueError(
                    f"File size ({len(data)} bytes) is not a multiple of 16 and padding is disabled."
                )

        total_blocks = len(data) // BLOCK_SIZE
        ciphertext_blocks = []

        start_time = time.time()
        for i in range(total_blocks):
            block = data[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]
            c_block = self.encrypt_block(key, block)

            if verify:
                expected_c = software_aes_ecb_encrypt(key, block)
                if c_block != expected_c:
                    raise ValueError(
                        f"Block {i} mismatch!\n"
                        f"  Plaintext:  {block.hex()}\n"
                        f"  FPGA Cipher: {c_block.hex()}\n"
                        f"  Expected:    {expected_c.hex()}"
                    )

            ciphertext_blocks.append(c_block)
            if progress_callback:
                progress_callback(i + 1, total_blocks)

        elapsed = time.time() - start_time
        encrypted_data = b"".join(ciphertext_blocks)

        with open(output_file, "wb") as f_out:
            f_out.write(encrypted_data)

        return {
            "input_file": input_file,
            "output_file": output_file,
            "original_size": file_size,
            "encrypted_size": len(encrypted_data),
            "total_blocks": total_blocks,
            "elapsed_seconds": elapsed,
            "speed_bytes_sec": len(encrypted_data) / elapsed if elapsed > 0 else 0.0,
            "verified": verify
        }


def format_progress(done: int, total: int):
    pct = (done / total) * 100 if total > 0 else 100
    bar_len = 30
    filled = int(bar_len * done // total) if total > 0 else bar_len
    bar = "=" * filled + "-" * (bar_len - filled)
    print(f"\rProgress: [{bar}] {done}/{total} blocks ({pct:.1f}%)", end="", flush=True)


def list_ports():
    ports = serial.tools.list_ports.comports()
    if not ports:
        print("No serial ports detected.")
        return
    print("Available serial ports:")
    for p in ports:
        print(f"  {p.device:15} - {p.description}")


def main():
    parser = argparse.ArgumentParser(
        description="Stream and encrypt files via FPGA AES-128 UART Encryptor."
    )
    parser.add_argument("-p", "--port", type=str, help="Serial port (e.g. COM3, /dev/ttyUSB0)")
    parser.add_argument("-b", "--baud", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("-k", "--key", type=str, help="128-bit key as 32 hex chars or 16-char ASCII string")
    parser.add_argument("-i", "--input", type=str, help="Input file path to encrypt")
    parser.add_argument("-o", "--output", type=str, help="Output file path for ciphertext")
    parser.add_argument("--no-pad", action="store_true", help="Disable PKCS#7 padding (input must be multiple of 16)")
    parser.add_argument("--verify", action="store_true", help="Verify FPGA output with local software AES-128")
    parser.add_argument("--decrypt-sw", action="store_true", help="Decrypt output file using local software AES (to test roundtrip)")
    parser.add_argument("--decrypted-output", type=str, help="Path to write decrypted plaintext (with --decrypt-sw)")
    parser.add_argument("--timeout", type=float, default=3.0, help="UART response timeout in seconds (default: 3.0)")
    parser.add_argument("--list-ports", action="store_true", help="List available serial ports and exit")

    args = parser.parse_args()

    if args.list_ports:
        list_ports()
        sys.exit(0)

    if not args.port or not args.key or not args.input or not args.output:
        parser.print_help()
        sys.exit(1)

    try:
        key_bytes = parse_key(args.key)
    except ValueError as e:
        print(f"Key error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Connecting to {args.port} at {args.baud} baud...")
    try:
        with AESUartEncryptor(port=args.port, baudrate=args.baud, timeout=args.timeout) as encryptor:
            print("Synchronizing with FPGA encryptor...")
            encryptor.sync_startup()

            print(f"Encrypting '{args.input}' -> '{args.output}'...")
            print(f"Key (hex): {key_bytes.hex()}")

            stats = encryptor.encrypt_file(
                input_file=args.input,
                output_file=args.output,
                key=key_bytes,
                pad=not args.no_pad,
                verify=args.verify,
                progress_callback=format_progress
            )
            print()
            print("Encryption complete!")
            print(f"  Input size:     {stats['original_size']} bytes")
            print(f"  Encrypted size: {stats['encrypted_size']} bytes ({stats['total_blocks']} blocks)")
            print(f"  Time taken:     {stats['elapsed_seconds']:.2f} s ({stats['speed_bytes_sec']:.1f} bytes/s)")
            if stats['verified']:
                print("  Verification:   PASS (all blocks verified against NIST AES-128)")

            if args.decrypt_sw:
                dec_out = args.decrypted_output or (args.output + ".dec")
                print(f"Performing software roundtrip decryption to '{dec_out}'...")
                with open(args.output, "rb") as f_ciph:
                    ciph_data = f_ciph.read()
                plain_data = software_aes_ecb_decrypt(key_bytes, ciph_data)
                if not args.no_pad:
                    plain_data = pkcs7_unpad(plain_data, BLOCK_SIZE)
                with open(dec_out, "wb") as f_dec:
                    f_dec.write(plain_data)
                with open(args.input, "rb") as f_orig:
                    orig_data = f_orig.read()
                if plain_data == orig_data:
                    print(f"  Roundtrip verification: PASS (decrypted file matches original 100%)")
                else:
                    print(f"  Roundtrip verification: FAIL (decrypted data does not match original)")

    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
