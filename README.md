
# AES-VHDL + UART

This project is a fork of [AES-VHDL](https://github.com/hadipourh/AES-VHDL) by [hadipourh](https://github.com/hadipourh). The original implementation uses 387 I/O blocks (IOBs) to transmit and receive plaintext, keys, and ciphertext — a configuration that exceeds the I/O capacity of my [Posedge-1 Spartan-6 development board](https://github.com/mhaghighi/posedge_one).

To overcome this limitation, we developed a UART module to send and receive the data over a serial connection, significantly reducing the number of I/Os required and making the design compatible with the Posedge-1 board.

### UART protocol (both top levels)

8-N-1, 115200 baud by default (`divisor` generic = clock / baud; 208 for the board's 24 MHz oscillator). Data is sent as **raw bytes**, not as hex text:

| Top level | Host sends | FPGA replies |
|---|---|---|
| `TOP-LEVEL_MODULE-ENC` | 16 key bytes, then 16 plaintext bytes | 16 ciphertext bytes |
| `TOP-LEVEL_MODULE-DEC` | 16 key bytes, then 16 ciphertext bytes | 16 plaintext bytes |

Bytes go in FIPS 197 order (byte 0 first). For example, the key `2b7e151628aed2a6abf7158809cf4f3c` is sent as `0x2b, 0x7e, …, 0x3c`. Both top levels take the normal **cipher key**. After power-up each prints a short text banner, which the host should discard.

### Cores

| Core | Interface | Latency |
|---|---|---|
| `aes_enc` | hold `key` / `plaintext`, pull `rst` low for one clock (load) | `done` 10 cycles after the load cycle |
| `aes_dec` | hold `key` (cipher key) / `ciphertext`, pull `rst` low for one clock (load) | 10 cycles key expansion + 10 rounds; `done` 20 cycles after the load cycle, `plaintext` then held until the next load |

`aes_dec` expands the cipher key forwards to the last round key on chip, then runs the key schedule backwards while decrypting. (The upstream core expected the caller to supply round key 10.)

## Python UART File Streaming Script

A Python tool (`aes_uart_stream.py`) is provided to stream files over serial to the FPGA encryptor and save the resulting ciphertext.

### Requirements

```bash
pip install pyserial cryptography
```

### Usage Examples

1. **List available COM ports:**
   ```bash
   python aes_uart_stream.py --list-ports
   ```

2. **Stream and encrypt a file:**
   ```bash
   python aes_uart_stream.py -p COM3 -b 115200 -k 2b7e151628aed2a6abf7158809cf4f3c -i my_document.pdf -o my_document.enc --verify
   ```

3. **Encrypt and verify roundtrip decryption:**
   ```bash
   python aes_uart_stream.py -p COM3 -k 2b7e151628aed2a6abf7158809cf4f3c -i test.txt -o test.enc --verify --decrypt-sw
   ```

### GHDL Verification

To simulate and verify all modules using GHDL:

```powershell
# 1. AES Encryptor Core RTL
ghdl -i --std=08 AES-ENC/RTL/*.vhd AES-ENC/Testbench/enc_tb.vhd
ghdl -m --std=08 test_enc
ghdl -r --std=08 test_enc --stop-time=400ns

# 2. AES Decryptor Core RTL
ghdl -i --std=08 AES-DEC/RTL/*.vhd AES-DEC/Testbench/dec_tb.vhd
ghdl -m --std=08 test_dec
ghdl -r --std=08 test_dec --stop-time=800ns

# 3. Top-Level Encryptor with UART (Multi-block verification)
ghdl -i --std=08 UART/*.vhd AES-ENC/RTL/*.vhd TOP-LEVEL_MODULE-ENC/top_level.vhd TOP-LEVEL_MODULE-ENC/top_level_tb.vhd
ghdl -m --std=08 top_level_tb
ghdl -r --std=08 top_level_tb --stop-time=2ms

# 4. Top-Level Decryptor with UART
ghdl -i --std=08 UART/*.vhd AES-DEC/RTL/*.vhd TOP-LEVEL_MODULE-DEC/top_level.vhd TOP-LEVEL_MODULE-DEC/top_level_dec_tb.vhd
ghdl -m --std=08 top_level_dec_tb
ghdl -r --std=08 top_level_dec_tb --stop-time=2ms
```

### Specification test suite (`tests/`)

`tests/` verifies both cores against **FIPS 197 (upd1)** and **NIST AES_Core128.pdf**:

```bash
python tests/run_tests.py          # all tests (needs ghdl; pdftotext optional)
python tests/run_tests.py --list   # enc_primitives dec_primitives aes_enc aes_dec top_enc_uart top_dec_uart
```

* `tests/aes_ref.py` is an AES-128 model written from the FIPS 197 definitions (GF(2^8) arithmetic, S-box built from the field inverse and affine map).
* `tests/gen_vectors.py` checks that model against every intermediate value printed in both PDFs (S-box and inverse S-box tables, App. A.1 key expansion, App. B round states, all 4 Core128 ECB blocks for encryption and decryption) and against OpenSSL. It then writes `tests/vectors/`.
* The GHDL testbenches in `tests/tb/` check every S-box entry and each round function. They also check the state, the round key and `done` of both cores on **every clock cycle**, over 208 vectors (the spec examples, corner cases and random data), including a reset in the middle of a block.

## Authors

- [@MehrzadGolabi](https://github.com/MehrzadGolabi)
- [@Mohammad-HTZ](https://github.com/Mohammad-HTZ)


## Demo
-


## Roadmap

- 


