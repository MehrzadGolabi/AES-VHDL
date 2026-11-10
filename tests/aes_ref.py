"""
Pure-Python AES-128 reference model written directly from FIPS 197 (upd1).

Everything here is derived from the *definitions* in the standard rather than
copied tables:
  * SBOX()      - Sec. 5.1.1: multiplicative inverse in GF(2^8) + affine map
  * XTIMES()    - Sec. 4.2   : multiply by {02} modulo m(x) = x^8+x^4+x^3+x+1
  * MIXCOLUMNS  - Sec. 5.1.3 (eq. 5.6), INVMIXCOLUMNS Sec. 5.3.3 (eq. 5.10)
  * KEYEXPANSION- Sec. 5.2, Algorithm 2
  * CIPHER      - Sec. 5.1, Algorithm 1
  * INVCIPHER   - Sec. 5.3, Algorithm 3

The model records every intermediate state so testbenches can check the RTL
cycle-by-cycle, and so the values can be cross-checked against the
intermediate values printed in FIPS 197 Appendix B and NIST AES_Core128.pdf.

State convention: a 16-byte `bytes` object in FIPS input order
(in0 .. in15, column-major: s[r,c] = in[r + 4c]).
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# GF(2^8) arithmetic
# --------------------------------------------------------------------------

def xtimes(b: int) -> int:
    b <<= 1
    if b & 0x100:
        b ^= 0x11B
    return b & 0xFF


def gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = xtimes(a)
        b >>= 1
    return r


def ginv(b: int) -> int:
    if b == 0:
        return 0
    # b^254 = b^-1 in GF(2^8)
    r, e, x = 1, 254, b
    while e:
        if e & 1:
            r = gmul(r, x)
        x = gmul(x, x)
        e >>= 1
    return r


def _affine(b: int) -> int:
    c = 0x63
    out = 0
    for i in range(8):
        bit = ((b >> i) ^ (b >> ((i + 4) % 8)) ^ (b >> ((i + 5) % 8))
               ^ (b >> ((i + 6) % 8)) ^ (b >> ((i + 7) % 8)) ^ (c >> i)) & 1
        out |= bit << i
    return out


SBOX = [_affine(ginv(x)) for x in range(256)]
INV_SBOX = [0] * 256
for _x, _y in enumerate(SBOX):
    INV_SBOX[_y] = _x

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# --------------------------------------------------------------------------
# Round transformations (state = bytes, FIPS order)
# --------------------------------------------------------------------------

def sub_bytes(s: bytes) -> bytes:
    return bytes(SBOX[b] for b in s)


def inv_sub_bytes(s: bytes) -> bytes:
    return bytes(INV_SBOX[b] for b in s)


def shift_rows(s: bytes) -> bytes:
    # s'[r,c] = s[r, (c + r) mod 4]
    return bytes(s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4))


def inv_shift_rows(s: bytes) -> bytes:
    # s'[r, (c + r) mod 4] = s[r, c]
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * ((c + r) % 4)] = s[r + 4 * c]
    return bytes(out)


def _mix(s: bytes, m) -> bytes:
    out = []
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            v = 0
            for k in range(4):
                v ^= gmul(m[r][k], col[k])
            out.append(v)
    return bytes(out)


MC = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
IMC = [[0x0E, 0x0B, 0x0D, 0x09], [0x09, 0x0E, 0x0B, 0x0D],
       [0x0D, 0x09, 0x0E, 0x0B], [0x0B, 0x0D, 0x09, 0x0E]]


def mix_columns(s: bytes) -> bytes:
    return _mix(s, MC)


def inv_mix_columns(s: bytes) -> bytes:
    return _mix(s, IMC)


def add_round_key(s: bytes, k: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(s, k))

# --------------------------------------------------------------------------
# Key expansion
# --------------------------------------------------------------------------

def key_expansion(key: bytes) -> list[bytes]:
    """Returns the 44 words w[0..43] (4 bytes each)."""
    assert len(key) == 16
    w = [key[4 * i:4 * i + 4] for i in range(4)]
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]                      # ROTWORD
            temp = bytes(SBOX[b] for b in temp)             # SUBWORD
            temp = bytes([temp[0] ^ RCON[i // 4]]) + temp[1:]
        w.append(bytes(a ^ b for a, b in zip(w[i - 4], temp)))
    return w


def round_keys(key: bytes) -> list[bytes]:
    w = key_expansion(key)
    return [b"".join(w[4 * r:4 * r + 4]) for r in range(11)]

# --------------------------------------------------------------------------
# Cipher / InvCipher with full trace
# --------------------------------------------------------------------------

def encrypt_trace(key: bytes, pt: bytes) -> dict:
    rk = round_keys(key)
    tr = {"rk": rk, "start": [], "sb": [], "sr": [], "mc": []}
    s = add_round_key(pt, rk[0])
    for rnd in range(1, 11):
        tr["start"].append(s)              # start of round rnd
        s = sub_bytes(s);   tr["sb"].append(s)
        s = shift_rows(s);  tr["sr"].append(s)
        if rnd != 10:
            s = mix_columns(s); tr["mc"].append(s)
        s = add_round_key(s, rk[rnd])
    tr["ct"] = s
    return tr


def decrypt_trace(key: bytes, ct: bytes) -> dict:
    """FIPS 197 Algorithm 3 (INVCIPHER) with trace.

    ark[i] = state right after the AddRoundKey with round key rk[10-i]
    (ark[0] = ct ^ rk10, ..., ark[10] = plaintext).
    """
    rk = round_keys(key)
    tr = {"rk": rk, "ark": [], "isr": [], "isb": [], "imc": []}
    s = add_round_key(ct, rk[10])
    tr["ark"].append(s)
    for rnd in range(9, -1, -1):
        s = inv_shift_rows(s); tr["isr"].append(s)
        s = inv_sub_bytes(s);  tr["isb"].append(s)
        s = add_round_key(s, rk[rnd]); tr["ark"].append(s)
        if rnd != 0:
            s = inv_mix_columns(s); tr["imc"].append(s)
    tr["pt"] = s
    return tr


def encrypt(key: bytes, pt: bytes) -> bytes:
    return encrypt_trace(key, pt)["ct"]


def decrypt(key: bytes, ct: bytes) -> bytes:
    return decrypt_trace(key, ct)["pt"]
