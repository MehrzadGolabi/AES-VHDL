"""
Builds and cross-checks the test vectors used by the GHDL testbenches.

Verification chain:
    FIPS 197 (upd1) PDF  ---\
                             >---  aes_ref.py (model from spec definitions)  ---> vectors/*.txt ---> RTL testbenches
    AES_Core128.pdf      ---/            |
                              python `cryptography` (OpenSSL) for random vectors

1. The reference model is checked against every intermediate value printed in
   both PDFs (S-box / inverse S-box tables, Appendix A.1 key expansion,
   Appendix B round-by-round states, and all 4 ECB-AES128 blocks of
   AES_Core128.pdf for both encryption and decryption).  Needs `pdftotext`
   (poppler).  If it is missing, the PDF scan is skipped but the hard-coded
   known answers below are still enforced.
2. The model is checked against OpenSSL (via `cryptography`) on random data.
3. Vector files are written to tests/vectors/.

All hex values in the vector files use FIPS byte order (in0 first / MSB);
the testbenches convert to the core's internal byte order themselves.
"""

from __future__ import annotations

import argparse
import os
import random
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import aes_ref as A  # noqa: E402

H = bytes.fromhex

# ---------------------------------------------------------------------------
# Known-answer vectors transcribed from the two PDFs
# ---------------------------------------------------------------------------
FIPS_B_KEY = H("2b7e151628aed2a6abf7158809cf4f3c")
FIPS_B_PT = H("3243f6a8885a308d313198a2e0370734")
FIPS_B_CT = H("3925841d02dc09fbdc118597196a0b32")
FIPS_A1_W40_43 = ["d014f9a8", "c9ee2589", "e13f0cc8", "b6630ca6"]

CORE128_KEY = H("2B7E151628AED2A6ABF7158809CF4F3C")
CORE128_BLOCKS = [  # (plaintext, ciphertext) ECB-AES128
    (H("6BC1BEE22E409F96E93D7E117393172A"), H("3AD77BB40D7A3660A89ECAF32466EF97")),
    (H("AE2D8A571E03AC9C9EB76FAC45AF8E51"), H("F5D3D58503B9699DE785895A96FDBAAF")),
    (H("30C81C46A35CE411E5FBC1191A0A52EF"), H("43B1CD7F598ECE23881B00E3ED030688")),
    (H("F69F2445DF4F9B17AD2B417BE66C3710"), H("7B0C785E27E8AD3F8223207104725DD4")),
]


class Fail(Exception):
    pass


def check(cond: bool, msg: str):
    if not cond:
        raise Fail(msg)


# ---------------------------------------------------------------------------
# PDF scanning
# ---------------------------------------------------------------------------

def pdf_text(path: str) -> str | None:
    exe = shutil.which("pdftotext")
    if exe is None or not os.path.exists(path):
        return None
    out = subprocess.run([exe, "-layout", path, "-"], capture_output=True)
    return out.stdout.decode("latin-1")


def hex_tokens(text: str) -> str:
    """Whitespace-normalised, lower-case token stream with a leading/trailing space."""
    return " " + " ".join(text.lower().split()) + " "


def words(b: bytes) -> str:
    """'aabbccdd eeff0011 ...' : 4 big-endian 32-bit words, as in AES_Core128.pdf."""
    h = b.hex()
    return " ".join(h[i:i + 8] for i in range(0, 32, 8))


def matrix_rows(b: bytes) -> list[str]:
    """Row r of the 4x4 state, as printed in FIPS 197 App. B ('19 a0 9a e9')."""
    return [" ".join(f"{b[r + 4 * c]:02x}" for c in range(4)) for r in range(4)]


def verify_fips_pdf(text: str) -> int:
    t = hex_tokens(text)
    n = 0
    # --- Table 4 (SBOX) and Table 6 (INVSBOX): each row "x  b0 b1 ... b15"
    sbox_rows = [f" {x:x} " + " ".join(f"{A.SBOX[16 * x + y]:02x}" for y in range(16)) + " "
                 for x in range(16)]
    inv_rows = [f" {x:x} " + " ".join(f"{A.INV_SBOX[16 * x + y]:02x}" for y in range(16)) + " "
                for x in range(16)]
    for row in sbox_rows + inv_rows:
        # row 7 has the axis label 'x' in front; plain substring search copes
        check(row in t, f"FIPS S-box/inverse S-box row not found in PDF: {row.strip()}")
        n += 1
    # --- Appendix A.1 key expansion: every w[i]
    w = A.key_expansion(FIPS_B_KEY)
    for i, wi in enumerate(w):
        check(f" {wi.hex()} " in t, f"FIPS A.1 w[{i}] = {wi.hex()} not found in PDF")
        n += 1
    # --- Appendix B: rows of start / after SubBytes / after ShiftRows / after MixColumns / round key
    tr = A.encrypt_trace(FIPS_B_KEY, FIPS_B_PT)
    for rnd in range(1, 10):
        cols = [tr["start"][rnd - 1], tr["sb"][rnd - 1], tr["sr"][rnd - 1],
                tr["mc"][rnd - 1], tr["rk"][rnd]]
        for r in range(4):
            line = " " + " ".join(matrix_rows(c)[r] for c in cols) + " "
            check(line in t, f"FIPS App.B round {rnd} row {r} not found in PDF: {line.strip()}")
            n += 1
    for r in range(4):  # round 10 (layout has the round key printed separately)
        line = " " + " ".join(matrix_rows(c)[r] for c in
                              (tr["start"][9], tr["sb"][9], tr["sr"][9])) + " "
        check(line in t, f"FIPS App.B round 10 row {r} not found: {line.strip()}")
        check(" " + matrix_rows(tr["rk"][10])[r] + " " in t, "FIPS App.B round-10 key row missing")
        check(" " + matrix_rows(tr["ct"])[r] + " " in t, "FIPS App.B output row missing")
        n += 3
    return n


def verify_core128_pdf(text: str) -> int:
    t = hex_tokens(text)
    n = 0
    for pt, ct in CORE128_BLOCKS:
        e = A.encrypt_trace(CORE128_KEY, pt)
        vals = [A.add_round_key(pt, e["rk"][0])] + e["start"][1:] + e["sb"] + e["sr"] + e["mc"] + [e["ct"]]
        for v in vals:
            check(f" {words(v)} " in t, f"Core128 encrypt intermediate {words(v)} not found in PDF")
            n += 1
        d = A.decrypt_trace(CORE128_KEY, ct)
        vals = d["ark"] + d["isr"] + d["isb"] + d["imc"]
        for v in vals:
            check(f" {words(v)} " in t, f"Core128 decrypt intermediate {words(v)} not found in PDF")
            n += 1
        # plaintext / ciphertext words (block listing is column-interleaved in the
        # PDF text layer, so only check each 32-bit word individually)
        for blk in (pt, ct):
            for wd in words(blk).split():
                check(f" {wd} " in t, f"Core128 block word {wd} not found in PDF")
                n += 1
    return n


# ---------------------------------------------------------------------------
# Model self-checks
# ---------------------------------------------------------------------------

def verify_model(n_random: int, rng: random.Random) -> None:
    # Hard-coded known answers (always enforced, even without pdftotext)
    check(A.SBOX[0x53] == 0xED, "SBOX(53) != ED (FIPS 197 Sec 5.1.1 example)")
    check(A.encrypt(FIPS_B_KEY, FIPS_B_PT) == FIPS_B_CT, "FIPS App.B ciphertext mismatch")
    check(A.decrypt(FIPS_B_KEY, FIPS_B_CT) == FIPS_B_PT, "FIPS App.B inverse mismatch")
    check([w.hex() for w in A.key_expansion(FIPS_B_KEY)[40:]] == FIPS_A1_W40_43, "FIPS A.1 w40..43")
    for pt, ct in CORE128_BLOCKS:
        check(A.encrypt(CORE128_KEY, pt) == ct, f"Core128 encrypt {pt.hex()}")
        check(A.decrypt(CORE128_KEY, ct) == pt, f"Core128 decrypt {ct.hex()}")
    # Round helpers are inverses of each other
    for _ in range(64):
        s = rng.randbytes(16)
        check(A.inv_shift_rows(A.shift_rows(s)) == s, "ShiftRows inverse")
        check(A.inv_mix_columns(A.mix_columns(s)) == s, "MixColumns inverse")
    # OpenSSL cross-check
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        print("  [warn] python 'cryptography' not installed - OpenSSL cross-check skipped")
        return
    for _ in range(n_random):
        k, p = rng.randbytes(16), rng.randbytes(16)
        enc = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
        c = enc.update(p) + enc.finalize()
        check(A.encrypt(k, p) == c, f"model != OpenSSL for k={k.hex()} p={p.hex()}")
        check(A.decrypt(k, c) == p, f"model inverse != OpenSSL for k={k.hex()}")


# ---------------------------------------------------------------------------
# Vector files
# ---------------------------------------------------------------------------

def vector_sets(n_random: int, rng: random.Random):
    """(name, key, pt) tuples: spec KATs first, then corner cases, then random."""
    sets = [("FIPS197_AppB", FIPS_B_KEY, FIPS_B_PT)]
    for i, (pt, _) in enumerate(CORE128_BLOCKS):
        sets.append((f"Core128_ECB_blk{i + 1}", CORE128_KEY, pt))
    sets.append(("zero_key_zero_pt", bytes(16), bytes(16)))
    sets.append(("ones_key_ones_pt", b"\xff" * 16, b"\xff" * 16))
    sets.append(("fips_C1_style", bytes(range(16)), H("00112233445566778899aabbccddeeff")))
    for i in range(n_random):
        sets.append((f"random_{i}", rng.randbytes(16), rng.randbytes(16)))
    return sets


def write_vectors(outdir: str, n_random: int, rng: random.Random) -> dict:
    os.makedirs(outdir, exist_ok=True)
    counts = {}
    # S-box: "x sbox(x) invsbox(x)"
    with open(os.path.join(outdir, "sbox.txt"), "w", newline="\n") as f:
        for x in range(256):
            f.write(f"{x:02x} {A.SBOX[x]:02x} {A.INV_SBOX[x]:02x}\n")
    counts["sbox"] = 256
    # Round primitives: "in shift_rows mix_columns inv_shift_rows inv_mix_columns xtimes-bytes"
    with open(os.path.join(outdir, "round_funcs.txt"), "w", newline="\n") as f:
        states = [bytes(16), b"\xff" * 16, FIPS_B_PT] + [rng.randbytes(16) for _ in range(500)]
        for s in states:
            f.write(" ".join(x.hex() for x in (s, A.shift_rows(s), A.mix_columns(s),
                                                A.inv_shift_rows(s), A.inv_mix_columns(s))) + "\n")
    counts["round_funcs"] = len(states)
    # Encryption: name key pt ct  st0..st10  rk0..rk10
    #   st0 = pt ^ rk0 (start of round 1), st[r] = start of round r+1, st10 = ct
    sets = vector_sets(n_random, rng)
    with open(os.path.join(outdir, "enc.txt"), "w", newline="\n") as f:
        for name, k, p in sets:
            tr = A.encrypt_trace(k, p)
            st = [A.add_round_key(p, tr["rk"][0])] + tr["start"][1:] + [tr["ct"]]
            assert st[0] == tr["start"][0]
            f.write(" ".join([name, k.hex(), p.hex(), tr["ct"].hex()]
                             + [s.hex() for s in st] + [r.hex() for r in tr["rk"]]) + "\n")
    counts["enc"] = len(sets)
    # Decryption: name key rk10 ct pt  ark0..ark10  rk10..rk0
    with open(os.path.join(outdir, "dec.txt"), "w", newline="\n") as f:
        for name, k, p in sets:
            c = A.encrypt(k, p)
            tr = A.decrypt_trace(k, c)
            assert tr["pt"] == p
            f.write(" ".join([name, k.hex(), tr["rk"][10].hex(), c.hex(), p.hex()]
                             + [s.hex() for s in tr["ark"]]
                             + [r.hex() for r in reversed(tr["rk"])]) + "\n")
    counts["dec"] = len(sets)
    return counts


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--random", type=int, default=200, help="random enc/dec vectors for the RTL (default 200)")
    ap.add_argument("--seed", type=int, default=197)
    ap.add_argument("--out", default=os.path.join(HERE, "vectors"))
    ap.add_argument("--require-pdf", action="store_true", help="fail if the PDFs cannot be scanned")
    args = ap.parse_args(argv)
    rng = random.Random(args.seed)

    try:
        print("[1/3] Reference model vs. hard-coded KATs and OpenSSL ...")
        verify_model(2000, rng)
        print("      OK")

        print("[2/3] Reference model vs. PDF intermediate values ...")
        fips = pdf_text(os.path.join(ROOT, "NIST.FIPS.197-upd1.pdf"))
        core = pdf_text(os.path.join(ROOT, "AES_Core128.pdf"))
        if fips is None or core is None:
            msg = "pdftotext or PDFs not available - PDF scan skipped"
            if args.require_pdf:
                raise Fail(msg)
            print(f"      [warn] {msg}")
        else:
            n1 = verify_fips_pdf(fips)
            n2 = verify_core128_pdf(core)
            print(f"      OK  ({n1} values matched in FIPS 197, {n2} values matched in AES_Core128)")

        print("[3/3] Writing vector files ...")
        counts = write_vectors(args.out, args.random, rng)
        print("      " + ", ".join(f"{k}: {v}" for k, v in counts.items()) + f"  -> {args.out}")
    except Fail as e:
        print(f"FAIL: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
