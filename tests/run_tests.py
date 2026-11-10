"""
One-shot verification runner.

    python tests/run_tests.py            # everything
    python tests/run_tests.py aes_enc    # only selected tests
    python tests/run_tests.py --list

Steps:
  1. tests/gen_vectors.py : reference model vs FIPS 197 / AES_Core128 PDFs and
     OpenSSL, then writes tests/vectors/*.txt
  2. Every GHDL testbench below is built in its own work directory (the ENC and
     DEC trees reuse entity names, so they must live in separate libraries) and
     run with --assert-level=error.

GHDL is looked up in $GHDL, then PATH, then the WinGet install location.
"""

from __future__ import annotations

import argparse
import glob
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.join(HERE, "build")

WINGET_GHDL = os.path.expandvars(
    r"%LOCALAPPDATA%\Microsoft\WinGet\Packages"
    r"\ghdl.ghdl.ucrt64.mcode_Microsoft.Winget.Source_8wekyb3d8bbwe\bin\ghdl.exe")


def g(pattern: str) -> list[str]:
    return sorted(glob.glob(os.path.join(ROOT, pattern)))


ENC_RTL = g("AES-ENC/RTL/*.vhd")
DEC_RTL = g("AES-DEC/RTL/*.vhd")
UART = g("UART/*.vhd")
PKG = [os.path.join(HERE, "tb", "tb_util_pkg.vhd")]
TB = lambda n: [os.path.join(HERE, "tb", n)]  # noqa: E731

# name -> (sources, top, extra run args)
TESTS = {
    "enc_primitives": (ENC_RTL + PKG + TB("tb_enc_primitives.vhd"), "tb_enc_primitives", []),
    "dec_primitives": (DEC_RTL + PKG + TB("tb_dec_primitives.vhd"), "tb_dec_primitives", []),
    "aes_enc":        (ENC_RTL + PKG + TB("tb_aes_enc.vhd"), "tb_aes_enc", []),
    "aes_dec":        (DEC_RTL + PKG + TB("tb_aes_dec.vhd"), "tb_aes_dec", []),
    # pre-existing UART top-level testbenches shipped with the project
    "top_enc_uart":   (UART + ENC_RTL + g("TOP-LEVEL_MODULE-ENC/*.vhd"), "top_level_tb", ["--stop-time=5ms"]),
    "top_dec_uart":   (UART + DEC_RTL + g("TOP-LEVEL_MODULE-DEC/*.vhd"), "top_level_dec_tb", ["--stop-time=5ms"]),
}


def find_ghdl() -> str:
    for cand in (os.environ.get("GHDL"), shutil.which("ghdl"), WINGET_GHDL):
        if cand and os.path.exists(cand):
            return cand
    sys.exit("ghdl not found: set $GHDL or add it to PATH")


def run(cmd, cwd) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def run_test(ghdl: str, name: str, verbose: bool) -> bool:
    srcs, top, extra = TESTS[name]
    work = os.path.join(BUILD, name)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    common = ["--std=08", f"--workdir={work}", "-frelaxed"]
    t0 = time.time()
    for step in (["-i", *common, *srcs], ["-m", *common, top]):
        rc, out = run([ghdl, *step], HERE)
        if rc != 0:
            print(f"  FAIL {name:16s} (build)\n{out}")
            return False
    rc, out = run([ghdl, "-r", *common, top, "--assert-level=error", *extra], HERE)
    dt = time.time() - t0
    result = [ln for ln in out.splitlines() if "RESULT:" in ln or "error" in ln.lower()]
    ok = rc == 0 and "RESULT: FAIL" not in out and "(assertion error)" not in out
    if name.startswith("top_"):
        # legacy benches print their own messages; success = clean exit + final message
        ok = ok and ("PERFECTLY" in out or "MATCH" in out or "Passed" in out or "ALL" in out)
    summary = next((ln.split("RESULT:")[1].strip() for ln in out.splitlines() if "RESULT:" in ln), "")
    print(f"  {'PASS' if ok else 'FAIL'} {name:16s} {dt:6.1f}s  {summary}")
    if verbose or not ok:
        shown = out.splitlines() if verbose else result[:40]
        for ln in shown:
            print("       " + ln)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("tests", nargs="*", help="subset of tests to run")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--random", type=int, default=200, help="random vectors per core")
    ap.add_argument("--skip-gen", action="store_true", help="reuse existing tests/vectors")
    args = ap.parse_args()
    if args.list:
        print("\n".join(TESTS))
        return 0
    sel = args.tests or list(TESTS)
    for s in sel:
        if s not in TESTS:
            sys.exit(f"unknown test {s!r}; use --list")

    if not args.skip_gen:
        print("== Reference model / vector generation")
        rc = subprocess.call([sys.executable, os.path.join(HERE, "gen_vectors.py"), "--random", str(args.random)])
        if rc != 0:
            return rc

    ghdl = find_ghdl()
    print(f"== GHDL testbenches ({ghdl})")
    results = {n: run_test(ghdl, n, args.verbose) for n in sel}
    npass = sum(results.values())
    print(f"== {npass}/{len(results)} passed")
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
