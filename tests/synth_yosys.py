"""
Open-source Spartan-6 synthesis check (GHDL --synth -> Verilog -> Yosys synth_xilinx).

    python tests/synth_yosys.py                      # aes_enc and aes_dec
    python tests/synth_yosys.py --rtl-dir some/dir --top aes_dec

Reports flip-flop / LUT / MUXF7 / MUXF8 counts and the logic depth (cells on
the longest register-to-register path) for XC6SLX9.  Yosys has no Spartan-6
timing model, so the depth is the figure to compare between versions; turn it
into a clock frequency with ISE (`PERIOD` constraint) or a timing model.

GHDL's Verilog backend writes each 256-entry S-box `case` as a one-hot
priority mux that Yosys cannot recognise as a ROM, which inflates the result
about 7x.  The script therefore replaces the generated `sbox` / `inv_sbox`
modules with ROM-style Verilog built from tests/aes_ref.py; tb_*_primitives
prove that the RTL tables are identical to that model.

Tools: GHDL ($GHDL, PATH or the WinGet location) and Yosys ($YOSYS, PATH or
./oss-cad-suite-*/oss-cad-suite/bin).
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import aes_ref as A  # noqa: E402
from run_tests import find_ghdl  # noqa: E402


def find_yosys() -> tuple[str, dict]:
    env = dict(os.environ)
    cands = [os.environ.get("YOSYS"), shutil.which("yosys")]
    cands += glob.glob(os.path.join(ROOT, "oss-cad-suite*", "oss-cad-suite", "bin", "yosys.exe"))
    cands += glob.glob(os.path.join(ROOT, "oss-cad-suite*", "oss-cad-suite", "bin", "yosys"))
    for c in cands:
        if c and os.path.exists(c):
            suite = os.path.dirname(os.path.dirname(c))
            if os.path.isdir(os.path.join(suite, "lib")):  # OSS CAD Suite needs its DLLs on PATH
                env["PATH"] = os.pathsep.join([os.path.join(suite, "bin"), os.path.join(suite, "lib"), env["PATH"]])
            return c, env
    sys.exit("yosys not found: set $YOSYS, add it to PATH or unpack OSS CAD Suite in the repo root")


def rom_module(name: str, table: list[int]) -> str:
    rows = "\n".join(f"      8'h{i:02x}: output_byte = 8'h{v:02x};" for i, v in enumerate(table))
    return (f"module {name}\n  (input  [7:0] input_byte,\n   output reg [7:0] output_byte);\n"
            f"  always @* begin\n    case (input_byte)\n{rows}\n    endcase\n  end\nendmodule\n")


def patch_sboxes(verilog: str) -> str:
    def repl(m: re.Match) -> str:
        name = m.group(1)
        return rom_module(name, A.INV_SBOX if name.startswith("inv_sbox") else A.SBOX)
    out, n = re.subn(r"^module ((?:inv_)?sbox\w*)\n.*?^endmodule\n", repl, verilog, flags=re.S | re.M)
    if n == 0:
        print("  [warn] no sbox module found to replace")
    return out


def synth(rtl_dir: str, top: str, work: str) -> dict:
    ghdl = find_ghdl()
    yosys, env = find_yosys()
    os.makedirs(work, exist_ok=True)
    srcs = sorted(glob.glob(os.path.join(rtl_dir, "*.vhd")))
    p = subprocess.run([ghdl, "--synth", "--std=08", "--out=verilog", *srcs, "-e", top],
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"ghdl --synth failed:\n{p.stderr}")
    vfile = os.path.join(work, f"{top}.v")
    with open(vfile, "w", newline="\n") as f:
        f.write(patch_sboxes(p.stdout))
    stat = os.path.join(work, f"{top}.stat")
    ltp = os.path.join(work, f"{top}.ltp")
    script = (f"read_verilog {vfile}; synth_xilinx -family xc6s -top {top} -flatten; "
              f"tee -q -o {stat} stat; "
              # cut the design at the flip-flops, then the longest combinational path
              f"delete t:FD*; tee -q -o {ltp} ltp")
    p = subprocess.run([yosys, "-q", "-p", script], capture_output=True, text=True, env=env)
    if p.returncode != 0:
        sys.exit(f"yosys failed:\n{p.stdout}\n{p.stderr}")
    cells = {}
    for ln in open(stat):
        m = re.match(r"\s+(\d+)\s+(\w+)\s*$", ln)
        if m:
            cells[m.group(2)] = cells.get(m.group(2), 0) + int(m.group(1))
    depth = int(re.search(r"length=(\d+)", open(ltp).read()).group(1))
    return {
        "FF": sum(v for k, v in cells.items() if k.startswith("FD")),
        "LUT": sum(v for k, v in cells.items() if re.fullmatch(r"LUT\d", k)),
        "MUXF7": cells.get("MUXF7", 0),
        "MUXF8": cells.get("MUXF8", 0),
        "depth": depth,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rtl-dir", help="synthesise this directory instead of AES-ENC/RTL + AES-DEC/RTL")
    ap.add_argument("--top", default="aes_dec", help="top entity with --rtl-dir")
    args = ap.parse_args()
    jobs = ([(args.rtl_dir, args.top)] if args.rtl_dir else
            [(os.path.join(ROOT, "AES-ENC", "RTL"), "aes_enc"), (os.path.join(ROOT, "AES-DEC", "RTL"), "aes_dec")])
    print("Yosys synth_xilinx -family xc6s  (XC6SLX9 has 5720 LUTs, 11440 FFs)")
    print(f"  {'design':10s} {'FF':>5s} {'LUT':>6s} {'MUXF7':>6s} {'MUXF8':>6s}  {'logic depth (cells)':>20s}")
    for d, top in jobs:
        r = synth(d, top, os.path.join(HERE, "build", "synth", top))
        print(f"  {top:10s} {r['FF']:5d} {r['LUT']:6d} {r['MUXF7']:6d} {r['MUXF8']:6d}  {r['depth']:20d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
