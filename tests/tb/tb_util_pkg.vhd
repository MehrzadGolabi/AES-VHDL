-- Helpers shared by the AES testbenches (VHDL-2008).
--
-- Byte order: FIPS 197 numbers the input bytes in0..in15 and prints them
-- MSB-first (in0 = bits 127..120 of the hex string).  The RTL cores in this
-- repository keep in0 in bits 7..0 (in15 in bits 127..120), i.e. the byte
-- order is reversed.  swap_bytes() converts between the two (it is its own
-- inverse).  The vector files are always in FIPS order.

library ieee;
use ieee.std_logic_1164.all;
use std.textio.all;

package tb_util_pkg is
	subtype block_t is std_logic_vector(127 downto 0);

	function swap_bytes(x : std_logic_vector) return std_logic_vector;
	function hex(x : std_logic_vector) return string;

	-- read the next white-space separated word of a line
	procedure read_word(l : inout line; w : out line);
	-- read the next hex field (any width that is a multiple of 4)
	procedure read_hex(l : inout line; v : out std_logic_vector);
end package;

package body tb_util_pkg is
	function swap_bytes(x : std_logic_vector) return std_logic_vector is
		constant n : natural := x'length / 8;
		variable xi : std_logic_vector(x'length - 1 downto 0) := x;
		variable r  : std_logic_vector(x'length - 1 downto 0);
	begin
		for i in 0 to n - 1 loop
			r(8 * i + 7 downto 8 * i) := xi(8 * (n - 1 - i) + 7 downto 8 * (n - 1 - i));
		end loop;
		return r;
	end function;

	function hex(x : std_logic_vector) return string is
	begin
		return to_hstring(x);
	end function;

	procedure read_word(l : inout line; w : out line) is
		variable c    : character;
		variable good : boolean;
		variable buf  : line;
	begin
		-- skip leading blanks
		loop
			exit when l = null or l'length = 0;
			exit when l(l'left) /= ' ' and l(l'left) /= HT;
			read(l, c, good);
		end loop;
		buf := new string'("");
		loop
			exit when l = null or l'length = 0;
			exit when l(l'left) = ' ' or l(l'left) = HT;
			read(l, c, good);
			write(buf, c);
		end loop;
		w := buf;
	end procedure;

	procedure read_hex(l : inout line; v : out std_logic_vector) is
		variable good : boolean;
	begin
		hread(l, v, good);
		assert good report "read_hex: malformed vector file" severity failure;
	end procedure;
end package body;
