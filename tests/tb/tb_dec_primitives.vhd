-- Unit tests for the combinational building blocks of AES-DEC/RTL:
--   inv_sbox        : exhaustive vs FIPS 197 Table 6
--   sbox            : exhaustive vs Table 4 (used by the inverse key schedule)
--   inv_shift_rows  : 503 states vs INVSHIFTROWS() (Sec. 5.3.1)
--   inv_mix_columns : 503 states vs INVMIXCOLUMNS() (Sec. 5.3.3)

library ieee;
use ieee.std_logic_1164.all;
use std.textio.all;
use std.env.all;
use work.tb_util_pkg.all;

entity tb_dec_primitives is
	generic (VEC_DIR : string := "vectors/");
end entity;

architecture sim of tb_dec_primitives is
	signal b_in, sb_out, isb_out : std_logic_vector(7 downto 0);
	signal st_in, isr_out, imc_out : block_t;
begin
	u_sbox  : entity work.sbox            port map(input_byte => b_in, output_byte => sb_out);
	u_isbox : entity work.inv_sbox        port map(input_byte => b_in, output_byte => isb_out);
	u_isr   : entity work.inv_shift_rows  port map(input => st_in, output => isr_out);
	u_imc   : entity work.inv_mix_columns port map(input_data => st_in, output_data => imc_out);

	process
		file f : text;
		variable l : line;
		variable x, s, si : std_logic_vector(7 downto 0);
		variable a, sr, mc, isr, imc : block_t;
		variable errors, checks : natural := 0;

		procedure expect(cond : boolean; what : string) is
		begin
			checks := checks + 1;
			if not cond then errors := errors + 1; report what severity error; end if;
		end procedure;
	begin
		file_open(f, VEC_DIR & "sbox.txt", read_mode);
		while not endfile(f) loop
			readline(f, l);
			read_hex(l, x); read_hex(l, s); read_hex(l, si);
			b_in <= x; wait for 1 ns;
			expect(sb_out = s, "sbox(" & hex(x) & ") = " & hex(sb_out) & " expected " & hex(s));
			expect(isb_out = si, "inv_sbox(" & hex(x) & ") = " & hex(isb_out) & " expected " & hex(si));
		end loop;
		file_close(f);

		file_open(f, VEC_DIR & "round_funcs.txt", read_mode);
		while not endfile(f) loop
			readline(f, l);
			read_hex(l, a); read_hex(l, sr); read_hex(l, mc); read_hex(l, isr); read_hex(l, imc);
			st_in <= swap_bytes(a); wait for 1 ns;
			expect(isr_out = swap_bytes(isr), "inv_shift_rows(" & hex(a) & ") = " & hex(swap_bytes(isr_out)) & " expected " & hex(isr));
			expect(imc_out = swap_bytes(imc), "inv_mix_columns(" & hex(a) & ") = " & hex(swap_bytes(imc_out)) & " expected " & hex(imc));
		end loop;
		file_close(f);

		if errors = 0 then
			report "RESULT: PASS tb_dec_primitives  checks=" & integer'image(checks);
			finish;
		else
			report "RESULT: FAIL tb_dec_primitives  errors=" & integer'image(errors) severity failure;
		end if;
		wait;
	end process;
end architecture;
