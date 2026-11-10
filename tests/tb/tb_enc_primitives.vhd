-- Unit tests for the combinational building blocks of AES-ENC/RTL:
--   sbox        : exhaustive, all 256 inputs vs FIPS 197 Table 4
--   gfmult_by2  : exhaustive, all 256 inputs vs XTIMES() (FIPS 197 eq. 4.5)
--   shift_rows  : 503 states vs SHIFTROWS() (Sec. 5.1.2)
--   mix_columns : 503 states vs MIXCOLUMNS() (Sec. 5.1.3)

library ieee;
use ieee.std_logic_1164.all;
use std.textio.all;
use std.env.all;
use work.tb_util_pkg.all;

entity tb_enc_primitives is
	generic (VEC_DIR : string := "vectors/");
end entity;

architecture sim of tb_enc_primitives is
	signal sb_in, sb_out, gf_in, gf_out : std_logic_vector(7 downto 0);
	signal st_in, sr_out, mc_out        : block_t;
begin
	u_sbox : entity work.sbox        port map(input_byte => sb_in, output_byte => sb_out);
	u_gf   : entity work.gfmult_by2  port map(input_byte => gf_in, output_byte => gf_out);
	u_sr   : entity work.shift_rows  port map(input => st_in, output => sr_out);
	u_mc   : entity work.mix_columns port map(input_data => st_in, output_data => mc_out);

	process
		file f : text;
		variable l : line;
		variable x, s, si, xt : std_logic_vector(7 downto 0);
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
			sb_in <= x; gf_in <= x; wait for 1 ns;
			expect(sb_out = s, "sbox(" & hex(x) & ") = " & hex(sb_out) & " expected " & hex(s));
			xt := x(6 downto 0) & '0';
			if x(7) = '1' then xt := xt xor x"1b"; end if;
			expect(gf_out = xt, "xtimes(" & hex(x) & ") = " & hex(gf_out) & " expected " & hex(xt));
		end loop;
		file_close(f);

		file_open(f, VEC_DIR & "round_funcs.txt", read_mode);
		while not endfile(f) loop
			readline(f, l);
			read_hex(l, a); read_hex(l, sr); read_hex(l, mc); read_hex(l, isr); read_hex(l, imc);
			st_in <= swap_bytes(a); wait for 1 ns;
			expect(sr_out = swap_bytes(sr), "shift_rows(" & hex(a) & ") = " & hex(swap_bytes(sr_out)) & " expected " & hex(sr));
			expect(mc_out = swap_bytes(mc), "mix_columns(" & hex(a) & ") = " & hex(swap_bytes(mc_out)) & " expected " & hex(mc));
		end loop;
		file_close(f);

		if errors = 0 then
			report "RESULT: PASS tb_enc_primitives  checks=" & integer'image(checks);
			finish;
		else
			report "RESULT: FAIL tb_enc_primitives  errors=" & integer'image(errors) severity failure;
		end if;
		wait;
	end process;
end architecture;
