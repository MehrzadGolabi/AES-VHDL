-- Cycle-accurate verification of AES-ENC/RTL/aes_enc against FIPS 197.
--
-- For every vector in vectors/enc.txt (FIPS 197 App. B, the 4 ECB blocks of
-- AES_Core128.pdf, corner cases and random data) the testbench checks, on
-- every clock cycle n = 0..10 after the load cycle:
--   * the state at the start of round n+1 (= AddRoundKey output, visible on
--     the `ciphertext` port) against the reference model / PDF values,
--   * the round key in the key-schedule register against FIPS App. A.1 style
--     expansion (internal signal, read through a VHDL-2008 external name),
--   * that `done` is asserted in cycle 10 and only in cycle 10,
--   * the final ciphertext.
-- Every 3rd vector is preceded by an aborted run (reset re-asserted in the
-- middle of an encryption) to check that a new reset cleanly restarts the core.

library ieee;
use ieee.std_logic_1164.all;
use std.textio.all;
use std.env.all;
use work.tb_util_pkg.all;

entity tb_aes_enc is
	generic (VEC_FILE : string := "vectors/enc.txt");
end entity;

architecture sim of tb_aes_enc is
	constant T : time := 10 ns;
	signal clk        : std_logic := '0';
	signal rst        : std_logic := '0';
	signal key        : block_t := (others => '0');
	signal plaintext  : block_t := (others => '0');
	signal ciphertext : block_t;
	signal done       : std_logic;
	signal running    : boolean := true;
begin
	clk <= not clk after T / 2 when running;

	dut : entity work.aes_enc
		port map(clk => clk, rst => rst, key => key, plaintext => plaintext,
		         ciphertext => ciphertext, done => done);

	stim : process
		alias round_key is << signal .tb_aes_enc.dut.round_key : std_logic_vector(127 downto 0) >>;
		file f          : text;
		variable l      : line;
		variable name   : line;
		variable k, p, c: block_t;
		variable st, rk : std_logic_vector(11 * 128 - 1 downto 0);
		variable tmp    : block_t;
		variable errors : natural := 0;
		variable checks : natural := 0;
		variable nvec   : natural := 0;

		procedure expect(cond : boolean; what : string) is
		begin
			checks := checks + 1;
			if not cond then
				errors := errors + 1;
				report "[" & name.all & "] " & what severity error;
			end if;
		end procedure;
	begin
		file_open(f, VEC_FILE, read_mode);
		while not endfile(f) loop
			readline(f, l);
			next when l'length = 0;
			read_word(l, name);
			read_hex(l, k); read_hex(l, p); read_hex(l, c);
			for i in 0 to 10 loop read_hex(l, tmp); st(128 * i + 127 downto 128 * i) := tmp; end loop;
			for i in 0 to 10 loop read_hex(l, tmp); rk(128 * i + 127 downto 128 * i) := tmp; end loop;

			-- optional aborted run: start encrypting garbage, reset after 4 rounds
			if nvec mod 3 = 2 then
				key <= not swap_bytes(k); plaintext <= swap_bytes(c);
				rst <= '0'; wait until rising_edge(clk); wait for 1 ns;
				rst <= '1';
				for i in 1 to 4 loop wait until rising_edge(clk); end loop;
				wait for 1 ns;
			end if;

			-- load cycle
			key <= swap_bytes(k); plaintext <= swap_bytes(p);
			rst <= '0';
			wait until rising_edge(clk); wait for 1 ns;
			rst <= '1';
			for n in 0 to 10 loop
				tmp := st(128 * n + 127 downto 128 * n);
				expect(ciphertext = swap_bytes(tmp),
				       "cycle " & integer'image(n) & ": state " & hex(swap_bytes(ciphertext)) & " expected " & hex(tmp));
				tmp := rk(128 * n + 127 downto 128 * n);
				expect(round_key = swap_bytes(tmp),
				       "cycle " & integer'image(n) & ": round key " & hex(swap_bytes(round_key)) & " expected " & hex(tmp));
				if n = 10 then
					expect(done = '1', "done not asserted in cycle 10");
				else
					expect(done = '0', "done asserted early in cycle " & integer'image(n));
					wait until rising_edge(clk); wait for 1 ns;
				end if;
			end loop;
			expect(ciphertext = swap_bytes(c), "final ciphertext " & hex(swap_bytes(ciphertext)) & " expected " & hex(c));
			if nvec < 5 then
				report "[" & name.all & "] ct = " & hex(swap_bytes(ciphertext)) & "  (11 cycles incl. load)";
			end if;
			nvec := nvec + 1;
		end loop;
		file_close(f);

		running <= false;
		if errors = 0 then
			report "RESULT: PASS tb_aes_enc  vectors=" & integer'image(nvec) & " checks=" & integer'image(checks);
			finish;
		else
			report "RESULT: FAIL tb_aes_enc  errors=" & integer'image(errors) & " / checks=" & integer'image(checks)
				severity failure;
		end if;
		wait;
	end process;
end architecture;
