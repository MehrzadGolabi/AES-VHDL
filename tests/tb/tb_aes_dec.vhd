-- Cycle-accurate verification of AES-DEC/RTL/aes_dec against FIPS 197
-- INVCIPHER (Algorithm 3).
--
-- The core takes the cipher key, expands it forwards on chip to round key 10
-- (cycles 0..9), then decrypts (cycles 10..19); done is high in cycle 20.
--
-- Checked on every clock cycle after the load cycle:
--   cycles 0..9  : round key register = round key j (forward expansion,
--                  FIPS 197 App. A.1 style), done = '0'
--   cycles 10..20: state right after AddRoundKey(rk[20-n]) (on `plaintext`),
--                  round key register = rk[20-n], done only in cycle 20
--   after done   : plaintext stays valid for a few more cycles.

library ieee;
use ieee.std_logic_1164.all;
use std.textio.all;
use std.env.all;
use work.tb_util_pkg.all;

entity tb_aes_dec is
	generic (VEC_FILE : string := "vectors/dec.txt");
end entity;

architecture sim of tb_aes_dec is
	constant T : time := 10 ns;
	signal clk        : std_logic := '0';
	signal rst        : std_logic := '0';
	signal key        : block_t := (others => '0');
	signal ciphertext : block_t := (others => '0');
	signal plaintext  : block_t;
	signal done       : std_logic;
	signal running    : boolean := true;
begin
	clk <= not clk after T / 2 when running;

	dut : entity work.aes_dec
		port map(clk => clk, rst => rst, key => key, ciphertext => ciphertext,
		         plaintext => plaintext, done => done);

	stim : process
		alias round_key is << signal .tb_aes_dec.dut.round_key : std_logic_vector(127 downto 0) >>;
		file f            : text;
		variable l        : line;
		variable name     : line;
		variable k, k10   : block_t;
		variable c, p     : block_t;
		variable st, rk   : std_logic_vector(11 * 128 - 1 downto 0);
		variable tmp      : block_t;
		variable errors   : natural := 0;
		variable checks   : natural := 0;
		variable nvec     : natural := 0;

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
			read_hex(l, k); read_hex(l, k10); read_hex(l, c); read_hex(l, p);
			for i in 0 to 10 loop read_hex(l, tmp); st(128 * i + 127 downto 128 * i) := tmp; end loop;
			for i in 0 to 10 loop read_hex(l, tmp); rk(128 * i + 127 downto 128 * i) := tmp; end loop;

			if nvec mod 3 = 2 then  -- aborted run first
				key <= not swap_bytes(k); ciphertext <= swap_bytes(p);
				rst <= '0'; wait until rising_edge(clk); wait for 1 ns;
				rst <= '1';
				for i in 1 to 4 loop wait until rising_edge(clk); end loop;
				wait for 1 ns;
			end if;

			key <= swap_bytes(k); ciphertext <= swap_bytes(c);
			rst <= '0';
			wait until rising_edge(clk); wait for 1 ns;
			rst <= '1';
			-- key expansion: rk(...) holds rk10..rk0, so round key j is slot 10-j
			for j in 0 to 9 loop
				tmp := rk(128 * (10 - j) + 127 downto 128 * (10 - j));
				expect(round_key = swap_bytes(tmp),
				       "expand cycle " & integer'image(j) & ": round key " & hex(swap_bytes(round_key)) & " expected " & hex(tmp));
				expect(done = '0', "done asserted during key expansion, cycle " & integer'image(j));
				wait until rising_edge(clk); wait for 1 ns;
			end loop;
			for n in 0 to 10 loop
				tmp := st(128 * n + 127 downto 128 * n);
				expect(plaintext = swap_bytes(tmp),
				       "cycle " & integer'image(10 + n) & ": state " & hex(swap_bytes(plaintext)) & " expected " & hex(tmp));
				tmp := rk(128 * n + 127 downto 128 * n);
				expect(round_key = swap_bytes(tmp),
				       "cycle " & integer'image(10 + n) & ": round key " & hex(swap_bytes(round_key)) & " expected " & hex(tmp));
				if n = 10 then
					expect(done = '1', "done not asserted in cycle 20");
				else
					expect(done = '0', "done asserted early in cycle " & integer'image(10 + n));
					wait until rising_edge(clk); wait for 1 ns;
				end if;
			end loop;
			if nvec mod 4 = 0 then  -- result must be held after done
				for i in 1 to 3 loop
					wait until rising_edge(clk); wait for 1 ns;
					expect(done = '0', "done high again after completion");
					expect(plaintext = swap_bytes(p), "plaintext not held " & integer'image(i) & " cycles after done");
				end loop;
			end if;
			expect(plaintext = swap_bytes(p), "final plaintext " & hex(swap_bytes(plaintext)) & " expected " & hex(p));
			if nvec < 5 then
				report "[" & name.all & "] pt = " & hex(swap_bytes(plaintext)) & "  (21 cycles incl. load)";
			end if;
			nvec := nvec + 1;
		end loop;
		file_close(f);

		running <= false;
		if errors = 0 then
			report "RESULT: PASS tb_aes_dec  vectors=" & integer'image(nvec) & " checks=" & integer'image(checks);
			finish;
		else
			report "RESULT: FAIL tb_aes_dec  errors=" & integer'image(errors) & " / checks=" & integer'image(checks)
				severity failure;
		end if;
		wait;
	end process;
end architecture;
