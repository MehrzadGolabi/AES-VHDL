-- VHDL implementation of AES
-- Copyright (C) 2019  Hosein Hadipour

-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

library ieee;
use ieee.std_logic_1164.all;

-- AES-128 decryption (FIPS 197 INVCIPHER), iterative, one round per clock.
--
-- Interface: hold `key` and `ciphertext` and pull rst low for one clock to
-- load them.  The core first expands the cipher key forwards to round key 10
-- (10 cycles), then runs the 10 inverse rounds (10 cycles).  `done` is high
-- for one cycle 20 cycles after the load cycle; `plaintext` is valid from
-- then on and is held until the next load.

entity aes_dec is
	port (
		clk : in std_logic;
		rst : in std_logic;
		key : in std_logic_vector(127 downto 0);  -- cipher key (round key 0)
		ciphertext : in std_logic_vector(127 downto 0);
		plaintext : out std_logic_vector(127 downto 0);
		done : out std_logic
	);
end aes_dec;

architecture rtl of aes_dec is
	signal reg_output : std_logic_vector(127 downto 0);
	signal inv_mixcol_input : std_logic_vector(127 downto 0);
	signal inv_mixcol_output : std_logic_vector(127 downto 0);
	signal invsr_input : std_logic_vector(127 downto 0);
	signal invsb_input : std_logic_vector(127 downto 0);
	signal feedback : std_logic_vector(127 downto 0);
	signal round_key : std_logic_vector(127 downto 0);
	signal round_const : std_logic_vector(7 downto 0);
	signal is_first_round : std_logic;
	signal expand : std_logic;
	signal state_en : std_logic;
	signal key_en : std_logic;
begin
	-- Decryption body
	-- State register: loads the ciphertext, holds it during key expansion
	-- (clock enable, so no extra mux level in the round path) and holds the
	-- result after the last round.
	state_reg : process(clk) is
	begin
		if rising_edge(clk) then
			if rst = '0' then
				reg_output <= ciphertext;
			elsif state_en = '1' then
				reg_output <= feedback;
			end if;
		end if;
	end process state_reg;
	
	add_round_key_inst : entity work.add_round_key
		port map(
			input1 => reg_output,
			input2 => round_key,
			output => inv_mixcol_input
		);
	inv_mix_columns_inst : entity work.inv_mix_columns
		port map(
			input_data  => inv_mixcol_input,
			output_data => inv_mixcol_output
		);	
	invsr_input <= inv_mixcol_input when is_first_round = '1' else inv_mixcol_output;
	inv_shift_rows_inst : entity work.inv_shift_rows
		port map(
			input  => invsr_input,
			output => invsb_input
		);
	
	inv_sub_byte_inst : entity work.inv_sub_byte
		port map(
			input_data  => invsb_input,
			output_data => feedback
		);	
	 -- Keyschedule 
	 key_schedule_inst : entity work.key_schedule
	 	port map(
	 		clk         => clk,
	 		rst         => rst,
	 		en          => key_en,
	 		expand      => expand,
	 		key         => key,
	 		round_const => round_const,
	 		round_key   => round_key
	 	);
	 -- Controller
	 controller_inst : entity work.controller
	 	port map(
	 		clk            => clk,
	 		rst            => rst,
	 		rconst         => round_const,
	 		expand         => expand,
	 		state_en       => state_en,
	 		key_en         => key_en,
	 		is_first_round => is_first_round,
	 		done           => done
	 	);
	 plaintext <= inv_mixcol_input;
end architecture rtl;
