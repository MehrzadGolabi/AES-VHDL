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

-- Decryption key schedule.
-- rst = '0'   : load the cipher key (round key 0)
-- expand = '1': step forwards  (round key i -> i+1), used for 10 cycles to
--               reach round key 10 on chip
-- expand = '0': step backwards (round key i -> i-1) during decryption
-- en = '0'    : hold

library ieee;
use ieee.std_logic_1164.all;

entity key_schedule is
	port (
		clk : in std_logic;
		rst : in std_logic;
		en : in std_logic;
		expand : in std_logic;
		key : in std_logic_vector(127 downto 0);
		round_const : in std_logic_vector(7 downto 0);
		round_key : out std_logic_vector(127 downto 0)
	);
end key_schedule;

architecture behavioral of key_schedule is
	signal next_fwd : std_logic_vector(127 downto 0);
	signal next_inv : std_logic_vector(127 downto 0);
	signal reg_output : std_logic_vector(127 downto 0);
begin
	process(clk) is
	begin
		if rising_edge(clk) then
			if rst = '0' then
				reg_output <= key;
			elsif en = '1' then
				if expand = '1' then
					reg_output <= next_fwd;
				else
					reg_output <= next_inv;
				end if;
			end if;
		end if;
	end process;

	fwd_round_function_inst : entity work.key_sch_round_function
		port map(
			subkey      => reg_output,
			round_const => round_const,
			next_subkey => next_fwd
		);
	inv_round_function_inst : entity work.inv_ksch_round_func
		port map(
			subkey      => reg_output,
			round_const => round_const,
			next_subkey => next_inv
		);
	round_key <= reg_output;
end architecture behavioral;
