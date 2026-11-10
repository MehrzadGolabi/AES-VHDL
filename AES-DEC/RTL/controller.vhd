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

-- Decryption controller.
--
-- After the load cycle (rst = '0') the core runs two phases:
--   cnt  0 ..  9 : key expansion  - the key schedule runs forwards from the
--                  cipher key, using Rcon[1] .. Rcon[10], to reach round key 10
--   cnt 10 .. 19 : decryption     - the key schedule runs backwards
--                  (Rcon[10] .. Rcon[1]) while the state goes through the rounds
--   cnt 20       : done = '1', plaintext valid; state and key registers
--                  are frozen from here on, so the result is held
--   cnt 21       : idle
--
-- Every output is a flip-flop: it is computed from the next counter value
-- inside the clocked process, so nothing is assigned outside rising_edge(clk)
-- and no output adds decode logic to the datapath.

library ieee;
use ieee.std_logic_1164.all;

entity controller is
	port (
		clk : in std_logic;
		rst : in std_logic;
		rconst : out std_logic_vector(7 downto 0) := x"00";
		expand : out std_logic := '0';          -- '1' while expanding the key forwards
		state_en : out std_logic := '0';      -- state register clock enable
		key_en : out std_logic := '0';        -- key register clock enable
		is_first_round : out std_logic := '0';
		done : out std_logic := '0'
	);
end controller;

architecture behavioral of controller is
	subtype cnt_t is integer range 0 to 21;
	constant IDLE : cnt_t := 21;

	type rcon_array is array (1 to 10) of std_logic_vector(7 downto 0);
	constant RCON : rcon_array := (x"01", x"02", x"04", x"08", x"10", x"20", x"40", x"80", x"1b", x"36");

	function rcon_of(c : cnt_t) return std_logic_vector is
	begin
		if c <= 9 then
			return RCON(c + 1);          -- forward step c -> c+1 uses Rcon[c+1]
		elsif c <= 19 then
			return RCON(20 - c);         -- backward step from round key 20-c
		else
			return x"00";
		end if;
	end function;

	signal cnt : cnt_t := IDLE;
begin
	counter : process(clk) is
		variable nxt : cnt_t;
	begin
		if rising_edge(clk) then
			if rst = '0' then
				nxt := 0;
			elsif cnt /= IDLE then
				nxt := cnt + 1;
			else
				nxt := IDLE;
			end if;
			cnt <= nxt;
			rconst <= rcon_of(nxt);
			if nxt <= 9 then expand <= '1'; else expand <= '0'; end if;
			if nxt >= 10 and nxt <= 19 then state_en <= '1'; else state_en <= '0'; end if;
			if nxt <= 19 then key_en <= '1'; else key_en <= '0'; end if;
			if nxt = 10 then is_first_round <= '1'; else is_first_round <= '0'; end if;
			if nxt = 20 then done <= '1'; else done <= '0'; end if;
		end if;
	end process counter;
end architecture behavioral;
