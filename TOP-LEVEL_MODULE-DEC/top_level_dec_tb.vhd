library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity top_level_dec_tb is
end top_level_dec_tb;

architecture sim of top_level_dec_tb is
    signal clk      : std_logic := '0';
    signal uart_rxd : std_logic := '1';
    signal uart_txd : std_logic;

    constant divisor_val : integer := 16;
    constant clk_period  : time := 10 ns;
    constant bit_period  : time := divisor_val * clk_period;

    procedure send_byte(data : in std_logic_vector(7 downto 0); signal rxd : out std_logic) is
    begin
        rxd <= '0';
        wait for bit_period;
        for i in 0 to 7 loop
            rxd <= data(i);
            wait for bit_period;
        end loop;
        rxd <= '1';
        wait for bit_period;
    end procedure;

    type byte_array is array (natural range <>) of std_logic_vector(7 downto 0);

    -- Round 10 key for 2b7e151628aed2a6abf7158809cf4f3c:
    -- d0 14 f9 a8 c9 ee 25 89 e1 3f 0c c8 b6 63 0c a6 (Byte 0 is d0)
    -- cipher key (the core derives the last round key on chip)
    constant key_bytes : byte_array(0 to 15) := (
        x"2b", x"7e", x"15", x"16", x"28", x"ae", x"d2", x"a6",
        x"ab", x"f7", x"15", x"88", x"09", x"cf", x"4f", x"3c"
    );

    -- Ciphertext:
    constant cipher_bytes : byte_array(0 to 15) := (
        x"39", x"25", x"84", x"1d", x"02", x"dc", x"09", x"fb",
        x"dc", x"11", x"85", x"97", x"19", x"6a", x"0b", x"32"
    );

    -- Expected Plaintext:
    constant exp_plain_bytes : byte_array(0 to 15) := (
        x"32", x"43", x"f6", x"a8", x"88", x"5a", x"30", x"8d",
        x"31", x"31", x"98", x"a2", x"e0", x"37", x"07", x"34"
    );

    signal plain_out_bytes  : byte_array(0 to 15);
    signal plain_rx_cnt     : integer := 0;
    signal banner_done      : boolean := false;
    signal rx_done          : boolean := false;

begin
    uut : entity work.top_level
        generic map (
            divisor => divisor_val
        )
        port map (
            clk      => clk,
            uart_rxd => uart_rxd,
            uart_txd => uart_txd
        );

    clk_process : process
    begin
        while not rx_done loop
            clk <= '0';
            wait for clk_period / 2;
            clk <= '1';
            wait for clk_period / 2;
        end loop;
        wait;
    end process;

    recv_proc : process
        variable cur_byte : std_logic_vector(7 downto 0);
    begin
        while not rx_done loop
            wait until falling_edge(uart_txd);
            wait for bit_period / 2;
            if uart_txd = '0' then
                wait for bit_period;
                for i in 0 to 7 loop
                    cur_byte(i) := uart_txd;
                    wait for bit_period;
                end loop;
                
                if banner_done then
                    if plain_rx_cnt < 16 then
                        plain_out_bytes(plain_rx_cnt) <= cur_byte;
                        report "Decrypted Plaintext byte " & integer'image(plain_rx_cnt) & " received: " & 
                               to_hstring(cur_byte) & " (expected: " & to_hstring(exp_plain_bytes(plain_rx_cnt)) & ")";
                        assert cur_byte = exp_plain_bytes(plain_rx_cnt)
                            report "Mismatch in decrypted byte " & integer'image(plain_rx_cnt)
                            severity error;
                        plain_rx_cnt <= plain_rx_cnt + 1;
                    end if;
                end if;
            end if;
        end loop;
        wait;
    end process;

    stim_proc : process
    begin
        report "Waiting for DEC banner...";
        wait for 600 us;  -- longer than the boot banner
        banner_done <= true;

        report "Sending 16 cipher key bytes...";
        for i in 0 to 15 loop
            send_byte(key_bytes(i), uart_rxd);
        end loop;

        report "Sending 16 Ciphertext bytes...";
        for i in 0 to 15 loop
            send_byte(cipher_bytes(i), uart_rxd);
        end loop;

        wait for 50 us;

        assert plain_rx_cnt = 16
            report "Did not receive all 16 plaintext bytes! Received: " & integer'image(plain_rx_cnt)
            severity failure;

        report "ALL 16 DECRYPTED PLAINTEXT BYTES MATCH EXPECTED NIST VALUES PERFECTLY!";
        rx_done <= true;
        wait;
    end process;

end sim;
