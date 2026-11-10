library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity top_level_tb is
end top_level_tb;

architecture sim of top_level_tb is
    signal clk      : std_logic := '0';
    signal uart_rxd : std_logic := '1';
    signal uart_txd : std_logic;

    constant divisor_val : integer := 16;
    constant clk_period  : time := 10 ns;
    constant bit_period  : time := divisor_val * clk_period;

    -- Procedure to send 1 byte over UART (8-N-1)
    procedure send_byte(data : in std_logic_vector(7 downto 0); signal rxd : out std_logic) is
    begin
        -- Start bit
        rxd <= '0';
        wait for bit_period;
        -- 8 data bits (LSB first)
        for i in 0 to 7 loop
            rxd <= data(i);
            wait for bit_period;
        end loop;
        -- Stop bit
        rxd <= '1';
        wait for bit_period;
    end procedure;

    type byte_array is array (natural range <>) of std_logic_vector(7 downto 0);

    -- Vector 1:
    constant key1 : byte_array(0 to 15) := (
        x"2b", x"7e", x"15", x"16", x"28", x"ae", x"d2", x"a6",
        x"ab", x"f7", x"15", x"88", x"09", x"cf", x"4f", x"3c"
    );
    constant plain1 : byte_array(0 to 15) := (
        x"32", x"43", x"f6", x"a8", x"88", x"5a", x"30", x"8d",
        x"31", x"31", x"98", x"a2", x"e0", x"37", x"07", x"34"
    );
    constant exp_ciph1 : byte_array(0 to 15) := (
        x"39", x"25", x"84", x"1d", x"02", x"dc", x"09", x"fb",
        x"dc", x"11", x"85", x"97", x"19", x"6a", x"0b", x"32"
    );

    -- Vector 2:
    constant key2 : byte_array(0 to 15) := (others => x"00");
    constant plain2 : byte_array(0 to 15) := (others => x"00");
    constant exp_ciph2 : byte_array(0 to 15) := (
        x"66", x"e9", x"4b", x"d4", x"ef", x"8a", x"2c", x"3b",
        x"88", x"4c", x"fa", x"59", x"ca", x"34", x"2b", x"2e"
    );

    -- Vector 3:
    -- p = 6BC1BEE2 2E409F96 E93D7E11 7393172A
    -- k = 2B7E1516 28AED2A6 ABF71588 09CF4F3C
    -- c = 3AD77BB4 0D7A3660 A89ECAF3 2466EF97
    constant key3 : byte_array(0 to 15) := (
        x"2b", x"7e", x"15", x"16", x"28", x"ae", x"d2", x"a6",
        x"ab", x"f7", x"15", x"88", x"09", x"cf", x"4f", x"3c"
    );
    constant plain3 : byte_array(0 to 15) := (
        x"6b", x"c1", x"be", x"e2", x"2e", x"40", x"9f", x"96",
        x"e9", x"3d", x"7e", x"11", x"73", x"93", x"17", x"2a"
    );
    constant exp_ciph3 : byte_array(0 to 15) := (
        x"3a", x"d7", x"7b", x"b4", x"0d", x"7a", x"36", x"60",
        x"a8", x"9e", x"ca", x"f3", x"24", x"66", x"ef", x"97"
    );

    signal cipher_rx_cnt    : integer := 0;
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

    -- Clock generator (100 MHz)
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

    -- UART monitor process to receive from uart_txd
    recv_proc : process
        variable cur_byte : std_logic_vector(7 downto 0);
        variable expected : std_logic_vector(7 downto 0);
        variable blk_idx  : integer;
        variable byte_idx : integer;
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
                    blk_idx := cipher_rx_cnt / 16;
                    byte_idx := cipher_rx_cnt mod 16;
                    if blk_idx = 0 then
                        expected := exp_ciph1(byte_idx);
                    elsif blk_idx = 1 then
                        expected := exp_ciph2(byte_idx);
                    else
                        expected := exp_ciph3(byte_idx);
                    end if;

                    report "Block " & integer'image(blk_idx) & " Byte " & integer'image(byte_idx) & 
                           " received: " & to_hstring(cur_byte) & " (expected: " & to_hstring(expected) & ")";
                    assert cur_byte = expected
                        report "Mismatch in Block " & integer'image(blk_idx) & " Byte " & integer'image(byte_idx)
                        severity error;
                    cipher_rx_cnt <= cipher_rx_cnt + 1;
                end if;
            end if;
        end loop;
        wait;
    end process;

    -- Stimulus process: Send 3 consecutive blocks
    stim_proc : process
    begin
        report "Waiting for boot banner...";
        wait for 600 us;  -- longer than the boot banner
        banner_done <= true;

        -- Block 1
        report "--- Sending Block 1 (NIST Example 1) ---";
        for i in 0 to 15 loop send_byte(key1(i), uart_rxd); end loop;
        for i in 0 to 15 loop send_byte(plain1(i), uart_rxd); end loop;

        -- Wait for block 1 ciphertext to be received
        wait for 35 us;

        -- Block 2
        report "--- Sending Block 2 (All Zeros) ---";
        for i in 0 to 15 loop send_byte(key2(i), uart_rxd); end loop;
        for i in 0 to 15 loop send_byte(plain2(i), uart_rxd); end loop;

        wait for 35 us;

        -- Block 3
        report "--- Sending Block 3 (Core128 Test Vector) ---";
        for i in 0 to 15 loop send_byte(key3(i), uart_rxd); end loop;
        for i in 0 to 15 loop send_byte(plain3(i), uart_rxd); end loop;

        wait for 50 us;

        assert cipher_rx_cnt = 48
            report "Did not receive all 48 ciphertext bytes! Received: " & integer'image(cipher_rx_cnt)
            severity failure;

        report "ALL 3 BLOCKS (48 BYTES) STREAMED AND VERIFIED PERFECTLY!";
        rx_done <= true;
        wait;
    end process;

end sim;
