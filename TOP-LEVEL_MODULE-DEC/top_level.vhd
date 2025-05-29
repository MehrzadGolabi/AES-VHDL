library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.ALL;

entity top_level is
    port (
        clk       : in  std_logic;
        uart_rxd  : in  std_logic;
        uart_txd  : out std_logic
    );
end top_level;

architecture Behavioral of top_level is
    --------------------------------------------------------------------------
    --  Components
    --------------------------------------------------------------------------
    COMPONENT uart
        PORT (
            clk       : IN  std_logic;
            reset     : IN  std_logic;
            txdata    : IN  std_logic_vector(7 downto 0);
            wr        : IN  std_logic;
            rd        : IN  std_logic;
            uart_rxd  : IN  std_logic;          
            rxdata    : OUT std_logic_vector(7 downto 0);
            tx_avail  : OUT std_logic;
            tx_busy   : OUT std_logic;
            rx_avail  : OUT std_logic;
            rx_full   : OUT std_logic;
            rx_error  : OUT std_logic;
            uart_txd  : OUT std_logic
        );
    END COMPONENT;

    COMPONENT aes_dec
        PORT (
            clk        : IN  std_logic;
            rst        : IN  std_logic;
            dec_key    : IN  std_logic_vector(127 downto 0);
            ciphertext : IN  std_logic_vector(127 downto 0);          
            plaintext  : OUT std_logic_vector(127 downto 0);
            done       : OUT std_logic
        );
    END COMPONENT;

    --------------------------------------------------------------------------
    --  Character ? std_logic_vector helper
    --------------------------------------------------------------------------
    function c2s (c : character) return std_logic_vector is
        variable tmp : std_logic_vector(7 downto 0);
    begin
        tmp := std_logic_vector(to_unsigned(character'pos(c), 8));
        return tmp;
    end function;

    --------------------------------------------------------------------------
    --  Power-up banner
    --------------------------------------------------------------------------
    constant CR : character := character'val(13);
    constant LF : character := character'val(10);

    constant banner : string :=
        "AES-UART DECRYPT ready (8-N-1)."                 & CR & LF &
        "Send 16-byte HEX KEY then 16-byte CIPHERTEXT (MSB first) HEX." & CR & LF &
        "Example:"                                        & CR & LF &
        "key        = 2b7e151628aed2a6abf7158809cf4f3c"   & CR & LF &
        "ciphertext = 3925841d02dc09fbdc118597196a0b32"   & CR & LF &
        "plaintext  = 3243f6a8885a308d313198a2e0370734"   & CR & LF & CR & LF;

    constant BANNER_LEN : integer := banner'length;

    --------------------------------------------------------------------------
    --  FSM states
    --------------------------------------------------------------------------
    type state_t is (BOOT_LOAD, BOOT_SEND, RESET_S,
                     RX_KEY, RX_CIPH, AES_START, AES_WAIT,
                     TX_LOAD, TX_SEND, FINISH);
    signal pr_state : state_t := BOOT_LOAD;

    --------------------------------------------------------------------------
    --  UART control
    --------------------------------------------------------------------------
    signal wr         : std_logic := '0';
    signal rd         : std_logic := '0';
    signal txdata     : std_logic_vector(7 downto 0);
    signal rxdata     : std_logic_vector(7 downto 0);
    signal tx_busy    : std_logic;
    signal rx_full    : std_logic;
    signal tx_avail   : std_logic;
    signal rx_avail   : std_logic;
    signal rx_error   : std_logic;
    signal reset_uart : std_logic := '1';

    --------------------------------------------------------------------------
    --  AES buffers
    --------------------------------------------------------------------------
    signal key_reg        : std_logic_vector(127 downto 0) := (others => '0');
    signal ciphertext_reg : std_logic_vector(127 downto 0) := (others => '0');
    signal plaintext_reg  : std_logic_vector(127 downto 0);
    signal aes_rst        : std_logic := '1';
    signal aes_done       : std_logic;

    --  Counters
    signal boot_cnt  : integer range 0 to BANNER_LEN-1 := 0;
    signal key_cnt   : integer range 0 to 15 := 0;
    signal ciph_cnt  : integer range 0 to 15 := 0;
    signal plain_cnt : integer range 0 to 15 := 0;

begin
    --------------------------------------------------------------------------
    --  UART instance
    --------------------------------------------------------------------------
    Inst_uart : uart
        PORT MAP(
            clk       => clk,
            reset     => reset_uart,
            txdata    => txdata,
            wr        => wr,
            rd        => rd,
            uart_rxd  => uart_rxd,
            rxdata    => rxdata,
            tx_avail  => tx_avail,
            tx_busy   => tx_busy,
            rx_avail  => rx_avail,
            rx_full   => rx_full,
            rx_error  => rx_error,
            uart_txd  => uart_txd
        );

    --------------------------------------------------------------------------
    --  AES-DEC instance
    --------------------------------------------------------------------------
    Inst_aes_dec : aes_dec
        PORT MAP(
            clk        => clk,
            rst        => aes_rst,
            dec_key    => key_reg,
            ciphertext => ciphertext_reg,
            plaintext  => plaintext_reg,
            done       => aes_done
        );

    --------------------------------------------------------------------------
    --  Control FSM
    --------------------------------------------------------------------------
    fsm : process(clk)
    begin
        if rising_edge(clk) then
            ------------------------------------------------------------------
            --  defaults
            ------------------------------------------------------------------
            wr         <= '0';
            rd         <= '0';
            aes_rst    <= '1';
            reset_uart <= '0';

            case pr_state is
            ------------------------------------------------------------------
            --  One-time banner
            ------------------------------------------------------------------
            when BOOT_LOAD =>
                if tx_busy = '0' then
                    txdata  <= c2s(banner(boot_cnt + banner'range'low));
                    wr      <= '1';
                    pr_state <= BOOT_SEND;
                end if;

            when BOOT_SEND =>
                wr <= '0';
                if tx_busy = '0' then
                    if boot_cnt = BANNER_LEN-1 then
                        boot_cnt <= 0;
                        pr_state <= RESET_S;
                    else
                        boot_cnt <= boot_cnt + 1;
                        pr_state <= BOOT_LOAD;
                    end if;
                end if;

            ------------------------------------------------------------------
            --  Normal flow
            ------------------------------------------------------------------
            when RESET_S =>
                aes_rst    <= '1';      -- pulse reset
                key_cnt    <= 0;
                ciph_cnt   <= 0;
                plain_cnt  <= 0;
                pr_state   <= RX_KEY;

            --------------------------------------------------------------  
            when RX_KEY =>
                if rx_full = '1' then
                    rd <= '1';
                    key_reg((15-key_cnt)*8+7 downto (15-key_cnt)*8) <= rxdata;
                    if key_cnt = 15 then
                        key_cnt  <= 0;
                        pr_state <= RX_CIPH;
                    else
                        key_cnt <= key_cnt + 1;
                    end if;
                end if;

            --------------------------------------------------------------  
            when RX_CIPH =>
                if rx_full = '1' then
                    rd <= '1';
                    ciphertext_reg((15-ciph_cnt)*8+7 downto (15-ciph_cnt)*8) <= rxdata;
                    if ciph_cnt = 15 then
                        ciph_cnt <= 0;
                        pr_state <= AES_START;
                    else
                        ciph_cnt <= ciph_cnt + 1;
                    end if;
                end if;

            --------------------------------------------------------------  
            when AES_START =>
                aes_rst  <= '0';        -- latch data into core
                pr_state <= AES_WAIT;

            when AES_WAIT =>
                if aes_done = '1' then
                    plain_cnt <= 0;
                    pr_state  <= TX_LOAD;
                end if;

            --------------------------------------------------------------  
            when TX_LOAD =>
                txdata <= plaintext_reg((15-plain_cnt)*8+7 downto (15-plain_cnt)*8);
                wr     <= '1';
                pr_state <= TX_SEND;

            when TX_SEND =>
                wr <= '0';
                if tx_busy = '0' then
                    if plain_cnt = 15 then
                        pr_state <= FINISH;
                    else
                        plain_cnt <= plain_cnt + 1;
                        pr_state  <= TX_LOAD;
                    end if;
                end if;

            --------------------------------------------------------------  
            when FINISH =>
                pr_state <= RESET_S;    -- ready for next block
            end case;
        end if;
    end process fsm;

end Behavioral;
