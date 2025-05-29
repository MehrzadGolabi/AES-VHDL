
# AES-VHDL + UART

This project is a fork of [AES-VHDL](https://github.com/hadipourh/AES-VHDL) by [hadipourh](https://github.com/hadipourh). The original implementation uses 387 I/O blocks (IOBs) to transmit and receive plaintext, keys, and ciphertext — a configuration that exceeds the I/O capacity of my [Posedge-1 Spartan-6 development board](https://github.com/mhaghighi/posedge_one).

To overcome this limitation, We developed a UART module to send and receive hexadecimal data over a serial connection, significantly reducing the number of I/Os required and making the design compatible with the Posedge-1 board.

## Authors

- [@MehrzadGolabi](https://github.com/MehrzadGolabi)
- [@Mohammad-HTZ](https://github.com/Mohammad-HTZ)


## Demo
-


## Roadmap

- 


