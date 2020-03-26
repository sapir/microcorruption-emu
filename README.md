# An MSP430 emulator for microcorruption

This is intended to run the microcorruption CTF (https://microcorruption.com/)

Tested with levels 18 and 19.

See [example.py](example.py) for example usage. Note that the interrupt function
is coded for level 19. In other levels, the arguments shouldn't be popped from the
stack at the end of the `do_int_0x10` function.

The microcorruption-gdbserver crate contains a gdbserver, you need `gdb-msp430` to use it.
See install instructions @ [https://github.com/cemeyer/msp430-emu-uctf](msp430-emu-ctf).
Note that unlike msp430-emu-ctf, this gdbserver doesn't currently implement int 0x10 (and
probably some other features, too.)
