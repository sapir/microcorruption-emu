# An MSP430 emulator

This is intended to run the microcorruption CTF (https://microcorruption.com/)

Tested with levels 18 and 19.

See [example.py](example.py) for example usage. Note that the interrupt function
is coded for level 19. In other levels, the arguments shouldn't be popped from the
stack at the end of the `do_int_0x10` function.
