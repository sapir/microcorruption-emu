import re
import pyucorremu
from random import randint
from enum import Enum


class Interrupt(Enum):
    putchar = 0x00
    getchar = 0x01
    gets = 0x02
    dep = 0x10
    markpage = 0x11
    rand = 0x20
    hsm1 = 0x7D
    hsm2 = 0x7E
    deadbolt = 0x7F


class Reg(Enum):
    pc = 0
    sp = 1
    sr = 2
    cg = 3


class CtfDevice:
    def __init__(self, dump_path):
        self.emu = pyucorremu.load_dump_file(dump_path)

    def get_cur_interrupt_type(self):
        # high byte of SR (mostly) contains interrupt type
        int_type = self.emu.get_reg(2) >> 8
        int_type &= 0x7F
        int_type = Interrupt(int_type)
        return int_type

    def do_int_0x10(self):
        int_type = self.get_cur_interrupt_type()

        def arg_addr(i):
            return self.emu.get_reg(Reg.sp.value) + 8 + 2 * i

        if int_type == Interrupt.putchar:
            c = self.emu.get_byte(arg_addr(0))
            c = chr(c)
            print(f"Output: {c}")
            num_args = 1

        elif int_type == Interrupt.gets:
            ptr = self.emu.get_word(arg_addr(0))
            maxlen = self.emu.get_word(arg_addr(1))
            print(f"gets time! writing to {ptr:#x}, maxlen={maxlen:#x}")

            s = input()
            s = s.encode()

            # TODO: is this what the real gets does? maybe only add 1?
            # what if we hit the maximum length?
            s = s.ljust(maxlen, b"\0")

            for i, b in enumerate(s):
                print(f"Writing {ptr + i:#x} = {b}")
                self.emu.set_byte(ptr + i, b)

            num_args = 2

        elif int_type == Interrupt.rand:
            rand = randint(0, 0xFFFF)
            self.emu.set_reg(15, rand)
            num_args = 0

        else:
            raise Exception(f"unsupported interrupt {int_type}")

        # Pop return address from stack
        ret_addr = self.emu.get_word(self.emu.get_reg(Reg.sp.value))
        self.emu.set_reg(
            Reg.sp.value, self.emu.get_reg(Reg.sp.value) + 2 + num_args * 2
        )
        self.emu.set_reg(Reg.pc.value, ret_addr)


def main():
    dev = CtfDevice("dump.bin")

    while True:
        if dev.emu.get_reg(Reg.sr.value) & 0x10:
            print("CPUOFF set, stopping")
            break

        pc = dev.emu.pc()
        if pc == 0x10:
            dev.do_int_0x10()
            continue

        dev.emu.step()

        # Example: trace all memory writes
        for op in dev.emu.last_ops():
            if op["type"] == "write_mem":
                print(f"Wrote {op['addr']:#x} = {op['value']:#x}")


if __name__ == "__main__":
    main()
