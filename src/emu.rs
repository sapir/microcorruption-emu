use super::disasm::{
    next_insn, AccessSize, Instruction, Opcode, Operand, RegisterMode, REG_PC, REG_SP, REG_SR,
};
use std::convert::TryInto;
use std::ops::{Index, IndexMut};
use std::path::Path;

#[derive(Clone, Debug)]
pub enum Error {
    UnalignedAccess { addr: u16 },
}

pub struct Memory {
    pub data: Vec<u8>,
}

impl Memory {
    pub fn new() -> Self {
        Self {
            data: vec![0; 0x1_0000],
        }
    }

    pub fn from_dump<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let data = std::fs::read(path)?;
        assert_eq!(data.len(), 0x1_0000);
        Ok(Self { data })
    }

    pub fn get_byte(&self, addr: u16) -> u8 {
        self.data[usize::from(addr)]
    }

    pub fn get_word(&self, addr: u16) -> Result<u16, Error> {
        if (addr & 1) != 0 {
            return Err(Error::UnalignedAccess { addr });
        }

        Ok(u16::from_le_bytes(
            self.data[usize::from(addr)..usize::from(addr) + 2]
                .try_into()
                .unwrap(),
        ))
    }

    pub fn get(&self, addr: u16, size: AccessSize) -> Result<u16, Error> {
        match size {
            AccessSize::Byte => Ok(self.get_byte(addr).into()),
            AccessSize::Word => Ok(self.get_word(addr)?),
        }
    }

    pub fn set_byte(&mut self, addr: u16, value: u8) {
        self.data[usize::from(addr)] = value;
    }

    pub fn set_word(&mut self, addr: u16, value: u16) -> Result<(), Error> {
        if (addr & 1) != 0 {
            return Err(Error::UnalignedAccess { addr });
        }

        self.data[usize::from(addr)] = (value & 0xff).try_into().unwrap();
        self.data[usize::from(addr) + 1] = (value >> 8).try_into().unwrap();

        Ok(())
    }

    pub fn set(&mut self, addr: u16, size: AccessSize, value: u16) -> Result<(), Error> {
        match size {
            AccessSize::Byte => {
                self.set_byte(addr, (value & 0xff).try_into().unwrap());
                Ok(())
            }

            AccessSize::Word => self.set_word(addr, value),
        }
    }
}

pub const STATUS_BIT_C: u16 = 0;
pub const STATUS_BIT_Z: u16 = 1;
pub const STATUS_BIT_N: u16 = 2;
// TODO: is this really what microcorruption is using?
pub const STATUS_BIT_V: u16 = 8;

pub struct Registers {
    regs: [u16; 16],
}

impl Registers {
    pub fn new() -> Self {
        Self { regs: [0; 16] }
    }

    pub fn pc(&self) -> u16 {
        self[REG_PC]
    }

    fn get_status_bit(&self, bit: u16) -> bool {
        (self[REG_SR] & (1 << bit)) != 0
    }

    pub fn status_c(&self) -> bool {
        self.get_status_bit(STATUS_BIT_C)
    }

    pub fn status_z(&self) -> bool {
        self.get_status_bit(STATUS_BIT_Z)
    }

    pub fn status_n(&self) -> bool {
        self.get_status_bit(STATUS_BIT_N)
    }

    pub fn status_v(&self) -> bool {
        self.get_status_bit(STATUS_BIT_V)
    }

    /// Used for calculating status bits
    fn is_negative(size: AccessSize, value: u16) -> bool {
        (value & size.msb()) != 0
    }

    /// `result` is the result of the instruction, the value stored in the destination
    /// when any is stored.
    pub fn set_status_bits(&mut self, size: AccessSize, result: u16, c: bool, v: bool) {
        let z = result == 0;
        let n = Self::is_negative(size, result);
        // CTF emulator seems to clears other bits here, level 19 requires this to happen
        // soon after the INT() call.
        // let mut sr = self[REG_SR];
        // sr &= !(STATUS_BIT_C | STATUS_BIT_Z | STATUS_BIT_N | STATUS_BIT_V);
        let mut sr = 0;
        sr |= (c as u16) << STATUS_BIT_C;
        sr |= (z as u16) << STATUS_BIT_Z;
        sr |= (n as u16) << STATUS_BIT_N;
        sr |= (v as u16) << STATUS_BIT_V;
        self[REG_SR] = sr;
    }

    /// Calculate status V bit for add operations.
    /// See http://www.ti.com/lit/ug/slau144j/slau144j.pdf table 3-1
    pub fn calc_add_overflow(size: AccessSize, a: u16, b: u16, result: u16) -> bool {
        let a_is_neg = Self::is_negative(size, a);
        let b_is_neg = Self::is_negative(size, b);
        let res_is_neg = Self::is_negative(size, result);
        a_is_neg == b_is_neg && a_is_neg != res_is_neg
    }

    /// Calculate status V bit for subtraction operations.
    /// See http://www.ti.com/lit/ug/slau144j/slau144j.pdf table 3-1
    pub fn calc_sub_overflow(size: AccessSize, a: u16, b: u16, result: u16) -> bool {
        let a_is_neg = Self::is_negative(size, a);
        let b_is_neg = Self::is_negative(size, b);
        let res_is_neg = Self::is_negative(size, result);
        a_is_neg != b_is_neg && b_is_neg == res_is_neg
    }
}

impl Index<u16> for Registers {
    type Output = u16;

    fn index(&self, index: u16) -> &u16 {
        &self.regs[usize::from(index)]
    }
}

impl IndexMut<u16> for Registers {
    fn index_mut(&mut self, index: u16) -> &mut u16 {
        &mut self.regs[usize::from(index)]
    }
}

pub struct Emulator {
    pub regs: Registers,
    pub mem: Memory,
}

impl Emulator {
    pub fn new() -> Self {
        Self {
            regs: Registers::new(),
            mem: Memory::new(),
        }
    }

    pub fn from_dump<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let mem = Memory::from_dump(path)?;
        let mut regs = Registers::new();
        regs[REG_PC] = mem.get_word(0xfffe).unwrap();
        Ok(Self { regs, mem })
    }

    pub fn pc(&self) -> u16 {
        self.regs.pc()
    }

    fn read_operand(&mut self, operand: &Operand, size: AccessSize) -> u16 {
        match operand {
            Operand::Register {
                reg,
                mode,
                increment,
            } => {
                let value = self.regs[*reg];

                let value = match mode {
                    RegisterMode::Direct => value,
                    RegisterMode::Indirect => self.mem.get(value, size).unwrap(),
                };

                if *increment {
                    self.regs[*reg] += match size {
                        AccessSize::Byte => 1,
                        AccessSize::Word => 2,
                    };
                }

                value
            }

            Operand::Indexed { reg, offset } => {
                let mut addr = self.regs[*reg];
                addr = addr.wrapping_add(*offset as u16);
                self.mem.get(addr, size).unwrap()
            }

            Operand::Immediate(value) => *value,

            Operand::Absolute(addr) => self.mem.get(*addr, size).unwrap(),
        }
    }

    pub fn write_operand(&mut self, operand: &Operand, size: AccessSize, value: u16) {
        match operand {
            Operand::Register {
                reg,
                mode,
                increment,
            } => {
                assert!(!increment);

                match mode {
                    RegisterMode::Direct => {
                        if size == AccessSize::Byte {
                            assert_eq!(value, value & 0xff);
                        }

                        self.regs[*reg] = value;
                    }

                    RegisterMode::Indirect => self.mem.set(self.regs[*reg], size, value).unwrap(),
                }
            }

            Operand::Indexed { reg, offset } => {
                let mut addr = self.regs[*reg];
                addr = addr.wrapping_add(*offset as u16);
                self.mem.set(addr, size, value).unwrap();
            }

            Operand::Absolute(addr) => {
                self.mem.set(*addr, size, value).unwrap();
            }

            Operand::Immediate(_) => unreachable!(),
        }
    }

    fn push(&mut self, value: u16) {
        self.regs[REG_SP] = self.regs[REG_SP].wrapping_sub(2);
        self.mem.set_word(self.regs[REG_SP], value).unwrap();
    }

    fn pop(&mut self) -> u16 {
        let value = self.mem.get_word(self.regs[REG_SP]).unwrap();
        self.regs[REG_SP] = self.regs[REG_SP].wrapping_add(2);
        value
    }

    pub fn perform(&mut self, insn: &Instruction) {
        use Opcode::*;

        match insn.opcode {
            Rrc(size) | Rra(size) => {
                let mut value = self.read_operand(&insn.operands[0], size);
                let c = (value & 1) != 0;
                let new_msb = match insn.opcode {
                    Rrc(_) => self.regs.status_c(),
                    Rra(_) => (value & size.msb()) != 0,
                    _ => unreachable!(),
                };

                value >>= 1;
                if new_msb {
                    value |= size.msb();
                }

                self.write_operand(&insn.operands[0], size, value);

                self.regs.set_status_bits(size, value, c, false);
            }

            Swpb => {
                let value = self.read_operand(&insn.operands[0], AccessSize::Word);
                self.write_operand(
                    &insn.operands[0],
                    AccessSize::Word,
                    (value >> 8) | (value << 8),
                );

                self.regs
                    .set_status_bits(AccessSize::Word, value, value != 0, false);
            }

            Sxt => {
                let mut value = self.read_operand(&insn.operands[0], AccessSize::Byte);
                if (value & 0x80) != 0 {
                    value |= 0xff00;
                }

                self.write_operand(&insn.operands[0], AccessSize::Word, value);

                self.regs
                    .set_status_bits(AccessSize::Word, value, value != 0, false);
            }

            Push(size) => {
                let value = self.read_operand(&insn.operands[0], size);
                self.push(value);
            }

            Call => {
                let ret_addr = self.pc();
                self.push(ret_addr);

                let dest = self.read_operand(&insn.operands[0], AccessSize::Word);
                self.regs[REG_PC] = dest;
            }

            Reti => {
                self.regs[REG_SR] = self.pop();
                self.regs[REG_PC] = self.pop();
            }

            Jne | Jeq | Jnc | Jc | Jn | Jge | Jl | Jmp => {
                let cond = match insn.opcode {
                    Jne => !self.regs.status_z(),
                    Jeq => self.regs.status_z(),
                    Jnc => !self.regs.status_c(),
                    Jc => self.regs.status_c(),
                    Jn => self.regs.status_n(),
                    Jge => !(self.regs.status_n() ^ self.regs.status_v()),
                    Jl => self.regs.status_n() ^ self.regs.status_v(),
                    Jmp => true,
                    _ => unreachable!(),
                };

                if cond {
                    self.regs[REG_PC] = self.read_operand(&insn.operands[0], AccessSize::Word);
                }
            }

            Mov(size) | Add(size) | Addc(size) | Subc(size) | Sub(size) | Cmp(size)
            | Dadd(size) | Bit(size) | Bic(size) | Bis(size) | Xor(size) | And(size) => {
                let opnd1 = self.read_operand(&insn.operands[0], size);
                let mut value = opnd1;

                match insn.opcode {
                    Mov(_size) => {}

                    Add(size) | Addc(size) | Sub(size) | Cmp(size) | Subc(size) => {
                        let opnd2 = self.read_operand(&insn.operands[1], size);

                        let mut final_opnd1 = opnd1;
                        if matches!(insn.opcode, Sub(_) | Cmp(_) | Subc(_)) {
                            final_opnd1 = !final_opnd1;
                        }

                        if matches!(insn.opcode, Sub(_) | Cmp(_)) {
                            final_opnd1 = final_opnd1.wrapping_add(1);
                        } else if matches!(insn.opcode, Addc(_) | Subc(_)) {
                            final_opnd1 = final_opnd1.wrapping_add(self.regs.status_c().into());
                        }

                        let value32 = u32::from(final_opnd1).wrapping_add(opnd2.into());
                        value = value32 as u16;

                        self.regs.set_status_bits(
                            size,
                            value,
                            value32 > 0xffff,
                            if matches!(insn.opcode, Add(_) | Addc(_)) {
                                Registers::calc_add_overflow(size, opnd1, opnd2, value)
                            } else {
                                Registers::calc_sub_overflow(size, opnd1, opnd2, value)
                            },
                        )
                    }

                    Dadd(size) => {
                        fn get_nibble(x: u16, shift: u16) -> u16 {
                            (x >> shift) & 0xf
                        }

                        fn from_bcd(x: u16) -> u16 {
                            get_nibble(x, 12) * 1000
                                + get_nibble(x, 8) * 100
                                + get_nibble(x, 4) * 10
                                + get_nibble(x, 0)
                        }

                        fn get_digit(x: u16, digit_value: u16) -> u16 {
                            (x / digit_value) % 10
                        }

                        fn to_bcd(x: u16) -> u16 {
                            (get_digit(x, 1000) << 12)
                                | (get_digit(x, 100) << 8)
                                | (get_digit(x, 10) << 4)
                                | get_digit(x, 1)
                        }

                        let opnd2 = self.read_operand(&insn.operands[1], size);
                        let value = from_bcd(opnd1).checked_add(from_bcd(opnd2)).unwrap();
                        let encoded_value = to_bcd(value);
                        self.write_operand(&insn.operands[1], size, encoded_value);

                        // TODO: when is N really set?
                        let c = match size {
                            AccessSize::Byte => value > 99,
                            AccessSize::Word => value > 9999,
                        };

                        self.regs.set_status_bits(size, encoded_value, c, false);
                    }

                    Bit(size) | And(size) => {
                        value &= self.read_operand(&insn.operands[1], size);

                        self.regs.set_status_bits(size, value, value != 0, false);
                    }

                    Bic(size) => {
                        value = self.read_operand(&insn.operands[1], size) & !value;
                    }

                    Bis(size) => {
                        value = self.read_operand(&insn.operands[1], size) | value;
                    }

                    Xor(size) => {
                        let opnd2 = self.read_operand(&insn.operands[1], size);
                        value = opnd2 ^ value;

                        self.regs.set_status_bits(
                            size,
                            value,
                            value != 0,
                            Registers::is_negative(size, opnd1)
                                && Registers::is_negative(size, opnd2),
                        );
                    }

                    _ => unreachable!(),
                }

                if !matches!(insn.opcode, Cmp(_size) | Bit(_size)) {
                    self.write_operand(&insn.operands[1], size, value);
                }
            }
        }
    }

    pub fn next_insn(&self) -> super::disasm::Result<Instruction> {
        next_insn(self.pc(), |addr| Some(self.mem.get_word(addr).unwrap()))
    }

    pub fn step(&mut self) {
        let insn = self.next_insn().unwrap();
        // Set next PC before calling perform(). This way any jumps can override the PC, and
        // instructions that need the address of the next instruction (=call) can just read the
        // value of PC.
        self.regs[REG_PC] = self.pc().wrapping_add(insn.byte_size);
        self.perform(&insn);
    }
}
