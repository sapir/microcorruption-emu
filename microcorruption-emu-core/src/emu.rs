use super::disasm::{
    self, next_insn, AccessSize, Instruction, Opcode, Operand, RegisterMode, REG_PC, REG_SP, REG_SR,
};
use arrayvec::ArrayVec;
use std::convert::TryInto;
use std::ops::{Index, IndexMut};
use std::path::Path;

#[derive(Clone, Debug)]
pub enum Error {
    BadOpcode { pc: u16, word: u16 },
    UnalignedAccess { pc: u16, addr: u16 },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum LoadError {
    BadDumpLength(usize),
    IO(std::io::Error),
}

#[derive(Debug)]
pub enum MemoryError {
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

    pub fn from_buf(data: Vec<u8>) -> Result<Self, LoadError> {
        if data.len() != 0x1_0000 {
            return Err(LoadError::BadDumpLength(data.len()));
        }

        Ok(Self { data })
    }

    pub fn from_dump_file<P: AsRef<Path>>(path: P) -> Result<Self, LoadError> {
        let data = std::fs::read(path).map_err(LoadError::IO)?;
        Self::from_buf(data)
    }

    pub fn get_byte(&self, addr: u16) -> u8 {
        self.data[usize::from(addr)]
    }

    pub fn get_word(&self, addr: u16) -> Result<u16, MemoryError> {
        if (addr & 1) != 0 {
            return Err(MemoryError::UnalignedAccess { addr });
        }

        Ok(u16::from_le_bytes(
            self.data[usize::from(addr)..usize::from(addr) + 2]
                .try_into()
                .unwrap(),
        ))
    }

    pub fn get(&self, addr: u16, size: AccessSize) -> Result<u16, MemoryError> {
        match size {
            AccessSize::Byte => Ok(self.get_byte(addr).into()),
            AccessSize::Word => Ok(self.get_word(addr)?),
        }
    }

    pub fn set_byte(&mut self, addr: u16, value: u8) {
        self.data[usize::from(addr)] = value;
    }

    pub fn set_word(&mut self, addr: u16, value: u16) -> Result<(), MemoryError> {
        if (addr & 1) != 0 {
            return Err(MemoryError::UnalignedAccess { addr });
        }

        self.data[usize::from(addr)] = (value & 0xff).try_into().unwrap();
        self.data[usize::from(addr) + 1] = (value >> 8).try_into().unwrap();

        Ok(())
    }

    pub fn set(&mut self, addr: u16, size: AccessSize, value: u16) -> Result<(), MemoryError> {
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

#[derive(Debug)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmulatorOpKind {
    /// A direct read from a register.
    ReadReg,
    ReadMem,
    /// An explicit write to a register. @REG+ doesn't count.
    WriteReg,
    WriteMem,
}

#[derive(Clone, Debug)]
pub struct EmulatorOp {
    pub kind: EmulatorOpKind,
    pub size: AccessSize,
    pub addr: u16,
    pub value: u16,
}

pub struct Emulator {
    pub regs: Registers,
    pub mem: Memory,
    pub last_ops: ArrayVec<[EmulatorOp; 4]>,
    /// Used for nicer errors, because pc while performing instruction already points to next
    /// instruction.
    cur_insn_pc: u16,
}

impl Emulator {
    #[cfg(test)]
    pub fn new() -> Self {
        Self {
            regs: Registers::new(),
            mem: Memory::new(),
            last_ops: ArrayVec::new(),
            // Value doesn't matter here
            cur_insn_pc: 0,
        }
    }

    pub fn from_initial_memory(mem: Memory) -> Self {
        let mut regs = Registers::new();
        regs[REG_PC] = mem.get_word(0xfffe).unwrap();
        // Value of cur_insn_pc doesn't matter here
        Self {
            regs,
            mem,
            last_ops: ArrayVec::new(),
            cur_insn_pc: 0,
        }
    }

    pub fn from_dump_file<P: AsRef<Path>>(path: P) -> Result<Self, LoadError> {
        let mem = Memory::from_dump_file(path)?;
        Ok(Self::from_initial_memory(mem))
    }

    pub fn pc(&self) -> u16 {
        self.regs.pc()
    }

    /// Assumes self.cur_insn_pc is set
    fn wrap_mem_error(&self, err: MemoryError) -> Error {
        match err {
            MemoryError::UnalignedAccess { addr } => Error::UnalignedAccess {
                pc: self.cur_insn_pc,
                addr,
            },
        }
    }

    fn read_operand(&mut self, operand: &Operand, size: AccessSize) -> Result<u16> {
        match operand {
            Operand::Register {
                reg,
                mode,
                increment,
            } => {
                let mut value = self.regs[*reg];

                let value = match mode {
                    RegisterMode::Direct => {
                        // write_operand() also truncates, but this is still required for correct
                        // status flags and possibly other cases.
                        if size == AccessSize::Byte {
                            value &= 0xff;
                        }

                        self.last_ops.push(EmulatorOp {
                            kind: EmulatorOpKind::ReadReg,
                            size,
                            addr: *reg,
                            value,
                        });

                        value
                    }

                    RegisterMode::Indirect => {
                        let addr = value;
                        let value = self
                            .mem
                            .get(value, size)
                            .map_err(|e| self.wrap_mem_error(e))?;

                        self.last_ops.push(EmulatorOp {
                            kind: EmulatorOpKind::ReadMem,
                            size,
                            addr,
                            value,
                        });

                        value
                    }
                };

                if *increment {
                    self.regs[*reg] += match size {
                        AccessSize::Byte => 1,
                        AccessSize::Word => 2,
                    };
                }

                Ok(value)
            }

            Operand::Indexed { reg, offset } => {
                let mut addr = self.regs[*reg];
                addr = addr.wrapping_add(*offset as u16);
                let value = self
                    .mem
                    .get(addr, size)
                    .map_err(|e| self.wrap_mem_error(e))?;
                self.last_ops.push(EmulatorOp {
                    kind: EmulatorOpKind::ReadMem,
                    size,
                    addr,
                    value,
                });
                Ok(value)
            }

            Operand::Immediate(value) => Ok(*value),

            Operand::Absolute(addr) => {
                let value = self
                    .mem
                    .get(*addr, size)
                    .map_err(|e| self.wrap_mem_error(e))?;

                self.last_ops.push(EmulatorOp {
                    kind: EmulatorOpKind::ReadMem,
                    size,
                    addr: *addr,
                    value,
                });

                Ok(value)
            }
        }
    }

    pub fn write_operand(
        &mut self,
        operand: &Operand,
        size: AccessSize,
        mut value: u16,
    ) -> Result<()> {
        if size == AccessSize::Byte {
            value &= 0xff;
        }

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

                        self.last_ops.push(EmulatorOp {
                            kind: EmulatorOpKind::WriteReg,
                            size,
                            addr: *reg,
                            value,
                        });

                        self.regs[*reg] = value;
                        Ok(())
                    }

                    RegisterMode::Indirect => {
                        let addr = self.regs[*reg];
                        self.mem
                            .set(addr, size, value)
                            .map_err(|e| self.wrap_mem_error(e))?;

                        self.last_ops.push(EmulatorOp {
                            kind: EmulatorOpKind::WriteMem,
                            size,
                            addr,
                            value,
                        });

                        Ok(())
                    }
                }
            }

            Operand::Indexed { reg, offset } => {
                let mut addr = self.regs[*reg];
                addr = addr.wrapping_add(*offset as u16);
                self.mem
                    .set(addr, size, value)
                    .map_err(|e| self.wrap_mem_error(e))?;

                self.last_ops.push(EmulatorOp {
                    kind: EmulatorOpKind::WriteMem,
                    size,
                    addr,
                    value,
                });

                Ok(())
            }

            Operand::Absolute(addr) => {
                self.mem
                    .set(*addr, size, value)
                    .map_err(|e| self.wrap_mem_error(e))?;

                self.last_ops.push(EmulatorOp {
                    kind: EmulatorOpKind::WriteMem,
                    size,
                    addr: *addr,
                    value,
                });

                Ok(())
            }

            Operand::Immediate(_) => unreachable!(),
        }
    }

    fn push(&mut self, value: u16) -> Result<()> {
        self.regs[REG_SP] = self.regs[REG_SP].wrapping_sub(2);
        self.mem
            .set_word(self.regs[REG_SP], value)
            .map_err(|e| self.wrap_mem_error(e))
    }

    fn pop(&mut self) -> Result<u16> {
        let value = self
            .mem
            .get_word(self.regs[REG_SP])
            .map_err(|e| self.wrap_mem_error(e))?;
        self.regs[REG_SP] = self.regs[REG_SP].wrapping_add(2);
        Ok(value)
    }

    pub fn perform(&mut self, insn: &Instruction) -> Result<()> {
        use Opcode::*;

        self.last_ops.clear();

        match insn.opcode {
            Rrc(size) | Rra(size) => {
                let mut value = self.read_operand(&insn.operands[0], size)?;

                // ctf seems not to touch the carry bit for Rra
                let c = match insn.opcode {
                    Rrc(_) => (value & 1) != 0,
                    Rra(_) => self.regs.status_c(),
                    _ => unreachable!(),
                };

                let new_msb = match insn.opcode {
                    Rrc(_) => self.regs.status_c(),
                    Rra(_) => (value & size.msb()) != 0,
                    _ => unreachable!(),
                };

                // Try to emulate ctf - ???
                let mut neg = if value == 0x8000 {
                    false
                } else {
                    self.regs.status_n()
                };
                neg |= new_msb;

                value >>= 1;
                if new_msb {
                    value |= size.msb();
                }

                self.write_operand(&insn.operands[0], size, value)?;

                self.regs.set_status_bits(size, value, c, false);
                // zero bit is cleared by ctf. Also overwrite neg with value calculated earlier.
                self.regs[REG_SR] &= !((1 << STATUS_BIT_Z) | (1 << STATUS_BIT_N));
                self.regs[REG_SR] |= u16::from(neg) << STATUS_BIT_N;
            }

            Swpb => {
                let value = self.read_operand(&insn.operands[0], AccessSize::Word)?;
                self.write_operand(
                    &insn.operands[0],
                    AccessSize::Word,
                    (value >> 8) | (value << 8),
                )?;
            }

            Sxt => {
                let mut value = self.read_operand(&insn.operands[0], AccessSize::Byte)?;
                if (value & 0x80) != 0 {
                    value |= 0xff00;
                }

                self.write_operand(&insn.operands[0], AccessSize::Word, value)?;

                self.regs
                    .set_status_bits(AccessSize::Word, value, value != 0, false);
            }

            Push(size) => {
                let value = self.read_operand(&insn.operands[0], size)?;
                self.push(value)?;
            }

            Call => {
                let ret_addr = self.pc();
                self.push(ret_addr)?;

                let dest = self.read_operand(&insn.operands[0], AccessSize::Word)?;
                self.regs[REG_PC] = dest;
            }

            Reti => {
                self.regs[REG_SR] = self.pop()?;
                self.regs[REG_PC] = self.pop()?;
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
                    self.regs[REG_PC] = self.read_operand(&insn.operands[0], AccessSize::Word)?;
                }
            }

            Mov(size) | Add(size) | Addc(size) | Subc(size) | Sub(size) | Cmp(size)
            | Dadd(size) | Bit(size) | Bic(size) | Bis(size) | Xor(size) | And(size) => {
                let opnd1 = self.read_operand(&insn.operands[0], size)?;
                let mut value = opnd1;

                match insn.opcode {
                    Mov(_size) => {}

                    Add(size) | Addc(size) | Sub(size) | Cmp(size) | Subc(size) => {
                        let opnd2 = self.read_operand(&insn.operands[1], size)?;

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

                        let carry = if matches!(insn.opcode, Sub(_) | Cmp(_) | Subc(_)) {
                            opnd2 >= opnd1
                        } else {
                            value32 > 0xffff
                        };

                        // Apparently ctf emulator doesn't set the overflow bit here
                        self.regs.set_status_bits(size, value, carry, false)
                    }

                    Dadd(size) => {
                        fn get_nibble(x: u16, shift: u16) -> u16 {
                            (x >> shift) & 0xf
                        }

                        let opnd2 = self.read_operand(&insn.operands[1], size)?;

                        let num_digits = match size {
                            AccessSize::Byte => 2,
                            AccessSize::Word => 4,
                        };

                        // ctf seems not to touch the negative bit
                        let old_neg = self.regs.status_n();

                        value = 0;
                        // ctf seems to ignore the carry bit
                        // self.regs.status_c().into();
                        let mut carry = 0;
                        for i in 0..num_digits {
                            let shift = 4 * i;

                            let mut sum_digit =
                                get_nibble(opnd1, shift) + get_nibble(opnd2, shift) + carry;

                            if sum_digit >= 10 {
                                sum_digit -= 10;
                                // in case it's >= 16
                                sum_digit &= 0xf;
                                carry = 1;
                            } else {
                                carry = 0;
                            }

                            value |= sum_digit << shift;
                        }

                        self.write_operand(&insn.operands[1], size, value)?;

                        self.regs.set_status_bits(size, value, carry != 0, false);
                        self.regs[REG_SR] &= !(1 << STATUS_BIT_N);
                        self.regs[REG_SR] |= u16::from(old_neg) << STATUS_BIT_N;
                    }

                    Bit(size) | And(size) => {
                        value &= self.read_operand(&insn.operands[1], size)?;

                        self.regs.set_status_bits(size, value, value != 0, false);
                    }

                    Bic(size) => {
                        value = self.read_operand(&insn.operands[1], size)? & !value;
                    }

                    Bis(size) => {
                        value |= self.read_operand(&insn.operands[1], size)?;
                    }

                    Xor(size) => {
                        let opnd2 = self.read_operand(&insn.operands[1], size)?;
                        value ^= opnd2;

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
                    self.write_operand(&insn.operands[1], size, value)?;
                }
            }
        }

        Ok(())
    }

    pub fn next_insn(&self) -> Result<Instruction> {
        // The closure passed to next_insn() expects all the addresses to be aligned.
        // It's enough to just check the beginning of the instruction, because if it's aligned,
        // then all of the instruction's words will be aligned.
        if (self.pc() & 1) != 0 {
            return Err(Error::UnalignedAccess {
                pc: self.pc(),
                addr: self.pc(),
            });
        }

        next_insn(self.pc(), |addr| Some(self.mem.get_word(addr).unwrap())).map_err(|e| match e {
            disasm::Error::BadOpcode { word } => Error::BadOpcode {
                pc: self.pc(),
                word,
            },

            disasm::Error::Eof => unreachable!(),
        })
    }

    pub fn step(&mut self) -> Result<()> {
        self.cur_insn_pc = self.pc();
        let insn = self.next_insn()?;

        // Set next PC before calling perform(). This way any jumps can override the PC, and
        // instructions that need the address of the next instruction (=call) can just read the
        // value of PC.
        self.regs[REG_PC] = self.pc().wrapping_add(insn.byte_size);
        self.perform(&insn)?;

        Ok(())
    }
}

/// Many or all of the tests are testing for the ctf's behavior
#[cfg(test)]
mod tests {
    use super::*;
    use arrayvec::ArrayVec;

    fn do_dadd_test(
        emu: &mut Emulator,
        size: AccessSize,
        a: u16,
        b: u16,
        expected: u16,
        old_sr: u16,
        expected_sr: u16,
    ) {
        println!(
            "Testing dadd {:#x}, {:#x} = {:#x}, SR={:#x}",
            a, b, expected, expected_sr
        );

        // Clear status register to avoid involving carry
        emu.regs[REG_SR] = old_sr;
        emu.regs[14] = a;
        emu.regs[15] = b;
        emu.perform(&Instruction {
            opcode: Opcode::Dadd(size),
            operands: ArrayVec::from([
                Operand::new_direct_register(14),
                Operand::new_direct_register(15),
            ]),
            byte_size: 2,
        })
        .unwrap();

        if emu.regs[15] != expected {
            panic!(
                "dadd test failed, {:#x} + {:#x} should be {:#x}, got {:#x} instead",
                a, b, expected, emu.regs[15]
            );
        }

        assert_eq!(emu.regs[REG_SR], expected_sr);
    }

    #[test]
    fn test_dadd() {
        let mut emu = Emulator::new();
        do_dadd_test(&mut emu, AccessSize::Word, 0x1, 0x1, 0x2, 0, 0);
        do_dadd_test(&mut emu, AccessSize::Word, 0x1, 0x2, 0x3, 0, 0);
        do_dadd_test(&mut emu, AccessSize::Word, 0x2, 0x1, 0x3, 0, 0);
        do_dadd_test(&mut emu, AccessSize::Word, 0x10, 0x10, 0x20, 0, 0);
        do_dadd_test(&mut emu, AccessSize::Word, 0x6540, 0x13c, 0x6682, 0, 0);
        do_dadd_test(&mut emu, AccessSize::Word, 0x160e, 0x04a2, 0x2116, 0, 0);
        do_dadd_test(&mut emu, AccessSize::Word, 0x3c01, 0x0845, 0x4a46, 0, 0);
        do_dadd_test(&mut emu, AccessSize::Word, 0x3c01, 0xdd01, 0x7f02, 0, 1);
        do_dadd_test(&mut emu, AccessSize::Word, 0x3c01, 0x0dd0, 0x4031, 0, 0);
        do_dadd_test(&mut emu, AccessSize::Word, 0xf, 0xf, 0x14, 0, 0);
        do_dadd_test(&mut emu, AccessSize::Word, 0x1858, 0x29a3, 0x4861, 0, 0);
        do_dadd_test(&mut emu, AccessSize::Word, 0x3c01, 0x19e6, 0x5c47, 0, 0);
        do_dadd_test(&mut emu, AccessSize::Word, 0x8000, 0x0, 0x8000, 0, 0);
        do_dadd_test(&mut emu, AccessSize::Word, 0x0, 0x8000, 0x8000, 0, 0);
        // doesn't touch negative bit
        do_dadd_test(&mut emu, AccessSize::Word, 0x0, 0x8000, 0x8000, 4, 4);
        do_dadd_test(&mut emu, AccessSize::Word, 0x3c01, 0x19e6, 0x5c47, 4, 4);
    }

    fn do_sub_test(
        emu: &mut Emulator,
        size: AccessSize,
        a: u16,
        b: u16,
        expected: u16,
        expected_sr: u16,
    ) {
        println!(
            "Testing {:#x} - {:#x} = {:#x}, SR={:#x}",
            a, b, expected, expected_sr
        );
        emu.regs[REG_SR] = 0;
        emu.regs[14] = a;
        emu.perform(&Instruction {
            opcode: Opcode::Sub(size),
            operands: ArrayVec::from([Operand::Immediate(b), Operand::new_direct_register(14)]),
            byte_size: 4,
        })
        .unwrap();
        assert_eq!(emu.regs[14], expected);
        assert_eq!(emu.regs[REG_SR], expected_sr);
    }

    #[test]
    fn test_sub() {
        let mut emu = Emulator::new();
        do_sub_test(&mut emu, AccessSize::Word, 0, 0, 0, 3);
        do_sub_test(&mut emu, AccessSize::Word, 0x1111, 1, 0x1110, 1);
        do_sub_test(&mut emu, AccessSize::Word, 0x1111, 0x10, 0x1101, 1);
        do_sub_test(&mut emu, AccessSize::Word, 0x1111, 0x1000, 0x111, 1);
        do_sub_test(&mut emu, AccessSize::Word, 0x1111, 0x2000, 0xf111, 4);
        do_sub_test(&mut emu, AccessSize::Word, 0x1111, 0x7000, 0xa111, 4);
        do_sub_test(&mut emu, AccessSize::Word, 0x1111, 0x8000, 0x9111, 4);
        do_sub_test(&mut emu, AccessSize::Word, 0xffff, 1, 0xfffe, 5);
        do_sub_test(&mut emu, AccessSize::Word, 0xffff, 0x10, 0xffef, 5);
        do_sub_test(&mut emu, AccessSize::Word, 0xffff, 0x1000, 0xefff, 5);
        do_sub_test(&mut emu, AccessSize::Word, 0xffff, 0xffff, 0, 3);
        do_sub_test(&mut emu, AccessSize::Word, 0xffff, 0xfff0, 0xf, 1);
        do_sub_test(&mut emu, AccessSize::Word, 0xffff, 0x9000, 0x6fff, 1);
        do_sub_test(&mut emu, AccessSize::Word, 0xffff, 0x8010, 0x7fef, 1);
        do_sub_test(&mut emu, AccessSize::Word, 0xffff, 0x8001, 0x7ffe, 1);
        do_sub_test(&mut emu, AccessSize::Word, 0xffff, 0x8000, 0x7fff, 1);
        do_sub_test(&mut emu, AccessSize::Word, 0x8000, 1, 0x7fff, 1);
        do_sub_test(&mut emu, AccessSize::Word, 0x8000, 0x8000, 0, 3);
        do_sub_test(&mut emu, AccessSize::Word, 0x8000, 0x7fff, 1, 1);
        do_sub_test(&mut emu, AccessSize::Word, 0xf216, 0x4d2, 0xed44, 0x5);
        do_sub_test(&mut emu, AccessSize::Word, 0x4582, 0x8000, 0xc582, 0x4);
        do_sub_test(&mut emu, AccessSize::Word, 0x82bc, 0x8000, 0x2bc, 0x1);
    }

    fn do_rot_test(
        emu: &mut Emulator,
        opcode: Opcode,
        x: u16,
        sr: u16,
        expected: u16,
        expected_sr: u16,
    ) {
        println!(
            "Testing {:?}({:#x}) = {:#x}, SR={:#x}",
            opcode, x, expected, expected_sr
        );
        emu.regs[REG_SR] = sr;
        emu.regs[15] = x;
        emu.perform(&Instruction {
            opcode,
            operands: {
                let mut v = ArrayVec::new();
                v.push(Operand::new_direct_register(15));
                v
            },
            byte_size: 4,
        })
        .unwrap();
        assert_eq!(emu.regs[15], expected);
        assert_eq!(emu.regs[REG_SR], expected_sr);
    }

    #[test]
    fn test_rrc() {
        let mut emu = Emulator::new();
        let rrc_w = Opcode::Rrc(AccessSize::Word);
        do_rot_test(&mut emu, rrc_w, 2, 0, 1, 0);
        do_rot_test(&mut emu, rrc_w, 1, 0, 0, 1);
        do_rot_test(&mut emu, rrc_w, 0, 4, 0, 4);
        do_rot_test(&mut emu, rrc_w, 2, 4, 1, 4);
        do_rot_test(&mut emu, rrc_w, 1, 4, 0, 5);
        do_rot_test(&mut emu, rrc_w, 0x100, 0, 0x80, 0);
        do_rot_test(&mut emu, rrc_w, 0x100, 4, 0x80, 4);
        do_rot_test(&mut emu, rrc_w, 0x8001, 4, 0x4000, 5);
        do_rot_test(&mut emu, rrc_w, 0xc9fb, 4, 0x64fd, 5);
        do_rot_test(&mut emu, rrc_w, 0x8100, 4, 0x4080, 4);
        do_rot_test(&mut emu, rrc_w, 0x8100, 0, 0x4080, 0);
        do_rot_test(&mut emu, rrc_w, 0x8000, 4, 0x4000, 0);
        do_rot_test(&mut emu, rrc_w, 0x8000, 0, 0x4000, 0);
        do_rot_test(&mut emu, rrc_w, 0, 1, 0x8000, 4);
        do_rot_test(&mut emu, rrc_w, 0x8000, 1, 0xc000, 4);
        do_rot_test(&mut emu, rrc_w, 0x8001, 1, 0xc000, 5);
        do_rot_test(&mut emu, rrc_w, 0x8000, 5, 0xc000, 4);
        do_rot_test(&mut emu, rrc_w, 0x8001, 5, 0xc000, 5);
        do_rot_test(&mut emu, rrc_w, 0xc9fb, 5, 0xe4fd, 5);
        do_rot_test(&mut emu, rrc_w, 0xc9fb, 1, 0xe4fd, 5);
        do_rot_test(&mut emu, rrc_w, 0xc9fb, 0, 0x64fd, 1);
        do_rot_test(&mut emu, rrc_w, 0x8400, 0, 0x4200, 0);
        do_rot_test(&mut emu, rrc_w, 0x8400, 4, 0x4200, 4);
        do_rot_test(&mut emu, rrc_w, 0xc000, 0, 0x6000, 0);
        do_rot_test(&mut emu, rrc_w, 0xc000, 4, 0x6000, 4);
    }

    #[test]
    fn test_rra() {
        let mut emu = Emulator::new();
        let rra_w = Opcode::Rra(AccessSize::Word);
        do_rot_test(&mut emu, rra_w, 2, 0, 1, 0);
        do_rot_test(&mut emu, rra_w, 1, 0, 0, 0);
        do_rot_test(&mut emu, rra_w, 0, 0, 0, 0);
        do_rot_test(&mut emu, rra_w, 0, 1, 0, 1);
        // zero bit isn't set, but is it cleared? (yes)
        do_rot_test(&mut emu, rra_w, 2, 2, 1, 0);
        do_rot_test(&mut emu, rra_w, 1, 2, 0, 0);
        do_rot_test(&mut emu, rra_w, 0, 2, 0, 0);
    }
}
