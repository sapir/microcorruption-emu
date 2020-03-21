use super::disasm::{next_insn, AccessSize, Instruction, Opcode, Operand, RegisterMode, REG_PC};
use std::convert::TryInto;

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

    pub fn get_byte(&self, addr: u16) -> u8 {
        self.data[usize::from(addr)]
    }

    pub fn get_word(&self, addr: u16) -> Result<u16, Error> {
        if (addr & 1) != 0 {
            return Err(Error::UnalignedAccess { addr });
        }

        Ok(u16::from_le_bytes(
            self.data[usize::from(addr)..usize::from(addr + 2)]
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
        self.data[usize::from(addr + 1)] = (value >> 8).try_into().unwrap();

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

pub struct Emulator {
    pub regs: [u16; 16],
    pub mem: Memory,
}

impl Emulator {
    pub fn new() -> Self {
        Self {
            regs: [0; 16],
            mem: Memory::new(),
        }
    }

    pub fn pc(&self) -> u16 {
        self.regs[usize::from(REG_PC)]
    }

    fn read_operand(&mut self, operand: &Operand, size: AccessSize) -> u16 {
        match operand {
            Operand::Register {
                reg,
                mode,
                increment,
            } => {
                let value = self.regs[usize::from(*reg)];

                let value = match mode {
                    RegisterMode::Direct => value,
                    RegisterMode::Indirect => self.mem.get(value, size).unwrap(),
                };

                if *increment {
                    self.regs[usize::from(*reg)] += match size {
                        AccessSize::Byte => 1,
                        AccessSize::Word => 2,
                    };
                }

                value
            }

            Operand::Indexed { reg, offset } => {
                let mut addr = self.regs[usize::from(*reg)];
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

                let reg = usize::from(*reg);

                match mode {
                    RegisterMode::Direct => {
                        if size == AccessSize::Byte {
                            assert_eq!(value, value & 0xff);
                        }

                        self.regs[reg] = value;
                    }

                    RegisterMode::Indirect => self.mem.set(self.regs[reg], size, value).unwrap(),
                }
            }

            Operand::Indexed { reg, offset } => {
                let mut addr = self.regs[usize::from(*reg)];
                addr = addr.wrapping_add(*offset as u16);
                self.mem.set(addr, size, value).unwrap()
            }

            Operand::Immediate(_) | Operand::Absolute(_) => unreachable!(),
        }
    }

    pub fn perform(&mut self, insn: &Instruction) {
        use Opcode::*;

        match insn.opcode {
            Rrc(size) => todo!(),

            Swpb => {
                let value = self.read_operand(&insn.operands[0], AccessSize::Word);
                self.write_operand(
                    &insn.operands[0],
                    AccessSize::Word,
                    (value >> 8) | (value << 8),
                );
            }

            Rra(size) => todo!(),

            Sxt => {
                let mut value = self.read_operand(&insn.operands[0], AccessSize::Byte);
                if (value & 0x80) != 0 {
                    value |= 0xff00;
                }
                self.write_operand(&insn.operands[0], AccessSize::Word, value);
            }

            Push(size) => todo!(),
            Call => todo!(),
            Reti => todo!(),

            Jne => todo!(),
            Jeq => todo!(),
            Jnc => todo!(),
            Jc => todo!(),
            Jn => todo!(),
            Jge => todo!(),
            Jl => todo!(),
            Jmp => todo!(),

            Mov(size) | Add(size) | Addc(size) | Subc(size) | Sub(size) | Cmp(size)
            | Dadd(size) | Bit(size) | Bic(size) | Bis(size) | Xor(size) | And(size) => {
                let mut value = self.read_operand(&insn.operands[0], size);

                match insn.opcode {
                    Mov(_size) => {}

                    Add(size) => {
                        value = self
                            .read_operand(&insn.operands[1], size)
                            .wrapping_add(value);
                    }

                    Addc(size) => {
                        todo!();
                    }

                    Subc(size) => {
                        todo!();
                    }

                    Sub(size) | Cmp(size) => {
                        value = self
                            .read_operand(&insn.operands[1], size)
                            .wrapping_sub(value);
                    }

                    Dadd(size) => {
                        todo!();
                    }

                    Bit(size) | And(size) => {
                        value &= self.read_operand(&insn.operands[1], size);
                    }

                    Bic(size) => {
                        value = self.read_operand(&insn.operands[1], size) & !value;
                    }

                    Bis(size) => {
                        value = self.read_operand(&insn.operands[1], size) | value;
                    }

                    Xor(size) => {
                        value = self.read_operand(&insn.operands[1], size) ^ value;
                    }

                    _ => unreachable!(),
                }

                // TODO: flags

                if !matches!(insn.opcode, Cmp(_size) | Bit(_size)) {
                    self.write_operand(&insn.operands[1], size, value);
                }
            }
        }
    }

    pub fn step(&mut self) {
        let insn = next_insn(self.pc(), |addr| Some(self.mem.get_word(addr).unwrap())).unwrap();
        self.perform(&insn);
    }
}
