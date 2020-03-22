use arrayvec::ArrayVec;
use std::convert::TryInto;
use std::fmt::Display;

#[derive(Clone, Debug)]
pub enum Error {
    Eof,
    BadOpcode { word: u16 },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessSize {
    Byte,
    Word,
}

impl AccessSize {
    pub fn msb(self) -> u16 {
        match self {
            AccessSize::Byte => 0x80,
            AccessSize::Word => 0x8000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressingMode {
    Direct,
    Indexed,
    Indirect,
    IndirectAutoincrement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    Rrc(AccessSize),
    Swpb,
    Rra(AccessSize),
    Sxt,
    Push(AccessSize),
    Call,
    Reti,
    Jne,
    Jeq,
    Jnc,
    Jc,
    Jn,
    Jge,
    Jl,
    Jmp,
    Mov(AccessSize),
    Add(AccessSize),
    Addc(AccessSize),
    Subc(AccessSize),
    Sub(AccessSize),
    Cmp(AccessSize),
    Dadd(AccessSize),
    Bit(AccessSize),
    Bic(AccessSize),
    Bis(AccessSize),
    Xor(AccessSize),
    And(AccessSize),
}

impl Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use AccessSize::*;
        use Opcode::*;

        write!(
            f,
            "{}",
            match self {
                Rrc(Byte) => "rrc.b",
                Rrc(Word) => "rrc.w",
                Swpb => "swpb",
                Rra(Byte) => "rra.b",
                Rra(Word) => "rra.w",
                Sxt => "sxt",
                Push(Byte) => "push.b",
                Push(Word) => "push",
                Call => "call",
                Reti => "reti",
                Jne => "jne",
                Jeq => "jeq",
                Jnc => "jnc",
                Jc => "jc",
                Jn => "jn",
                Jge => "jge",
                Jl => "jl",
                Jmp => "jmp",
                Mov(Byte) => "mov.b",
                Mov(Word) => "mov",
                Add(Byte) => "add.b",
                Add(Word) => "add",
                Addc(Byte) => "addc.b",
                Addc(Word) => "addc",
                Subc(Byte) => "subc.b",
                Subc(Word) => "subc",
                Sub(Byte) => "sub.b",
                Sub(Word) => "sub",
                Cmp(Byte) => "cmp.b",
                Cmp(Word) => "cmp",
                Dadd(Byte) => "dadd.b",
                Dadd(Word) => "dadd",
                Bit(Byte) => "bit.b",
                Bit(Word) => "bit",
                Bic(Byte) => "bic.b",
                Bic(Word) => "bic",
                Bis(Byte) => "bis.b",
                Bis(Word) => "bis",
                Xor(Byte) => "xor.b",
                Xor(Word) => "xor",
                And(Byte) => "and.b",
                And(Word) => "and",
            }
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterMode {
    Direct,
    Indirect,
}

pub const REG_PC: u16 = 0;
pub const REG_SP: u16 = 1;
pub const REG_SR: u16 = 2;
pub const REG_CG: u16 = 3;

#[derive(Clone, Debug, PartialEq)]
pub enum Operand {
    Register {
        reg: u16,
        mode: RegisterMode,
        increment: bool,
    },

    Indexed {
        reg: u16,
        offset: i16,
    },

    Immediate(u16),

    Absolute(u16),
}

impl Operand {
    /// Returns operand and byte size
    fn with_reg<F>(
        addr: u16,
        reg: u16,
        mode: AddressingMode,
        is_src: bool,
        mut next_word: F,
    ) -> Result<(Self, u16)>
    where
        F: FnMut() -> Option<u16>,
    {
        if is_src {
            match (reg, mode) {
                (REG_PC, AddressingMode::Indexed) => {
                    // Relative to PC, but PC is known, convert to absolute
                    return Ok((
                        Operand::Absolute(addr.wrapping_add(next_word().ok_or(Error::Eof)?)),
                        2,
                    ));
                }

                (REG_PC, AddressingMode::IndirectAutoincrement) => {
                    // Autoincrement PC = get next word
                    return Ok((Operand::Immediate(next_word().ok_or(Error::Eof)?), 2));
                }

                (REG_SR, AddressingMode::Indexed) => {
                    // Pretend SR is 0
                    return Ok((Operand::Absolute(next_word().ok_or(Error::Eof)?), 2));
                }

                (REG_SR, AddressingMode::Indirect) => {
                    return Ok((Operand::Immediate(4), 0));
                }

                (REG_SR, AddressingMode::IndirectAutoincrement) => {
                    return Ok((Operand::Immediate(8), 0));
                }

                (REG_CG, AddressingMode::Direct) => {
                    return Ok((Operand::Immediate(0), 0));
                }

                (REG_CG, AddressingMode::Indexed) => {
                    return Ok((Operand::Immediate(1), 0));
                }

                (REG_CG, AddressingMode::Indirect) => {
                    return Ok((Operand::Immediate(2), 0));
                }

                (REG_CG, AddressingMode::IndirectAutoincrement) => {
                    return Ok((Operand::Immediate(0xffff), 0));
                }

                _ => {}
            }
        }

        Ok(match mode {
            AddressingMode::Direct => (
                Operand::Register {
                    reg,
                    mode: RegisterMode::Direct,
                    increment: false,
                },
                0,
            ),

            AddressingMode::Indexed => (
                Operand::Indexed {
                    reg,
                    offset: next_word().ok_or(Error::Eof)? as i16,
                },
                2,
            ),

            AddressingMode::Indirect | AddressingMode::IndirectAutoincrement => (
                Operand::Register {
                    reg,
                    mode: RegisterMode::Indirect,
                    increment: mode == AddressingMode::IndirectAutoincrement,
                },
                0,
            ),
        })
    }
}

fn fmt_reg(f: &mut std::fmt::Formatter, reg: u16) -> std::fmt::Result {
    match reg {
        REG_PC => write!(f, "PC"),
        REG_SP => write!(f, "SP"),
        REG_SR => write!(f, "SR"),
        REG_CG => write!(f, "CG"),
        _ => write!(f, "R{}", reg),
    }
}

impl Display for Operand {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            &Operand::Register {
                reg,
                mode,
                increment,
            } => {
                match mode {
                    RegisterMode::Direct => {}
                    RegisterMode::Indirect => write!(f, "@")?,
                }

                fmt_reg(f, reg)?;

                if increment {
                    write!(f, "+")?;
                }

                Ok(())
            }

            &Operand::Indexed { reg, offset } => {
                write!(f, "{:#x}(", offset)?;
                fmt_reg(f, reg)?;
                write!(f, ")")
            }

            &Operand::Immediate(x) => write!(f, "#{:#x}", x),

            &Operand::Absolute(x) => write!(f, "&{:#x}", x),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Instruction {
    pub opcode: Opcode,
    pub operands: ArrayVec<[Operand; 2]>,
    pub byte_size: u16,
}

impl Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.opcode)?;

        if let Some(opnd) = self.operands.get(0) {
            write!(f, " ")?;
            opnd.fmt(f)?;
        }

        if let Some(opnd) = self.operands.get(1) {
            write!(f, ", ")?;
            opnd.fmt(f)?;
        }

        Ok(())
    }
}

pub fn next_insn<F>(mut addr: u16, mut get_word: F) -> Result<Instruction>
where
    F: FnMut(u16) -> Option<u16>,
{
    let addr0 = addr;
    let mut next_word = {
        let addr = &mut addr;
        move || {
            let w = get_word(*addr)?;
            *addr += 2;
            Some(w)
        }
    };

    let word = next_word().ok_or(Error::Eof)?;
    let mut byte_size = 2;

    // when relevant
    let size = match (word >> 6) & 1 {
        0 => AccessSize::Word,
        1 => AccessSize::Byte,
        _ => unreachable!(),
    };

    let src_mode = match (word >> 4) & 0b11 {
        0b00 => AddressingMode::Direct,
        0b01 => AddressingMode::Indexed,
        0b10 => AddressingMode::Indirect,
        0b11 => AddressingMode::IndirectAutoincrement,
        _ => unreachable!(),
    };

    if (word >> 13) == 0b000 {
        if (word >> 10) != 0b000100 {
            return Err(Error::BadOpcode { word });
        }

        let opcode = match (word >> 7) & 0b111 {
            0b000 => Opcode::Rrc(size),
            0b001 => Opcode::Swpb,
            0b010 => Opcode::Rra(size),
            0b011 => Opcode::Sxt,
            0b100 => Opcode::Push(size),
            0b101 => Opcode::Call,
            0b110 => Opcode::Reti,
            _ => return Err(Error::BadOpcode { word }),
        };

        if opcode == Opcode::Reti {
            if word != 0b0001_0011_0000_0000 {
                return Err(Error::BadOpcode { word });
            }

            return Ok(Instruction {
                opcode,
                operands: ArrayVec::new(),
                byte_size,
            });
        }

        if matches!(opcode, Opcode::Swpb | Opcode::Sxt | Opcode::Call) && size != AccessSize::Byte {
            return Err(Error::BadOpcode { word });
        }

        let reg = word & 0xf;
        let (operand, opnd_size) = Operand::with_reg(addr0, reg, src_mode, true, next_word)?;
        byte_size += opnd_size;
        let mut operands = ArrayVec::new();
        operands.push(operand);

        Ok(Instruction {
            opcode,
            operands,
            byte_size,
        })
    } else if (word >> 13) == 0b001 {
        let opcode = match (word >> 10) & 0b111 {
            0b000 => Opcode::Jne,
            0b001 => Opcode::Jeq,
            0b010 => Opcode::Jnc,
            0b011 => Opcode::Jc,
            0b100 => Opcode::Jn,
            0b101 => Opcode::Jge,
            0b110 => Opcode::Jl,
            0b111 => Opcode::Jmp,
            _ => unreachable!(),
        };

        // Sign-extend 10-bit to 16-bit
        let mut dest: i16 = (word & 0x3ff).try_into().unwrap();
        if (dest & 0x200) != 0 {
            dest -= 0x400;
        }

        // Convert to address
        dest *= 2;
        let dest = addr.wrapping_add(dest as u16);

        let mut operands = ArrayVec::new();
        operands.push(Operand::Immediate(dest));

        Ok(Instruction {
            opcode,
            operands,
            byte_size,
        })
    } else {
        let mut operands = ArrayVec::new();

        let src_reg = (word >> 8) & 0xf;
        let (src, opnd_size) = Operand::with_reg(addr0, src_reg, src_mode, true, &mut next_word)?;
        operands.push(src);
        byte_size += opnd_size;

        let dst_reg = word & 0xf;
        let dst_mode = match (word >> 7) & 1 {
            0 => AddressingMode::Direct,
            1 => AddressingMode::Indexed,
            _ => unreachable!(),
        };
        let (dst, opnd_size) = Operand::with_reg(addr0, dst_reg, dst_mode, false, next_word)?;
        operands.push(dst);
        byte_size += opnd_size;

        let opcode = match word >> 12 {
            0b0100 => Opcode::Mov(size),
            0b0101 => Opcode::Add(size),
            0b0110 => Opcode::Addc(size),
            0b0111 => Opcode::Subc(size),
            0b1000 => Opcode::Sub(size),
            0b1001 => Opcode::Cmp(size),
            0b1010 => Opcode::Dadd(size),
            0b1011 => Opcode::Bit(size),
            0b1100 => Opcode::Bic(size),
            0b1101 => Opcode::Bis(size),
            0b1110 => Opcode::Xor(size),
            0b1111 => Opcode::And(size),
            _ => unreachable!(),
        };

        Ok(Instruction {
            opcode,
            operands,
            byte_size,
        })
    }
}

#[cfg(test)]
pub fn disasm(mut addr: u16, buf: &[u8]) -> Result<Vec<Instruction>> {
    let mut get_word = move |at: u16| {
        let index = usize::from(at.wrapping_sub(addr));
        Some((u16::from(*buf.get(index + 1)?) << 8) | u16::from(*buf.get(index)?))
    };

    let end_addr = addr.wrapping_add(buf.len() as u16);

    let mut insns = vec![];
    loop {
        let insn = next_insn(addr, &mut get_word);
        if let &Err(Error::Eof) = &insn {
            if addr == end_addr {
                break;
            }
        }

        let insn = insn?;

        addr += insn.byte_size;
        insns.push(insn);
    }

    Ok(insns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ret() {
        // ret is mov @sp+, pc
        assert_eq!(
            &*disasm(0x0010, b"\x30\x41").unwrap(),
            &[Instruction {
                opcode: Opcode::Mov(AccessSize::Word),
                operands: ArrayVec::from([
                    Operand::Register {
                        reg: REG_SP,
                        mode: RegisterMode::Indirect,
                        increment: true
                    },
                    Operand::Register {
                        reg: REG_PC,
                        mode: RegisterMode::Direct,
                        increment: false
                    }
                ]),
                byte_size: 2
            }][..]
        );
    }
}
