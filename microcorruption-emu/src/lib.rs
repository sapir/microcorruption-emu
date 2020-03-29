pub use microcorruption_emu_core::*;
use rand::Rng;
use std::{collections::HashSet, convert::TryFrom};

const SR_CPUOFF: u16 = 0x10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceState {
    Running,
    WaitingForInput,
    Success,
    Failure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InterruptType {
    Putchar,
    // Getchar = 1
    Gets,
    Dep,
    MarkPage,
    Rand,
    Hsm1,
    Hsm2,
    Deadbolt,
}

impl TryFrom<u16> for InterruptType {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        use InterruptType::*;

        Ok(match value {
            0 => Putchar,
            // 1 => Getchar,
            2 => Gets,
            0x10 => Dep,
            0x11 => MarkPage,
            0x20 => Rand,
            0x7d => Hsm1,
            0x7e => Hsm2,
            0x7f => Deadbolt,
            _ => return Err(()),
        })
    }
}

fn fail_device<E>(_: E) -> DeviceState {
    DeviceState::Failure
}

struct DepState {
    enabled: bool,
    executable_pages: HashSet<u8>,
}

impl DepState {
    fn new() -> Self {
        Self {
            enabled: false,
            executable_pages: (0..=0xff).collect(),
        }
    }

    fn get_page(addr: u16) -> u8 {
        let page = addr >> 8;
        u8::try_from(page).unwrap()
    }

    fn validate_before_stepping(&self, emu: &Emulator) -> Result<(), DeviceState> {
        if self.enabled {
            let cur_page = Self::get_page(emu.pc());
            if !self.executable_pages.contains(&cur_page) {
                return Err(DeviceState::Failure);
            }
        }

        Ok(())
    }

    fn validate_after_stepping(&self, emu: &Emulator) -> Result<(), DeviceState> {
        if self.enabled {
            for op in &emu.last_ops {
                if op.kind == emu::EmulatorOpKind::WriteMem {
                    let page = Self::get_page(op.addr);
                    if self.executable_pages.contains(&page) {
                        return Err(DeviceState::Failure);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Emulator with handling of int 0x10 and success/failure tracking.
pub struct FullEmulator {
    device_state: DeviceState,
    emu: Emulator,
    pop_int_0x10_args: bool,
    dep_state: DepState,
}

impl FullEmulator {
    pub fn new(emu: Emulator, pop_int_0x10_args: bool) -> Self {
        Self {
            device_state: DeviceState::Running,
            emu,
            pop_int_0x10_args,
            dep_state: DepState::new(),
        }
    }

    #[inline]
    pub fn device_state(&self) -> DeviceState {
        self.device_state
    }

    #[inline]
    pub fn emu(&self) -> &Emulator {
        &self.emu
    }

    #[inline]
    pub fn emu_mut(&mut self) -> &mut Emulator {
        &mut self.emu
    }

    fn cur_interrupt_type(&self) -> Option<InterruptType> {
        // high byte of SR (mostly) contains interrupt type
        let mut int_type = self.emu.regs[REG_SR] >> 8;
        int_type &= 0x7F;
        InterruptType::try_from(int_type).ok()
    }

    fn get_interrupt_arg(&self, index: u16) -> Result<u16, DeviceState> {
        let sp = self.emu.regs[REG_SP];
        self.emu
            .mem
            .get_word(sp + 8 + 2 * index)
            .map_err(fail_device)
    }

    fn handle_int_0x10<F>(
        &mut self,
        int_type: InterruptType,
        mut output_callback: F,
    ) -> Result<(), DeviceState>
    where
        F: FnMut(&str),
    {
        match int_type {
            InterruptType::Putchar => {
                let b = self.get_interrupt_arg(0)? as u8;
                if b == b'\n' || b == b' ' || b.is_ascii_graphic() {
                    // We just checked that it's valid utf-8
                    output_callback(std::str::from_utf8(&[b]).unwrap());
                }

                self.ret_from_int_0x10(1)?;
            }

            // Gets is handled specially with the WaitingForInput state
            InterruptType::Gets => unreachable!(),

            InterruptType::Rand => {
                let mut rng = rand::thread_rng();
                self.emu.regs[15] = rng.gen();
                self.ret_from_int_0x10(0)?;
            }

            // No point in ret_from_int_0x10 here, the device is now off
            InterruptType::Deadbolt => return Err(DeviceState::Success),

            InterruptType::Hsm1 => {
                // Don't actually need to do anything here.
                // Pretend the password is always wrong.
                // let password_ptr = self.get_interrupt_arg(0)?;
                // let out_ptr = self.get_interrupt_arg(1)?;
                // self.emu.mem.set_byte(out_ptr, 1).map_err(fail_device)?;
                self.ret_from_int_0x10(2)?;
            }

            InterruptType::Hsm2 => {
                // Don't actually need to do anything here.
                // Pretend the password is always wrong.
                // let password_ptr = self.get_interrupt_arg(0)?;
                self.ret_from_int_0x10(1)?;
            }

            InterruptType::Dep => {
                self.dep_state.enabled = true;
                self.ret_from_int_0x10(0)?;
            }

            InterruptType::MarkPage => {
                let page = self.get_interrupt_arg(0)?;
                let writable = self.get_interrupt_arg(1)?;
                // manual says 0 or 1, but assume that non-zero is ok
                let writable = writable != 0;
                let executable = !writable;

                let page = u8::try_from(page).map_err(|_| DeviceState::Failure)?;

                if executable {
                    self.dep_state.executable_pages.insert(page);
                } else {
                    self.dep_state.executable_pages.remove(&page);
                }

                self.ret_from_int_0x10(2)?;
            }
        }

        Ok(())
    }

    fn ret_from_int_0x10(&mut self, num_args: u16) -> Result<(), DeviceState> {
        let ret_addr = self
            .emu
            .mem
            .get_word(self.emu.regs[REG_SP])
            .map_err(fail_device)?;

        // Pop the return address
        let mut pop_size = 2;
        if self.pop_int_0x10_args {
            pop_size += num_args * 2;
        }

        self.emu.regs[REG_SP] += pop_size;
        self.emu.regs[REG_PC] = ret_addr;
        Ok(())
    }

    fn parse_input<F>(
        &mut self,
        input: &str,
        mut output_callback: F,
    ) -> Result<Vec<u8>, DeviceState>
    where
        F: FnMut(&str),
    {
        if input.starts_with("0x") {
            // Skip 0x prefix, remove any spaces
            let input = input[2..].replace(" ", "");

            match hex::decode(input) {
                Ok(buf) => Ok(buf),

                Err(_) => {
                    output_callback("\n(please input hex bytes as 0x1234...)\n");
                    return Err(DeviceState::WaitingForInput);
                }
            }
        } else {
            Ok(input.into())
        }
    }

    fn do_finish_gets<F>(
        &mut self,
        input: &str,
        output_callback: F,
    ) -> Result<DeviceState, DeviceState>
    where
        F: FnMut(&str),
    {
        let ptr = self.get_interrupt_arg(0).map_err(fail_device)?;
        let maxlen = self.get_interrupt_arg(1).map_err(fail_device)?;

        let input = self.parse_input(input, output_callback)?;

        for (i, b) in input
            .iter()
            .take(usize::from(maxlen))
            .chain(std::iter::once(&0))
            .enumerate()
        {
            self.emu.mem.set_byte(ptr + u16::try_from(i).unwrap(), *b);
        }

        self.ret_from_int_0x10(2).map_err(fail_device)?;

        Ok(DeviceState::Running)
    }

    /// See step() for what to do with the return value.
    #[must_use]
    pub fn finish_gets<F>(&mut self, input: &str, output_callback: F) -> DeviceState
    where
        F: FnMut(&str),
    {
        self.device_state = self
            .do_finish_gets(input, output_callback)
            .unwrap_or_else(|e| e);
        self.device_state
    }

    fn do_step<F>(&mut self, output_callback: F) -> Result<DeviceState, DeviceState>
    where
        F: FnMut(&str),
    {
        assert_eq!(self.device_state, DeviceState::Running);

        if self.emu.pc() == 0x10 {
            match self.cur_interrupt_type() {
                Some(InterruptType::Gets) => return Ok(DeviceState::WaitingForInput),

                Some(int_type) => {
                    self.handle_int_0x10(int_type, output_callback)?;
                    return Ok(DeviceState::Running);
                }

                _ => return Err(DeviceState::Failure),
            }
        }

        self.dep_state.validate_before_stepping(&self.emu)?;

        self.emu.step().map_err(fail_device)?;

        self.dep_state.validate_after_stepping(&self.emu)?;

        if (self.emu.regs[REG_SR] & SR_CPUOFF) != 0 {
            return Err(DeviceState::Failure);
        }

        Ok(DeviceState::Running)
    }

    /// If this returns WaitingForInput, then finish_gets() must be called before calling step()
    /// again.
    /// If this returns Success or Failure, then step() must not be called again.
    ///
    /// The return value can also be accessed as device_state().
    #[must_use]
    pub fn step<F>(&mut self, output_callback: F) -> DeviceState
    where
        F: FnMut(&str),
    {
        self.device_state = self.do_step(output_callback).unwrap_or_else(|e| e);
        self.device_state
    }
}
