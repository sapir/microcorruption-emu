mod disasm;
mod emu;

use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

#[pyclass]
struct Emulator {
    emu: emu::Emulator,
}

#[pymethods]
impl Emulator {
    fn pc(&self) -> u16 {
        self.emu.pc()
    }

    fn get_reg(&self, index: u16) -> u16 {
        self.emu.regs[index]
    }

    fn set_reg(&mut self, index: u16, value: u16) {
        self.emu.regs[index] = value;
    }

    fn get_byte(&self, addr: u16) -> u8 {
        self.emu.mem.get_byte(addr)
    }

    fn get_word(&self, addr: u16) -> u16 {
        // TODO: don't panic
        self.emu.mem.get_word(addr).unwrap()
    }

    fn set_byte(&mut self, addr: u16, value: u8) {
        self.emu.mem.set_byte(addr, value);
    }

    fn set_word(&mut self, addr: u16, value: u16) {
        // TODO: don't panic
        self.emu.mem.set_word(addr, value).unwrap();
    }

    fn next_insn(&self) -> PyResult<String> {
        self.emu
            .next_insn()
            .map(|insn| insn.to_string())
            .map_err(|e| ValueError::py_err(format!("{:?}", e)))
    }

    fn step(&mut self) {
        self.emu.step();
    }
}

#[pyfunction]
fn load(dump_path: &str) -> PyResult<Emulator> {
    Ok(Emulator {
        emu: emu::Emulator::from_dump(dump_path)?,
    })
}

#[pymodule]
fn msp430emu(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Emulator>()?;
    m.add_wrapped(wrap_pyfunction!(load))?;
    Ok(())
}
