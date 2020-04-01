use microcorruption_emu::*;
use pyo3::exceptions::{Exception, ValueError};
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

    fn step(&mut self) -> PyResult<()> {
        self.emu
            .step()
            .map_err(|e| Exception::py_err(format!("{:?}", e)))
    }

    fn last_ops(&self) -> PyResult<Vec<PyObject>> {
        let gil = Python::acquire_gil();
        let py = gil.python();

        Ok(self
            .emu
            .last_ops
            .iter()
            .map(|op| {
                use emu::EmulatorOpKind::*;
                use std::collections::HashMap;

                let mut hm: HashMap<&str, PyObject> = HashMap::new();

                hm.insert("type", {
                    let s = match op.kind {
                        ReadReg => "read_reg",
                        WriteReg => "write_reg",
                        ReadMem => "read_mem",
                        WriteMem => "write_mem",
                    };
                    s.into_py(py)
                });

                hm.insert("size", {
                    let s = match op.size {
                        disasm::AccessSize::Byte => "byte",
                        disasm::AccessSize::Word => "word",
                    };
                    s.into_py(py)
                });

                hm.insert("addr", op.addr.into_py(py));
                hm.insert("value", op.value.into_py(py));

                hm.into_py(py)
            })
            .collect::<Vec<_>>())
    }
}

#[pyfunction]
fn load_dump_file(dump_path: &str) -> PyResult<Emulator> {
    match emu::Emulator::from_dump_file(dump_path) {
        Ok(emu) => Ok(Emulator { emu }),

        Err(LoadError::BadDumpLength(size)) => Err(ValueError::py_err(format!(
            "Bad memory dump length {}, must be 65536",
            size
        ))),

        Err(LoadError::IO(e)) => Err(e.into()),
    }
}

fn disasm_err_to_py(err: disasm::Error) -> PyErr {
    use disasm::Error::*;

    match err {
        Eof => ValueError::py_err("EOF during disassembly - Buffer contains truncated instruction"),

        BadOpcode { word } => ValueError::py_err(format!("Bad instruction word {:#06x}", word)),
    }
}

#[pyfunction]
fn disasm(addr: u16, buf: &[u8]) -> PyResult<Vec<String>> {
    let insns = disasm::disasm(addr, buf).map_err(disasm_err_to_py)?;

    Ok(insns.into_iter().map(|insn| insn.to_string()).collect())
}

#[pymodule]
fn pyucorremu(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Emulator>()?;
    m.add_wrapped(wrap_pyfunction!(load_dump_file))?;
    m.add_wrapped(wrap_pyfunction!(disasm))?;
    Ok(())
}
