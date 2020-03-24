mod disasm;
mod emu;

#[cfg(not(test))]
mod pymod {
    use super::*;
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

                    hm.insert("addr", op.addr.into_py(py));
                    hm.insert("value", op.value.into_py(py));

                    hm.into_py(py)
                })
                .collect::<Vec<_>>())
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
}
