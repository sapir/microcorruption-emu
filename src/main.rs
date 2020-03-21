mod disasm;
mod emu;

fn main() {
    let mut emu = emu::Emulator::new();
    emu.step();
}
