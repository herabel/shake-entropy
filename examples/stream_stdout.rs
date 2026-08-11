use shake_entropy::HardwareEntropyPool;
use std::io::{stdout, Write};
fn main() {
    let mut pool = HardwareEntropyPool::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut out = stdout().lock();
    loop {
        pool.fill_bytes(&mut buffer);
        if out.write_all(&buffer).is_err() {
            break;
        }
    }
}