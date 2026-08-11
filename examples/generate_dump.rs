use shake_entropy::HardwareEntropyPool;
use std::fs::File;
use std::io::Write;
fn main() {
    let mut pool = HardwareEntropyPool::new();
    let mut file = File::create("entropy.bin").expect("Error creating entropy file");
    let chunk_size = 64 * 1024; // 64 KB
    let total_bytes = 10 * 1024 * 1024; // 10 МB
    let mut buffer = vec![0u8; chunk_size];
    println!("Generating 10MB of entropy");
    let mut written = 0;
    while written < total_bytes {
        pool.fill_bytes(&mut buffer);
        file.write_all(&buffer).unwrap();
        written += chunk_size;
    }
    println!("Successfully generated entropy file");
}