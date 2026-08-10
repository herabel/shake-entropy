//! Entropy generation source leveraging CPU hardware jitter/instructions.
//! 
//! This module provides a Deterministic Random Bit Generator (DRBG)
//! backed by [`cpu_entropy`].
//! 
//! ### Traits
//! - Implements [rand_core::TryRng](https://docs.rs/rand_core/0.10/rand_core/trait.TryRng.html) (v0.10) for fallible entropy retrieval.
//! 
//! ### Security note
//! Uses direct CPU instructions. Ensure the target architecture supports
//! the necessary features (`rdrand`, `rdseed` via [`cpu_entropy`]) before deployment.

const RESEED_THRESHOLD: usize = 1024*1024;
const DOMAIN_SEPARATOR: &str = concat!("shake-entropy-v", env!("CARGO_PKG_VERSION"), "-domain-separator");

use getrandom;
use rand_core::{TryRng};
use tiny_keccak::{Hasher, Shake, Xof};
use crate::cpu_entropy;
use zeroize::Zeroize;

pub struct HardwareEntropyPool{
    state: tiny_keccak::Shake,
    counter: usize,
}

impl Default for HardwareEntropyPool {
    fn default() -> Self {
        Self::new()
    }
}

/// A pool compatible with [rand_core::Rng](https://docs.rs/rand_core/0.10/rand_core/trait.Rng.html), [rand_core::CryptoRng](https://docs.rs/rand_core/0.10/rand_core/trait.CryptoRng.html).
impl HardwareEntropyPool {
    pub fn try_new() -> Result<HardwareEntropyPool, getrandom::Error> {

        let mut hasher= Shake::v256();
        hasher.update(DOMAIN_SEPARATOR.as_ref());

        let mut os_buf = [0u8; 64];
        getrandom::fill(&mut os_buf)?;

        if let Some(mut hard_random_number_rdrand)  = cpu_entropy::gen_rdrand(50){
            hasher.update(&hard_random_number_rdrand.to_le_bytes());
            hard_random_number_rdrand.zeroize();
        }
        

        if let Some(mut hard_random_number_rdseed) = cpu_entropy::gen_rdseed(50){
            hasher.update(&hard_random_number_rdseed.to_le_bytes());
            hard_random_number_rdseed.zeroize();
        };

        hasher.update(&os_buf);

        os_buf.zeroize();

        Ok ( Self { state: (hasher), counter: (0) } )
    }

    pub fn new() -> Self {
        Self::try_new().expect("Failed to initialize OS entropy source")
    }

    pub fn reseed(&mut self) -> Result<(), getrandom::Error> {
        let mut new_hasher = Shake::v256();

        new_hasher.update(DOMAIN_SEPARATOR.as_ref());

        let mut old_seed = [0u8; 32];
        self.state.squeeze(&mut old_seed);
        self.state = Shake::v256();
        new_hasher.update(&old_seed);
        old_seed.zeroize();

        let mut os_buf = [0u8; 64];
        getrandom::fill(&mut os_buf)?;

        if let Some(mut hard_random_number_rdrand)  = cpu_entropy::gen_rdrand(50){
            new_hasher.update(&hard_random_number_rdrand.to_le_bytes());
            hard_random_number_rdrand.zeroize();
        }


        if let Some(mut hard_random_number_rdseed) = cpu_entropy::gen_rdseed(50){
            new_hasher.update(&hard_random_number_rdseed.to_le_bytes());
            hard_random_number_rdseed.zeroize();
        };

        new_hasher.update(&os_buf);

        os_buf.zeroize();

        self.state = new_hasher;
        self.counter = 0;

        Ok(())
    }

    pub fn counter(&self) -> usize {
        self.counter
    }

}

impl rand_core::TryRng for HardwareEntropyPool{
    type Error = core::convert::Infallible;

    /// An attempt to create next u32
    fn try_next_u32(&mut self) -> Result<u32,Self::Error> {
        let mut local_array = [0u8;4];
        let _ = rand_core::TryRng::try_fill_bytes(self, &mut local_array);
        let output = u32::from_le_bytes(local_array);
        local_array.zeroize();
        Ok(output)
    }
    /// An attempt to create next u64
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut local_array = [0u8;8];
        let _ = rand_core::TryRng::try_fill_bytes(self, &mut local_array);
        let output = u64::from_le_bytes(local_array);
        local_array.zeroize();
        Ok(output)
    }

    /// An attempt to fill destination with u8 slice
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        if self.counter > RESEED_THRESHOLD {
            let reseed_success = (0..20).any(|_| self.reseed().is_ok());
            if !reseed_success {
                panic!("Fatal error: OS entropy reseed failed after 20 attempts!");
            };
        };

        self.state.squeeze(dst);
        self.counter += dst.len();
        Ok(())
    }
}

impl rand_core::TryCryptoRng for HardwareEntropyPool {}

/// Fills a destination with bytes.
/// If you need to generate a lot of data use [`HardwareEntropyPool`] instead
pub fn fill_random_bytes<S>(dest: &mut S)
where
    S: ?Sized + AsMut<[u8]>,
{
    let mut pool = HardwareEntropyPool::new();
    let _ = pool.try_fill_bytes(dest.as_mut());
}