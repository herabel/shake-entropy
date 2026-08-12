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

const RESEED_THRESHOLD: usize = 1024 * 1024;
const DOMAIN_SEPARATOR: &str = concat!(
    "shake-entropy-v",
    env!("CARGO_PKG_VERSION"),
    "-domain-separator"
);

use crate::cpu_entropy;
use crate::entropy::EntropyError::{ByteEntropyFailed, OsEntropyFailed, ReseedFailed};
use core::fmt::{Display, Formatter};
use getrandom;
use rand_core::TryRng;
use tiny_keccak::{Hasher, Shake, Xof};
use zeroize::Zeroize;

#[cfg_attr(test, derive(Clone))]
pub struct HardwareEntropyPool {
    state: Shake,
    counter: usize,
    calls_counter: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    OsEntropyFailed,
    ReseedFailed,
    UnsupportedHardware,
    ByteEntropyFailed,
}

impl Display for EntropyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            OsEntropyFailed => write!(f, "OsEntropy failed"),
            ReseedFailed => write!(f, "Reseed failed"),
            EntropyError::UnsupportedHardware => write!(f, "Unsupported hardware"),
            ByteEntropyFailed => write!(f, "Byte entropy failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EntropyError {}

impl Default for HardwareEntropyPool {
    fn default() -> Self {
        Self::new()
    }
}

/// A pool compatible with [rand_core::Rng](https://docs.rs/rand_core/0.10/rand_core/trait.Rng.html), [rand_core::CryptoRng](https://docs.rs/rand_core/0.10/rand_core/trait.CryptoRng.html).
impl HardwareEntropyPool {
    pub fn try_new() -> Result<HardwareEntropyPool, getrandom::Error> {
        let mut hasher = Shake::v256();
        hasher.update(DOMAIN_SEPARATOR.as_ref());

        let mut os_buf = [0u8; 64];
        getrandom::fill(&mut os_buf)?;

        if let Some(mut hard_random_number_rdrand) = cpu_entropy::gen_rdrand(50) {
            hasher.update(&hard_random_number_rdrand.to_le_bytes());
            hard_random_number_rdrand.zeroize();
        }

        if let Some(mut hard_random_number_rdseed) = cpu_entropy::gen_rdseed(50) {
            hasher.update(&hard_random_number_rdseed.to_le_bytes());
            hard_random_number_rdseed.zeroize();
        };

        hasher.update(&os_buf);

        if let Some(mut cycles) = cpu_entropy::get_rdtsc() {
            hasher.update(&cycles.to_le_bytes());
            cycles.zeroize();
        }
        os_buf.zeroize();

        Ok(Self {
            state: hasher,
            counter: 0,
            calls_counter: 0,
        })
    }

    pub fn new() -> Self {
        Self::try_new().expect("Failed to initialize OS entropy source")
    }

    pub fn reseed(&mut self) -> Result<(), EntropyError> {
        let mut new_hasher = Shake::v256();

        new_hasher.update(DOMAIN_SEPARATOR.as_ref());

        let mut old_seed = [0u8; 32];
        self.state.squeeze(&mut old_seed);
        self.state = Shake::v256();
        new_hasher.update(&old_seed);
        old_seed.zeroize();

        let mut os_buf = [0u8; 64];
        getrandom::fill(&mut os_buf).map_err(|_| ReseedFailed)?;

        if let Some(mut hard_random_number_rdrand) = cpu_entropy::gen_rdrand(50) {
            new_hasher.update(&hard_random_number_rdrand.to_le_bytes());
            hard_random_number_rdrand.zeroize();
        }

        if let Some(mut hard_random_number_rdseed) = cpu_entropy::gen_rdseed(50) {
            new_hasher.update(&hard_random_number_rdseed.to_le_bytes());
            hard_random_number_rdseed.zeroize();
        };

        new_hasher.update(&os_buf);

        if let Some(mut cycles) = cpu_entropy::get_rdtsc() {
            new_hasher.update(&cycles.to_le_bytes());
            cycles.zeroize();
        }

        os_buf.zeroize();

        self.state = new_hasher;
        self.counter = 0;
        self.calls_counter = 0;

        Ok(())
    }

    pub fn counter(&self) -> usize {
        self.counter
    }

    pub fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.try_fill_bytes(dst).expect("Failed to fill bytes");
    }
}

impl TryRng for HardwareEntropyPool {
    type Error = EntropyError;

    /// An attempt to create next u32
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut local_array = [0u8; 4];
        TryRng::try_fill_bytes(self, &mut local_array).map_err(|_| ByteEntropyFailed)?;
        let output = u32::from_le_bytes(local_array);
        local_array.zeroize();
        Ok(output)
    }
    /// An attempt to create next u64
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut local_array = [0u8; 8];
        TryRng::try_fill_bytes(self, &mut local_array).map_err(|_| ByteEntropyFailed)?;
        let output = u64::from_le_bytes(local_array);
        local_array.zeroize();
        Ok(output)
    }

    /// An attempt to fill destination with u8 slice
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        if self.counter > RESEED_THRESHOLD || self.calls_counter > 10000 {
            let reseed_success = (0..20).any(|_| self.reseed().is_ok());
            if !reseed_success {
                return Err(ReseedFailed);
            };
        };

        self.state.squeeze(dst);
        self.counter += dst.len();
        self.calls_counter += 1;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for HardwareEntropyPool {}

/// Fills a destination with bytes.
/// If you need to generate a lot of data use [`HardwareEntropyPool`] instead
pub fn fill_random_bytes<S>(dest: &mut S) -> Result<(), EntropyError>
where
    S: ?Sized + AsMut<[u8]>,
{
    let mut pool = HardwareEntropyPool::try_new().map_err(|_| OsEntropyFailed)?;
    pool.try_fill_bytes(dest.as_mut())
}
