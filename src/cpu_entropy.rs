/// Loops to gather entropy from [`try_rdseed`]. Returns `None` if the attempt is blank.
pub fn gen_rdseed(loop_amount: u16) -> Option<u64> {
    for _ in 0..loop_amount {
        let attempt = try_rdseed();
        if attempt.is_some() {
            return attempt;
        }
        core::hint::spin_loop();
    }
    None
}

/// Loops to gather entropy from [`try_rdrand`]. Returns `None` if the output is blank.
pub fn gen_rdrand(loop_amount: u16) -> Option<u64> {
    for _ in 0..loop_amount {
        let attempt = try_rdrand();
        if attempt.is_some() {
            return attempt;
        }
        core::hint::spin_loop();
    }
    None
}

/// Queries the hardware `RDSEED` processor register.
///
/// Returns `None` if the operation status is 0 or the feature is unsupported by the CPU.
#[cfg(target_arch = "x86_64")]
pub fn try_rdseed() -> Option<u64> {
    #[cfg(feature = "std")]
    if is_x86_feature_detected!("rdseed") {
        unsafe {
            let mut val: u64 = 0;
            let status: i32 = core::arch::x86_64::_rdseed64_step(&mut val);
            if status == 1 { Some(val) } else { None }
        }
    } else {
        None
    }

    // RDSEED fallback for no_std
    #[cfg(not(feature = "std"))]
    {
        unsafe {
            let mut val: u64 = 0;
            if core::arch::x86_64::_rdseed64_step(&mut val) == 1 {
                Some(val)
            } else {
                None
            }
        }
    }
}

/// Queries the hardware `RDRAND` processor register.
///
/// Returns `None` if the operation status is 0 or the feature is unsupported by the CPU.
#[cfg(target_arch = "x86_64")]
pub fn try_rdrand() -> Option<u64> {
    #[cfg(feature = "std")]
    if is_x86_feature_detected!("rdrand") {
        unsafe {
            let mut val: u64 = 0;
            let status: i32 = core::arch::x86_64::_rdrand64_step(&mut val);
            if status == 1 { Some(val) } else { None }
        }
    } else {
        None
    }

    // RDRAND fallback for no_std
    #[cfg(not(feature = "std"))]
    {
        unsafe {
            let mut val: u64 = 0;
            if core::arch::x86_64::_rdrand64_step(&mut val) == 1 {
                Some(val)
            } else {
                None
            }
        }
    }
}

/// A `try_rdseed` fallback for non x86_64 arch
#[cfg(not(target_arch = "x86_64"))]
pub fn try_rdseed() -> Option<u64> {
    None
}
/// A `try_rdrand` fallback for non x86_64 arch
#[cfg(not(target_arch = "x86_64"))]
pub fn try_rdrand() -> Option<u64> {
    None
}

pub fn get_rdtsc() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        return Some(unsafe { core::arch::x86_64::_rdtsc() });
    }
    #[cfg(target_arch = "x86")]
    {
        return Some(unsafe { core::arch::x86::_rdtsc() });
    }
    #[allow(unreachable_code)]
    None
}
