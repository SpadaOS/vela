//! 时钟子系统（PLAN-0.1.0 T5.1）：clock_gettime / gettimeofday。

use vela_abi as abi;
use vela_sys::Host;

use crate::{write_guest, GuestProcess};

pub(super) fn sys_clock_gettime(proc: &GuestProcess, host: &dyn Host, clk: u64, tp: u64) -> i64 {
    let (secs, nsecs) = match clk {
        abi::CLOCK_REALTIME => {
            let (s, ns) = host.realtime();
            (s as u64, ns as u64)
        }
        // MONOTONIC_RAW/BOOTTIME 语义子集：统一映射宿主单调时钟（PLAN T2.7）
        abi::CLOCK_MONOTONIC | abi::CLOCK_MONOTONIC_RAW | abi::CLOCK_BOOTTIME => {
            let n = host.monotonic_ns();
            (n / 1_000_000_000, n % 1_000_000_000)
        }
        _ => return -(abi::EINVAL as i64),
    };
    if tp == 0 {
        return 0;
    }
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&secs.to_le_bytes());
    out[8..16].copy_from_slice(&nsecs.to_le_bytes());
    match write_guest(proc, tp, &out) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

pub(super) fn sys_gettimeofday(proc: &GuestProcess, host: &dyn Host, tv: u64) -> i64 {
    if tv == 0 {
        return 0;
    }
    let (s, ns) = host.realtime();
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&s.to_le_bytes());
    out[8..16].copy_from_slice(&((ns / 1000) as u64).to_le_bytes());
    match write_guest(proc, tv, &out) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}
