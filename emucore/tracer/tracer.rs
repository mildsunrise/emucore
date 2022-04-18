#![no_std]
use core::panic::PanicInfo;
extern "C" {
    fn abort() -> !;
}
#[panic_handler]
fn panic_handler(_info: &PanicInfo) -> ! { unsafe { abort() } }

use core::ffi::c_void;
use core::mem::MaybeUninit;
#[allow(non_camel_case_types)]
type c_int = i32;

type UcErr = c_int;
pub const UC_ERR_OK: UcErr = 0;
type UcEngine = *mut c_void;

// populated in Python side to avoid loading problems
#[no_mangle]
static mut uc_reg_read: Option<extern "C" fn(UcEngine, c_int, *mut c_void) -> UcErr> = None;

pub const UC_X86_REG_RSP: c_int = 44;

// code

#[repr(C)]
struct TraceEntry {
    sp: u64,
    ip: u64,
}

#[repr(C)]
struct TraceData {
    capacity: usize,
    size: usize,
    entries: *mut TraceEntry,
}

#[no_mangle]
extern "C" fn hook_block(uc: UcEngine, bb_addr: u64, bb_size: u32, raw_data: *mut c_void) {
    let TraceData { entries, size, capacity } = unsafe { &mut *(raw_data as *mut TraceData) };
    let entry = |n: usize| unsafe { &mut *entries.offset(n as isize) };

    let reg_read = unsafe { uc_reg_read.unwrap() };
    let mut out = MaybeUninit::<u64>::uninit();
    let sp = match reg_read(uc, UC_X86_REG_RSP, out.as_mut_ptr() as *mut c_void) {
        UC_ERR_OK => unsafe { out.assume_init() },
        _ => return,
    };

    while *size > 0 && entry(*size - 1).sp <= sp {
        *size -= 1;
    }
    if *size < *capacity {
        let ip = bb_addr + bb_size as u64;
        *entry(*size) = TraceEntry { sp, ip };
        *size += 1;
    }
}
