#![no_main]
#![allow(dead_code)]
#![crate_type = "cdylib"]

mod ffi;
mod pipe;
mod windows;

use crate::ffi::*;
use crate::pipe::*;

use std::os::raw::c_void;
use windows::*;

/// Entry point for the custom Rust-based DLL.
///
/// This function serves as the main entry point for invoking functionality
/// via the Reflective DLL template. As examples, it performs the following operations:
///
/// 1. Displays a message box with a greeting message using the `MessageBoxA` Windows API call.
/// 2. Delegates execution to an external C entry point function (`c_entry`) for further processing.
/// 3. Outputs a message using a named pipe or standard output, depending on the build configuration.
#[unsafe(no_mangle)]
#[allow(named_asm_labels)]
#[allow(non_snake_case, unused_variables)]
pub fn dll_main() {
    let msg = b"Hello from Rust Reflective DLL!\0";
    unsafe {
        MessageBoxA(
            std::ptr::null_mut(),
            msg.as_ptr() as LPVOID,
            msg.as_ptr() as LPVOID,
            0,
        );
    }

    // Call the C entry point
    unsafe {
        c_entry();
    }

    // Write output to the pipe
    write_output("Hello from the Rust Reflective DLL via output!");
}

/// Retrieves the instruction pointer (IP) on the `x86_64` architecture.
///
/// This function obtains the current value of the instruction pointer (RIP register)
/// using inline assembly. It can be used to determine the memory address of the
/// currently executing instruction, which is helpful for low-level debugging,
/// locating code regions, or working with reflective APIs.
///
/// # Returns
/// A `usize` representing the value of the instruction pointer (RIP).
///
/// # Safety
/// - This function uses inline assembly, which is inherently unsafe.
#[cfg(target_arch = "x86_64")]
unsafe fn get_ip() -> usize {
    let rip: usize;
    unsafe { std::arch::asm!("lea {}, [rip]", out(reg) rip) };
    rip
}

/// Retrieves the instruction pointer (IP) on the `x86` architecture.
///
/// This function obtains the current value of the instruction pointer (EIP register)
/// using inline assembly. It is useful for determining the memory address of the
/// next executing instruction, which aids in low-level debugging, reflective APIs,
/// and locating code regions.
///
/// # Returns
/// A `usize` representing the value of the instruction pointer (EIP).
///
/// # Safety
/// - This function uses inline assembly, which is inherently unsafe.
#[cfg(target_arch = "x86")]
unsafe fn get_ip() -> usize {
    let eip: usize;
    unsafe {
        std::arch::asm!(
        "call 1f",
        "1: pop {}",
        out(reg) eip,
        );
    }

    eip
}

/// Searches for an `MZ` (DOS) header followed by a valid `PE` header in memory.
///
/// This function scans backward in memory, starting from the current instruction pointer,
/// to locate an `MZ` (Microsoft DOS) executable file signature. If found, it then checks
/// for a valid `PE` (Portable Executable) header. The function is useful for identifying
/// the base address of a module in reflective DLL contexts or other low-level scenarios.
///
/// # Returns
/// - `Some(*const u8)` pointing to the start of the `MZ` header if a valid `MZ` and
///   `PE` header sequence is found.
/// - `None` if no valid header is located within the scanned range.
///
/// # Methodology
/// The function performs the following steps:
/// 1. Retrieves the current instruction pointer address using `get_ip()`.
/// 2. Iterates backward in memory to locate the `MZ` signature (DOS header).
/// 3. Validates the header fields, including the `e_lfanew` offset, to confirm a
///    valid `PE` (Portable Executable) structure.
/// 4. Returns a pointer to the `MZ` header if the validation is successful.
///
/// # Safety
/// - This function includes unsafe code due to direct memory access and pointer handling.
/// - Improper use of this function could lead to undefined behavior, such as accessing
///   invalid memory or causing segmentation faults.
pub fn find_mz_pe_signature() -> Option<*const u8> {
    let rip = unsafe { get_ip() };
    let mut ptr = rip as *const u8;

    loop {
        if ptr < 2 as *const u8 {
            break;
        }

        let dos_header = unsafe { ptr.offset(-2) } as *const ImageDosHeader;

        if unsafe { std::ptr::read_unaligned(&(*dos_header).e_magic) } == IMAGE_DOS_SIGNATURE {
            let e_lfanew = unsafe { std::ptr::read_unaligned(&(*dos_header).e_lfanew) } as isize;

            if e_lfanew >= std::mem::size_of::<ImageDosHeader>() as isize && e_lfanew < 1024 {
                let nt_header_ptr =
                    unsafe { (dos_header as *const u8).offset(e_lfanew) } as *const ImageNtHeaders;

                if unsafe { std::ptr::read_unaligned(&(*nt_header_ptr).signature) }
                    == IMAGE_NT_SIGNATURE
                {
                    return Some(dos_header as *const u8);
                }
            }
        }

        ptr = unsafe { ptr.offset(-1) };
    }

    None
}

/// ReflectiveLoader for compatability with legacy Reflective DLL loaders
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn ReflectiveLoader() {
    let module_base = find_mz_pe_signature();
    if module_base.is_some() {
        let module_base = module_base.unwrap();
        // You can pass in module_base into your reflective loader here via rcx or esp-4.
        // Something like this probably works
        //      std::arch::asm!("mov rcx, {0}, in(reg) module_base);
        //      std::arch::asm!(".byte 0x90, 0x90, 0x90 /* Reflective loader bytes here */");
        // By default, the template assumes the pe2shc construction where the module base
        // also contains a jmp to the stub, so we just call into it below
        unsafe { std::arch::asm!("call {0}", in(reg) module_base) };
    }
}

#[unsafe(no_mangle)]
#[allow(named_asm_labels)]
#[allow(non_snake_case, unused_variables, unreachable_patterns)]
pub unsafe extern "system" fn DllMain(
    dll_module: HANDLE,
    call_reason: u32,
    reserved: *mut c_void,
) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            // Code to run when the DLL is loaded into a process
            // Initialize resources, etc.
            dll_main();
        }
        DLL_THREAD_ATTACH => {
            // Code to run when a new thread is created in the process
        }
        DLL_THREAD_DETACH => {
            // Code to run when a thread exits cleanly
        }
        DLL_PROCESS_DETACH => {
            // Code to run when the DLL is unloaded from the process
            // Clean up resources, etc.
        }
        _ => {}
    }
    return 1;
}
