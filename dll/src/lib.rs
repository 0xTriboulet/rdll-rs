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
