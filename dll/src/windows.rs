// Basic Windows type aliases using Rust primitives
pub(crate) type DWORD = u32;
pub(crate) type BOOL = i32; // Windows BOOL is typically defined as int
pub(crate) type HANDLE = *mut std::ffi::c_void; // Treat handles as opaque pointers
pub(crate) type LPVOID = *mut std::ffi::c_void;

pub(crate) const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
pub(crate) const PIPE_TYPE_BYTE: u32 = 0x00000000;
pub(crate) const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
pub(crate) const ERROR_PIPE_CONNECTED: u32 = 535;
// Constants for DllMain call_reason
pub(crate) const DLL_PROCESS_ATTACH: DWORD = 1;
pub(crate) const DLL_PROCESS_DETACH: DWORD = 0;
pub(crate) const DLL_THREAD_ATTACH: DWORD = 2;
pub(crate) const DLL_THREAD_DETACH: DWORD = 3;

#[allow(non_snake_case)]
#[link(name = "kernel32")]
unsafe extern "system" {
    pub(crate) fn WinExec(lpCmdLine: LPVOID, uCmdShow: DWORD) -> DWORD;
    pub(crate) fn GetModuleHandleA(lpModuleName: LPVOID) -> HANDLE;
    pub(crate) fn GetProcAddress(hmodule: HANDLE, lpProcName: LPVOID) -> LPVOID;
}

#[allow(non_snake_case)]
#[link(name = "user32")]
unsafe extern "system" {
    pub fn MessageBoxA(hWnd: HANDLE, lpText: LPVOID, lpCaption: LPVOID, uType: DWORD);
}

#[allow(non_snake_case)]
#[link(name = "user32")]
unsafe extern "system" {
    pub(crate) fn GetLastError() -> u32;
    pub(crate) fn CreateNamedPipeA(
        lpName: *const u8,                              // LPCSTR
        dwOpenMode: u32,                                // DWORD
        dwPipeMode: u32,                                // DWORD
        nMaxInstances: u32,                             // DWORD
        nOutBufferSize: u32,                            // DWORD
        nInBufferSize: u32,                             // DWORD
        nDefaultTimeOut: u32,                           // DWORD
        lpSecurityAttributes: *const core::ffi::c_void, // opaque pointer, fix in future...maybe
    ) -> HANDLE;

    pub(crate) fn ConnectNamedPipe(
        hNamedPipe: HANDLE,
        lpOverLapped: *const core::ffi::c_void, // opaque pointer, fix in future...maybe
    ) -> BOOL;

    pub(crate) fn CloseHandle(handle: HANDLE) -> BOOL;

    pub(crate) fn WriteFile(
        hFile: HANDLE,
        lpBuffer: *const u8,
        nNumberOfBytesToWrite: u32,
        lpNumberOfBytesWritten: *mut u32,
        lpOverlapped: *const core::ffi::c_void,
    ) -> BOOL;

    pub(crate) fn FlushFileBuffers(handle: HANDLE) -> BOOL;
}

#[repr(C)]
pub(crate) struct ImageDosHeader {
    pub(crate) e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    pub(crate) e_lfanew: i32,
}

#[repr(C)]
pub(crate) struct ImageNtHeaders {
    pub(crate) signature: u32,
}

pub(crate) const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // 'MZ'
pub(crate) const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // 'PE\0\0'
