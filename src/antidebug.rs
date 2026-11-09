//! Windows 反调试检查。
//!
//! 目的很有限：让随手挂上调试器的人拿不到内存里的暗号与配置。不是强对抗，
//! 也挡不住有心人——真正的安全边界还是"指纹在本地、私钥在服务器"。

/// 当前进程是否正在被调试（非 Windows 平台恒为 false）。
#[cfg(target_os = "windows")]
pub fn is_being_debugged() -> bool {
    use windows::core::BOOL;
    use windows::Win32::System::Diagnostics::Debug::{
        CheckRemoteDebuggerPresent, IsDebuggerPresent,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    // 最常见的一层：本进程是否挂了调试器。
    if unsafe { IsDebuggerPresent() }.as_bool() {
        return true;
    }

    // 再查一次"远程调试器"（另一台机器上的 windbg 之类）。
    let mut remote = BOOL(0);
    if unsafe { CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote) }.is_ok() {
        return remote.as_bool();
    }
    false
}

/// 非 Windows 平台不做检查。
#[cfg(not(target_os = "windows"))]
pub fn is_being_debugged() -> bool {
    false
}
