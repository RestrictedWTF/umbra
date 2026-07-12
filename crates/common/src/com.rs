#[cfg(target_os = "windows")]
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
use crate::{Result, DebugError};

#[cfg(target_os = "windows")]
thread_local! {
    static COM_INITIALIZED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// NOTE: there is deliberately no standalone `com_initialize`. A bare
// CoInitializeEx that does not track the thread-local COM_INITIALIZED flag
// cannot be balanced by `com_uninitialize` (which only uninitializes when the
// flag is set), so it would leak a COM initialization count. All callers use the
// idempotent, flag-tracking `ensure_com_initialized` below.

/// Ensure COM is initialized on the current thread with MTA.
/// Uses a thread-local flag to avoid repeated calls.
/// Returns an error if the thread was previously initialized as STA (RPC_E_CHANGED_MODE),
/// because dbgeng requires MTA.
#[cfg(target_os = "windows")]
pub fn ensure_com_initialized() -> Result<()> {
    COM_INITIALIZED.with(|initialized| {
        if !initialized.get() {
            unsafe {
                CoInitializeEx(None, COINIT_MULTITHREADED).map_err(|e| {
                    let code = e.code().0;
                    if code == 0x80010106u32 as i32 {
                        DebugError::Com {
                            message: format!(
                                "COM initialized with wrong apartment model on this thread (HRESULT: 0x{:08X}). \
                                 dbgeng requires MTA. A library or runtime may have initialized STA first.",
                                code as u32
                            ),
                        }
                    } else {
                        DebugError::Com {
                            message: e.to_string(),
                        }
                    }
                })?;
            }
            initialized.set(true);
        }
        Ok(())
    })
}

/// Stub for non-Windows platforms.
#[cfg(not(target_os = "windows"))]
pub fn ensure_com_initialized() -> Result<()> {
    Ok(())
}

/// Uninitialize COM on the current thread.
/// Should only be called on the same thread that called `ensure_com_initialized()`.
#[cfg(target_os = "windows")]
pub fn com_uninitialize() {
    COM_INITIALIZED.with(|initialized| {
        if initialized.get() {
            unsafe {
                CoUninitialize();
            }
            initialized.set(false);
        }
    });
}

/// Stub for non-Windows platforms.
#[cfg(not(target_os = "windows"))]
pub fn com_uninitialize() {}
