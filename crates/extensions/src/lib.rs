use dbgeng::DebugControl;
use common::{DebugError, Result, validate_command_arg, validate_debugger_command};
use models::ExtensionResult;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32, Ordering};
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    IDebugClient, IDebugEventCallbacks, IDebugEventCallbacks_Vtbl, IDebugOutputCallbacks,
    IDebugOutputCallbacks_Impl, IDebugBreakpoint, DEBUG_EVENT_BREAKPOINT, DEBUG_EVENT_EXCEPTION,
};

// DbgEng event constants not exported by windows 0.52 crate
const DEBUG_EVENT_CREATE_PROCESS: u32 = 0x00000010;
const DEBUG_EVENT_EXIT_PROCESS: u32 = 0x00000020;
const DEBUG_EVENT_LOAD_MODULE: u32 = 0x00000040;
const DEBUG_EVENT_UNLOAD_MODULE: u32 = 0x00000080;
const DEBUG_EVENT_SESSION_STATUS: u32 = 0x00000200;
use serde::Serialize;
use windows::core::{ComInterface, HRESULT, IUnknown_Vtbl, PCSTR};

/// Debugger event types that can be captured via IDebugEventCallbacks.
#[derive(Debug, Clone, Serialize)]
pub enum DebugEvent {
    Breakpoint { address: u64 },
    Exception { code: u32, first_chance: bool },
    CreateProcess { image_name: String, base: u64 },
    ExitProcess { exit_code: u32 },
    LoadModule { name: String, base: u64 },
    UnloadModule { name: String, base: u64 },
    SessionStatus { status: u32 },
}

/// IDebugOutputCallbacks implementation that captures text output into a String.
#[windows::core::implement(IDebugOutputCallbacks)]
struct OutputCallbacks {
    output: Arc<Mutex<String>>,
}

impl OutputCallbacks {
    fn new() -> Self {
        Self {
            output: Arc::new(Mutex::new(String::new())),
        }
    }
}

impl IDebugOutputCallbacks_Impl for OutputCallbacks {
    fn Output(&self, _mask: u32, text: &PCSTR) -> windows::core::Result<()> {
        if !text.0.is_null() {
            unsafe {
                let cstr = std::ffi::CStr::from_ptr(text.0 as *const i8);
                if let Ok(s) = cstr.to_str() {
                    if let Ok(mut output) = self.output.lock() {
                        output.push_str(s);
                    }
                }
            }
        }
        Ok(())
    }
}

// DbgEng execution-status constants used inside event callbacks to tell the
// engine how to continue after the current event.
const DEBUG_STATUS_NO_CHANGE: u32 = 0;
const DEBUG_STATUS_GO_HANDLED: u32 = 2;
const STATUS_BREAKPOINT: i32 = 0x80000003u32 as i32;
const E_NOINTERFACE: i32 = 0x80004002u32 as i32;

/// Manual COM object implementing IDebugEventCallbacks.
///
/// We cannot use `#[windows::core::implement]` because DbgEng interprets the
/// HRESULT returned from event callbacks as a continuation status. The macro
/// maps a Rust `Ok(())` to `S_OK`, which DbgEng treats as
/// `DEBUG_STATUS_NO_CHANGE`, and maps any `Err` to a failure. To make the
/// engine handle the re-hit initial breakpoint we must return
/// `HRESULT(DEBUG_STATUS_GO_HANDLED as i32)` as a *success* code from `Exception`.
#[repr(C)]
struct EventCallbacksObject {
    vtable: *const IDebugEventCallbacks_Vtbl,
    refcount: AtomicU32,
    sender: std::sync::mpsc::SyncSender<DebugEvent>,
}

impl EventCallbacksObject {
    fn new(sender: std::sync::mpsc::SyncSender<DebugEvent>) -> *mut Self {
        let this = Box::into_raw(Box::new(Self {
            vtable: &Self::VTABLE,
            refcount: AtomicU32::new(1),
            sender,
        }));
        this
    }

    unsafe fn from_this(this: *mut std::ffi::c_void) -> *mut Self {
        this as *mut Self
    }

    fn send(&self, event: DebugEvent) {
        // Drop events silently when the channel is full to prevent unbounded
        // memory growth during heavy module-load bursts.
        let _ = self.sender.try_send(event);
    }

    unsafe extern "system" fn query_interface(
        this: *mut std::ffi::c_void,
        iid: *const windows::core::GUID,
        interface: *mut *mut std::ffi::c_void,
    ) -> HRESULT {
        let iid = &*iid;
        if *iid == <windows::core::IUnknown as ComInterface>::IID
            || *iid == <IDebugEventCallbacks as ComInterface>::IID
        {
            (*interface) = this;
            Self::add_ref(this);
            HRESULT(0)
        } else {
            (*interface) = std::ptr::null_mut();
            HRESULT(E_NOINTERFACE)
        }
    }

    unsafe extern "system" fn add_ref(this: *mut std::ffi::c_void) -> u32 {
        let this = Self::from_this(this);
        (*this).refcount.fetch_add(1, Ordering::SeqCst) + 1
    }

    unsafe extern "system" fn release(this: *mut std::ffi::c_void) -> u32 {
        let this = Self::from_this(this);
        let remaining = (*this).refcount.fetch_sub(1, Ordering::SeqCst) - 1;
        if remaining == 0 {
            let _ = Box::from_raw(this);
        }
        remaining
    }

    unsafe extern "system" fn get_interest_mask(
        this: *mut std::ffi::c_void,
        mask: *mut u32,
    ) -> HRESULT {
        let this = Self::from_this(this);
        (*mask) = DEBUG_EVENT_BREAKPOINT
            | DEBUG_EVENT_EXCEPTION
            | DEBUG_EVENT_CREATE_PROCESS
            | DEBUG_EVENT_EXIT_PROCESS
            | DEBUG_EVENT_LOAD_MODULE
            | DEBUG_EVENT_UNLOAD_MODULE
            | DEBUG_EVENT_SESSION_STATUS;
        // Notify the engine so it can subscribe the callback; returning S_OK
        // here is fine because this method's return is not a continuation code.
        let _ = this;
        HRESULT(0)
    }

    unsafe extern "system" fn breakpoint(
        this: *mut std::ffi::c_void,
        bp: *mut std::ffi::c_void,
    ) -> HRESULT {
        let this = Self::from_this(this);
        let bp = if bp.is_null() {
            None
        } else {
            Some(&*(bp as *mut IDebugBreakpoint))
        };
        let address = bp.and_then(|b| b.GetOffset().ok()).unwrap_or(0);
        (*this).send(DebugEvent::Breakpoint { address });
        HRESULT(DEBUG_STATUS_NO_CHANGE as i32)
    }

    unsafe extern "system" fn exception(
        this: *mut std::ffi::c_void,
        exception: *const windows::Win32::System::Diagnostics::Debug::EXCEPTION_RECORD64,
        firstchance: u32,
    ) -> HRESULT {
        let this = Self::from_this(this);
        let code = if exception.is_null() {
            0
        } else {
            (*exception).ExceptionCode.0
        };
        let first_chance = firstchance != 0;
        (*this).send(DebugEvent::Exception {
            code: code as u32,
            first_chance,
        });

        // After the initial attach is complete, first-chance breakpoint
        // exceptions are the engine's own injected initial breakpoint being
        // re-hit on resume. Return GO_HANDLED directly so the engine consumes
        // the event and keeps running. This return value is interpreted as a
        // continuation status, not an error code.
        // First-chance breakpoint exceptions that are not registered as
        // DbgEng breakpoints (e.g., the engine's injected initial breakpoint
        // or a passive interrupt) are handled automatically so the target
        // keeps running. Registered breakpoints fire the Breakpoint callback
        // instead and are reported as stops.
        let decision = if first_chance && code == STATUS_BREAKPOINT {
            DEBUG_STATUS_GO_HANDLED
        } else {
            DEBUG_STATUS_NO_CHANGE
        };
        HRESULT(decision as i32)
    }

    unsafe extern "system" fn create_thread(
        this: *mut std::ffi::c_void,
        _handle: u64,
        _dataoffset: u64,
        _startoffset: u64,
    ) -> HRESULT {
        let _ = Self::from_this(this);
        HRESULT(DEBUG_STATUS_NO_CHANGE as i32)
    }

    unsafe extern "system" fn exit_thread(
        this: *mut std::ffi::c_void,
        _exitcode: u32,
    ) -> HRESULT {
        let _ = Self::from_this(this);
        HRESULT(DEBUG_STATUS_NO_CHANGE as i32)
    }

    unsafe extern "system" fn create_process_a(
        this: *mut std::ffi::c_void,
        _imagefilehandle: u64,
        _handle: u64,
        baseoffset: u64,
        _modulesize: u32,
        modulename: windows::core::PCSTR,
        _imagename: windows::core::PCSTR,
        _checksum: u32,
        _timedatestamp: u32,
        _initialthreadhandle: u64,
        _threaddataoffset: u64,
        _startoffset: u64,
    ) -> HRESULT {
        let this = Self::from_this(this);
        let name = if modulename.0.is_null() {
            String::new()
        } else {
            let cstr = std::ffi::CStr::from_ptr(modulename.0 as *const i8);
            cstr.to_str().unwrap_or("").to_string()
        };
        (*this).send(DebugEvent::CreateProcess {
            image_name: name,
            base: baseoffset,
        });
        HRESULT(DEBUG_STATUS_NO_CHANGE as i32)
    }

    unsafe extern "system" fn exit_process(
        this: *mut std::ffi::c_void,
        exitcode: u32,
    ) -> HRESULT {
        let this = Self::from_this(this);
        (*this).send(DebugEvent::ExitProcess { exit_code: exitcode });
        HRESULT(DEBUG_STATUS_NO_CHANGE as i32)
    }

    unsafe extern "system" fn load_module(
        this: *mut std::ffi::c_void,
        _imagefilehandle: u64,
        baseoffset: u64,
        _modulesize: u32,
        modulename: windows::core::PCSTR,
        _imagename: windows::core::PCSTR,
        _checksum: u32,
        _timedatestamp: u32,
    ) -> HRESULT {
        let this = Self::from_this(this);
        let name = if modulename.0.is_null() {
            String::new()
        } else {
            let cstr = std::ffi::CStr::from_ptr(modulename.0 as *const i8);
            cstr.to_str().unwrap_or("").to_string()
        };
        (*this).send(DebugEvent::LoadModule {
            name,
            base: baseoffset,
        });
        HRESULT(DEBUG_STATUS_NO_CHANGE as i32)
    }

    unsafe extern "system" fn unload_module(
        this: *mut std::ffi::c_void,
        imagebasename: windows::core::PCSTR,
        baseoffset: u64,
    ) -> HRESULT {
        let this = Self::from_this(this);
        let name = if imagebasename.0.is_null() {
            String::new()
        } else {
            let cstr = std::ffi::CStr::from_ptr(imagebasename.0 as *const i8);
            cstr.to_str().unwrap_or("").to_string()
        };
        (*this).send(DebugEvent::UnloadModule {
            name,
            base: baseoffset,
        });
        HRESULT(DEBUG_STATUS_NO_CHANGE as i32)
    }

    unsafe extern "system" fn system_error(
        this: *mut std::ffi::c_void,
        _error: u32,
        _level: u32,
    ) -> HRESULT {
        let _ = Self::from_this(this);
        HRESULT(DEBUG_STATUS_NO_CHANGE as i32)
    }

    unsafe extern "system" fn session_status(
        this: *mut std::ffi::c_void,
        status: u32,
    ) -> HRESULT {
        let this = Self::from_this(this);
        (*this).send(DebugEvent::SessionStatus { status });
        HRESULT(DEBUG_STATUS_NO_CHANGE as i32)
    }

    unsafe extern "system" fn change_debuggee_state(
        this: *mut std::ffi::c_void,
        _flags: u32,
        _argument: u64,
    ) -> HRESULT {
        let _ = Self::from_this(this);
        HRESULT(DEBUG_STATUS_NO_CHANGE as i32)
    }

    unsafe extern "system" fn change_engine_state(
        this: *mut std::ffi::c_void,
        _flags: u32,
        _argument: u64,
    ) -> HRESULT {
        let _ = Self::from_this(this);
        HRESULT(DEBUG_STATUS_NO_CHANGE as i32)
    }

    unsafe extern "system" fn change_symbol_state(
        this: *mut std::ffi::c_void,
        _flags: u32,
        _argument: u64,
    ) -> HRESULT {
        let _ = Self::from_this(this);
        HRESULT(DEBUG_STATUS_NO_CHANGE as i32)
    }

    const VTABLE: IDebugEventCallbacks_Vtbl = IDebugEventCallbacks_Vtbl {
        base__: IUnknown_Vtbl {
            QueryInterface: Self::query_interface,
            AddRef: Self::add_ref,
            Release: Self::release,
        },
        GetInterestMask: Self::get_interest_mask,
        Breakpoint: Self::breakpoint,
        Exception: Self::exception,
        CreateThread: Self::create_thread,
        ExitThread: Self::exit_thread,
        CreateProcessA: Self::create_process_a,
        ExitProcess: Self::exit_process,
        LoadModule: Self::load_module,
        UnloadModule: Self::unload_module,
        SystemError: Self::system_error,
        SessionStatus: Self::session_status,
        ChangeDebuggeeState: Self::change_debuggee_state,
        ChangeEngineState: Self::change_engine_state,
        ChangeSymbolState: Self::change_symbol_state,
    };
}

/// Register event callbacks on a debug client. Returns a receiver that can be
/// polled for debugger events (breakpoints, exceptions, module loads, etc.).
pub fn register_event_callbacks(
    client: &IDebugClient,
) -> Result<std::sync::mpsc::Receiver<DebugEvent>> {
    let (tx, rx) = std::sync::mpsc::sync_channel(4096);
    let raw = EventCallbacksObject::new(tx);
    unsafe {
        // IDebugEventCallbacks is #[repr(transparent)] around a non-null
        // interface pointer, so transmuting our manually laid-out object is
        // valid as long as the vtable's first three entries are IUnknown.
        let dbgeng_callbacks: IDebugEventCallbacks = std::mem::transmute(raw);
        client
            .SetEventCallbacks(&dbgeng_callbacks)
            .map_err(|e| DebugError::Com {
                message: format!("SetEventCallbacks: {}", e),
            })?;
        // The engine AddRefs during SetEventCallbacks; release our initial
        // reference so the object's lifetime is owned by the engine.
        drop(dbgeng_callbacks);
    }
    Ok(rx)
}

/// Best-effort success classification for a dbgeng command.
///
/// `IDebugControl::Execute` returns `S_OK` even when the command itself failed
/// (e.g. `.load` of a missing DLL, or a syntax/resolution error) — the failure
/// is reported only in the emitted text. So a hard COM error is caught by the
/// caller's `?`, and here we additionally scan the captured output for dbgeng's
/// unambiguous failure markers (the `^ <Error> in '<cmd>'` caret indicator and
/// a few load/resolution phrases). Absent those, the command is assumed to have
/// succeeded. This is heuristic by nature; callers should still inspect `output`.
fn command_succeeded(output: &str) -> bool {
    const FAILURE_MARKERS: &[&str] = &[
        "^ Syntax error",
        "^ Bad ",
        "^ No ",
        "^ Range error",
        "^ Operand",
        "^ Extra character",
        "^ Memory access error",
        "^ Symbol not found",
        "^ Illegal",
        "^ Numeric expression",
        "Couldn't resolve error",
        "Unable to load image",
        "Unable to find module",
        "Win32 error",
    ];
    !FAILURE_MARKERS.iter().any(|m| output.contains(m))
}

/// Load a dbgeng extension DLL at the given path.
/// Uses `.load "<path>"` through the control execute interface.
/// The path is quoted to handle paths containing spaces.
///
/// Captures actual debugger output via IDebugOutputCallbacks.
///
/// NOTE: this is a library entry point that is intentionally NOT wired to any
/// MCP tool — loading an arbitrary DLL runs its `DllMain`/`DebugExtensionInitialize`
/// (arbitrary native code), which must never be reachable by an autonomous agent.
/// It exists for embedders that load a trusted extension out-of-band.
pub fn load_extension(control: &DebugControl, path: &str) -> Result<ExtensionResult> {
    let safe_path = validate_command_arg(path)?;
    let command = format!(".load \"{}\"", safe_path);

    let callbacks = OutputCallbacks::new();
    let output = callbacks.output.clone();
    let dbgeng_callbacks: IDebugOutputCallbacks = callbacks.into();

    // SetOutputCallbacks is on IDebugClient, not IDebugControl.
    // QueryInterface from IDebugControl to IDebugClient should succeed
    // because DbgEng's client object implements all core interfaces.
    let client = control
        .0
        .cast::<IDebugClient>()
        .map_err(|e| DebugError::Com {
            message: format!("cast to IDebugClient: {}", e),
        })?;

    unsafe {
        client
            .SetOutputCallbacks(&dbgeng_callbacks)
            .map_err(|e| DebugError::Com {
                message: format!("SetOutputCallbacks: {}", e),
            })?;
    }

    let result = control.execute(0, &command, 0);

    unsafe {
        let _ = client.SetOutputCallbacks(None::<&IDebugOutputCallbacks>);
    }

    let captured = output.lock().map(|s| s.clone()).unwrap_or_default();

    result?;
    let success = command_succeeded(&captured);
    Ok(ExtensionResult {
        output: captured,
        success,
    })
}

/// Invoke an arbitrary extension command string through the debugger control interface.
///
/// Captures actual debugger output via IDebugOutputCallbacks.
pub fn invoke_command(control: &DebugControl, command: &str) -> Result<ExtensionResult> {
    // This is the single sink for free-form commands, so it enforces the
    // code-execution blocklist in addition to the quoting/injection checks.
    let safe_command = validate_debugger_command(command)?;

    let callbacks = OutputCallbacks::new();
    let output = callbacks.output.clone();
    let dbgeng_callbacks: IDebugOutputCallbacks = callbacks.into();

    let client = control
        .0
        .cast::<IDebugClient>()
        .map_err(|e| DebugError::Com {
            message: format!("cast to IDebugClient: {}", e),
        })?;

    unsafe {
        client
            .SetOutputCallbacks(&dbgeng_callbacks)
            .map_err(|e| DebugError::Com {
                message: format!("SetOutputCallbacks: {}", e),
            })?;
    }

    let result = control.execute(0, &safe_command, 0);

    unsafe {
        let _ = client.SetOutputCallbacks(None::<&IDebugOutputCallbacks>);
    }

    let captured = output.lock().map(|s| s.clone()).unwrap_or_default();

    result?;
    let success = command_succeeded(&captured);
    Ok(ExtensionResult {
        output: captured,
        success,
    })
}
