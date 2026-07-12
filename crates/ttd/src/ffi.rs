//! FFI bridge to Microsoft's TTD ReplayApi (`TTDReplay.dll`).
//!
//! The engine is created through a reverse-engineered license handshake ported
//! from `commial/ttd-bindings`: `InitiateReplayEngineHandshake` returns a random
//! seed, which is transformed (indexed slices of vendored license text →
//! SHA-256 → base64) into a token passed to `CreateReplayEngineWithHandshake`.
//!
//! The vendored constants and vtable indices are pinned to a specific
//! `TTDReplay.dll` build. Microsoft documents this ABI as experimental, so a
//! mismatched DLL will fail the handshake (returns a clear error) rather than
//! misbehave silently. Nothing here is verifiable without a real `.run` trace.

use std::ffi::{c_void, CString};
use std::os::raw::c_char;
use std::sync::OnceLock;

use base64::Engine as _;
use common::{DebugError, Result};
use sha2::{Digest, Sha256};
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

use crate::csts;

/// A TTD replay position: `major` is the sequence, `minor` the step within it.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Position {
    pub major: u64,
    pub minor: u64,
}

// Exported factory functions (both `__cdecl`, i.e. the single x64 ABI).
type ProcInitiate = unsafe extern "C" fn(seed: *const c_char, b64rand_out: *mut u8) -> u32;
type ProcCreate =
    unsafe extern "C" fn(handshake: *const c_char, engine_out: *mut *mut c_void, guid: *mut u8) -> u32;

// IReplayEngine vtable indices (from commial/ttd-bindings TTD.hpp).
const IDX_ENGINE_GET_FIRST_POSITION: usize = 4;
const IDX_ENGINE_GET_LAST_POSITION: usize = 5;
const IDX_ENGINE_NEW_CURSOR: usize = 42;
const IDX_ENGINE_INITIALIZE: usize = 51;
// ICursor vtable indices.
const IDX_CURSOR_GET_POSITION: usize = 10;
const IDX_CURSOR_SET_POSITION: usize = 37;

/// Fetch vtable slot `index` of a C++ object whose first field is its vtable ptr.
unsafe fn vslot(obj: *mut c_void, index: usize) -> *const c_void {
    let vtbl = *(obj as *const *const c_void); // first field = vtable pointer
    *((vtbl as *const *const c_void).add(index))
}

fn to_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn not_supported(msg: impl Into<String>) -> DebugError {
    DebugError::NotSupported { message: msg.into() }
}

/// Build the handshake input string from the 48-byte seed, exactly mirroring the
/// reference: the seed's leading C-string, then two 0x65-byte license slices, then
/// one 0x4E-byte slice, each cut at its first NUL.
fn build_handshake_input(seed: &[u8; 48]) -> Vec<u8> {
    fn append_cstr(dst: &mut Vec<u8>, arr: &[u8], off: usize, maxlen: usize) {
        if off >= arr.len() {
            return;
        }
        let end = (off + maxlen).min(arr.len());
        for &b in &arr[off..end] {
            if b == 0 {
                break;
            }
            dst.push(b);
        }
    }

    let mut dest = Vec::new();
    // strncpy_s(dest, seed, 0x2F): leading bytes up to a NUL, max 47.
    for &b in seed.iter().take(0x2F) {
        if b == 0 {
            break;
        }
        dest.push(b);
    }
    // Two slices of aScopeOfLicense. The `(seed[i] - 48) % 0x11` arithmetic matches
    // C's int→u64 conversion for seeds below '0' (e.g. '+'/'/').
    for i in 0..2 {
        let idx = ((seed[i] as i64 - 48) as u64 % 0x11) as usize * 0x66;
        append_cstr(&mut dest, &csts::ASCOPEOFLICENSE, idx, 0x65);
    }
    // One slice of aVYHVAX4gukZ8Wv.
    let idx = ((seed[2] as i64 - 48) as u64 % 0x0B) as usize * 79;
    append_cstr(&mut dest, &csts::AVYHVAX4GUKZ8WV, idx, 0x4E);
    dest
}

/// The two factory exports, resolved once per process. Function pointers are
/// `Send + Sync`, so caching them avoids re-loading `TTDReplay.dll` (and leaking
/// an extra module refcount) on every trace open.
static TTD_PROCS: OnceLock<(ProcInitiate, ProcCreate)> = OnceLock::new();

/// Load `TTDReplay.dll` (and its CPU dependency) once and resolve the exports.
unsafe fn load_ttd_procs() -> Result<(ProcInitiate, ProcCreate)> {
    if let Some(procs) = TTD_PROCS.get() {
        return Ok(*procs);
    }
    // TTDReplayCPU.dll is a dependency of TTDReplay.dll; load it first if present.
    let _ = LoadLibraryW(PCWSTR(to_wide_nul("TTDReplayCPU.dll").as_ptr()));
    let module = LoadLibraryW(PCWSTR(to_wide_nul("TTDReplay.dll").as_ptr())).map_err(|e| {
        not_supported(format!(
            "TTDReplay.dll could not be loaded ({e}). Install the WinDbg/TTD components."
        ))
    })?;

    let initiate = GetProcAddress(module, PCSTR(c"InitiateReplayEngineHandshake".as_ptr() as *const u8))
        .ok_or_else(|| not_supported("InitiateReplayEngineHandshake export not found"))?;
    let create = GetProcAddress(module, PCSTR(c"CreateReplayEngineWithHandshake".as_ptr() as *const u8))
        .ok_or_else(|| not_supported("CreateReplayEngineWithHandshake export not found"))?;
    let procs: (ProcInitiate, ProcCreate) =
        (std::mem::transmute(initiate), std::mem::transmute(create));
    // A race just means two threads resolve the same addresses; keep the first.
    let _ = TTD_PROCS.set(procs);
    Ok(procs)
}

/// Perform the license handshake and create a replay engine instance.
/// Returns the raw `TTD::Replay::ReplayEngine*`.
unsafe fn create_engine() -> Result<*mut c_void> {
    let (initiate, create) = load_ttd_procs()?;

    let mut seed = [0u8; 48];
    let dbgeng = CString::new("DbgEng").unwrap();
    // Capture the handshake status: on failure the seed stays zero and the later
    // CreateReplayEngineWithHandshake failure would otherwise be misreported as a
    // DLL-version mismatch, misdirecting diagnosis.
    let rc = initiate(dbgeng.as_ptr(), seed.as_mut_ptr());
    if rc != 0 {
        return Err(not_supported(format!(
            "InitiateReplayEngineHandshake failed (rc={rc}); cannot derive the license handshake"
        )));
    }

    let input = build_handshake_input(&seed);
    let mut hasher = Sha256::new();
    hasher.update(&input);
    let digest = hasher.finalize(); // 32 bytes
    // Reference base64: standard alphabet, no padding (43 chars for 32 bytes).
    let token = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    let token = CString::new(token)
        .map_err(|e| not_supported(format!("handshake token contained NUL: {e}")))?;

    let mut engine: *mut c_void = std::ptr::null_mut();
    let mut guid = csts::VERSION_GUID; // mutable copy; passed as BYTE*
    let rc = create(token.as_ptr(), &mut engine, guid.as_mut_ptr());
    if engine.is_null() {
        return Err(not_supported(format!(
            "CreateReplayEngineWithHandshake failed (rc={rc}); the installed TTDReplay.dll \
             version likely does not match the vendored handshake constants"
        )));
    }
    Ok(engine)
}

/// An open TTD trace: a replay engine plus a cursor over it.
pub struct TtdTrace {
    engine: *mut c_void,
    cursor: *mut c_void,
}

// The replay engine is single-threaded; callers serialize access (the session
// manager holds each trace behind a mutex). The raw pointers are not otherwise
// shared, so it is sound to move a `TtdTrace` between threads.
unsafe impl Send for TtdTrace {}

/// IUnknown::Release vtable slot. The engine/cursor interface methods begin at
/// index 3+ (e.g. GetFirstPosition at 4), confirming slots 0..2 are the IUnknown
/// trio QueryInterface/AddRef/Release.
const IDX_IUNKNOWN_RELEASE: usize = 2;

impl Drop for TtdTrace {
    /// Release the cursor and then the replay engine. Without this, every
    /// open/close cycle leaked the engine (which pins the entire loaded trace,
    /// potentially hundreds of MB) plus its cursor. `create_engine()` only
    /// returns after the exact vtable ABI matched, so the Release slot is valid
    /// for any `TtdTrace` that exists.
    fn drop(&mut self) {
        unsafe {
            if !self.cursor.is_null() {
                let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(vslot(self.cursor, IDX_IUNKNOWN_RELEASE));
                release(self.cursor);
            }
            if !self.engine.is_null() {
                let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                    std::mem::transmute(vslot(self.engine, IDX_IUNKNOWN_RELEASE));
                release(self.engine);
            }
        }
    }
}

impl TtdTrace {
    /// Open `trace_path` (a `.run` file) and position a cursor at its start.
    pub fn open(trace_path: &str) -> Result<Self> {
        unsafe {
            let engine = create_engine()?;

            let path = to_wide_nul(trace_path);
            let initialize: unsafe extern "system" fn(*mut c_void, *const u16) -> bool =
                std::mem::transmute(vslot(engine, IDX_ENGINE_INITIALIZE));
            if !initialize(engine, path.as_ptr()) {
                return Err(not_supported(format!(
                    "ReplayEngine::Initialize failed for trace '{trace_path}'"
                )));
            }

            let new_cursor: unsafe extern "system" fn(*mut c_void, *const u8) -> *mut c_void =
                std::mem::transmute(vslot(engine, IDX_ENGINE_NEW_CURSOR));
            let cursor = new_cursor(engine, csts::GUID_CURSOR.as_ptr());
            if cursor.is_null() {
                return Err(not_supported("ReplayEngine::NewCursor returned null"));
            }

            let trace = TtdTrace { engine, cursor };
            // Seek to the first position so the cursor is valid to query.
            let first = trace.first_position();
            trace.set_position(first);
            Ok(trace)
        }
    }

    fn read_position(&self, index: usize) -> Position {
        unsafe {
            let f: unsafe extern "system" fn(*mut c_void) -> *const Position =
                std::mem::transmute(vslot(self.engine, index));
            let p = f(self.engine);
            if p.is_null() {
                Position::default()
            } else {
                *p
            }
        }
    }

    pub fn first_position(&self) -> Position {
        self.read_position(IDX_ENGINE_GET_FIRST_POSITION)
    }

    pub fn last_position(&self) -> Position {
        self.read_position(IDX_ENGINE_GET_LAST_POSITION)
    }

    /// Move the cursor to `pos`.
    pub fn set_position(&self, pos: Position) {
        unsafe {
            let f: unsafe extern "system" fn(*mut c_void, *const Position) =
                std::mem::transmute(vslot(self.cursor, IDX_CURSOR_SET_POSITION));
            f(self.cursor, &pos);
        }
    }

    /// Current cursor position (thread 0).
    pub fn current_position(&self) -> Position {
        unsafe {
            let f: unsafe extern "system" fn(*mut c_void, u32) -> *const Position =
                std::mem::transmute(vslot(self.cursor, IDX_CURSOR_GET_POSITION));
            let p = f(self.cursor, 0);
            if p.is_null() {
                Position::default()
            } else {
                *p
            }
        }
    }
}
