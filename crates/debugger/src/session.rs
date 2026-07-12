use std::sync::{Arc, mpsc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use dbgeng::{
    DebugClient, DebugControl, DebugDataSpaces, DebugRegisters, DebugSymbols,
    DebugSystemObjects,
};
use common::{DebugError, Result};

const MAX_MEMORY_SIZE: u32 = 256 * 1024; // 256KB cap on read/write

// How long to wait for the initial stop after an attach/open. If the target
// does not reach a stopped state within this window, the attach fails loudly
// rather than returning a broken session.
const ATTACH_WAIT_TIMEOUT_MS: u32 = 10_000;

// DbgEng execution status constants (from Windows SDK dbgeng.h)
const DEBUG_STATUS_GO: u32 = 1;
const DEBUG_STATUS_GO_HANDLED: u32 = 2;
const DEBUG_STATUS_GO_NOT_HANDLED: u32 = 3;
const DEBUG_STATUS_STEP_OVER: u32 = 4;
const DEBUG_STATUS_STEP_INTO: u32 = 5;
const DEBUG_STATUS_BREAK: u32 = 6;
const DEBUG_STATUS_STEP_BRANCH: u32 = 8;

// DbgEng interrupt flags
const DEBUG_INTERRUPT_PASSIVE: u32 = 0x00000000;

// DbgEng end session flags
const DEBUG_END_PASSIVE: u32 = 0;
const DEBUG_END_ACTIVE_DETACH: u32 = 2;

// DbgEng engine options
const DEBUG_ENGOPT_INITIAL_BREAK: u32 = 0x00000020;

// DEBUG_VALUE type constants (from dbgeng.h)
const DEBUG_VALUE_INT8: u32 = 1;
const DEBUG_VALUE_INT16: u32 = 2;
const DEBUG_VALUE_INT32: u32 = 3;
const DEBUG_VALUE_INT64: u32 = 4;
const DEBUG_VALUE_FLOAT32: u32 = 5;
const DEBUG_VALUE_FLOAT64: u32 = 6;
const DEBUG_VALUE_FLOAT80: u32 = 7;
const DEBUG_VALUE_FLOAT82: u32 = 8;
const DEBUG_VALUE_FLOAT128: u32 = 9;
const DEBUG_VALUE_VECTOR64: u32 = 10;
const DEBUG_VALUE_VECTOR128: u32 = 11;

// Processor type constants (from winnt.h / dbgeng.h)
const IMAGE_FILE_MACHINE_I386: u32 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u32 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u32 = 0xaa64;

// Max instruction length per architecture (bytes)
const MAX_INSTRUCTION_LEN_X86: u64 = 15;
const MAX_INSTRUCTION_LEN_ARM: u64 = 4;

struct DebugEngine {
    client: DebugClient,
    control: DebugControl,
    system: DebugSystemObjects,
    symbols: DebugSymbols,
    registers: DebugRegisters,
    data_spaces: DebugDataSpaces,
    events: Option<Arc<Mutex<std::sync::mpsc::Receiver<extensions::DebugEvent>>>>,
    target_type: String,
}

impl DebugEngine {
    /// Drain all pending debugger events from the event callback channel.
    fn poll_events(&self) -> Vec<extensions::DebugEvent> {
        let mut events = Vec::new();
        if let Some(ref rx) = self.events {
            if let Ok(guard) = rx.lock() {
                while let Ok(event) = guard.try_recv() {
                    events.push(event);
                }
            }
        }
        events
    }
}

enum EngineCommand {
    AttachProcess {
        pid: u32,
        respond: tokio::sync::oneshot::Sender<Result<()>>,
    },
    AttachKernel {
        connect_string: String,
        respond: tokio::sync::oneshot::Sender<Result<()>>,
    },
    OpenDumpFile {
        path: String,
        respond: tokio::sync::oneshot::Sender<Result<()>>,
    },
    Detach {
        respond: tokio::sync::oneshot::Sender<Result<()>>,
    },
    Break {
        respond: tokio::sync::oneshot::Sender<Result<()>>,
    },
    Resume {
        respond: tokio::sync::oneshot::Sender<Result<()>>,
    },
    Step {
        respond: tokio::sync::oneshot::Sender<Result<()>>,
    },
    WaitForEvent {
        timeout_ms: u32,
        respond: tokio::sync::oneshot::Sender<Result<()>>,
    },
    ReadMemory {
        address: u64,
        size: u32,
        respond: tokio::sync::oneshot::Sender<Result<Vec<u8>>>,
    },
    WriteMemory {
        address: u64,
        data: Vec<u8>,
        respond: tokio::sync::oneshot::Sender<Result<usize>>,
    },
    StackTrace {
        max_frames: u32,
        respond: tokio::sync::oneshot::Sender<Result<Vec<models::StackFrame>>>,
    },
    ListModules {
        respond: tokio::sync::oneshot::Sender<Result<Vec<models::ModuleInfo>>>,
    },
    GetRegisters {
        respond: tokio::sync::oneshot::Sender<Result<models::RegisterState>>,
    },
    ListProcesses {
        respond: tokio::sync::oneshot::Sender<Result<Vec<models::ProcessInfo>>>,
    },
    ListThreads {
        respond: tokio::sync::oneshot::Sender<Result<Vec<models::ThreadInfo>>>,
    },
    SetBreakpoint {
        address: u64,
        respond: tokio::sync::oneshot::Sender<Result<models::BreakpointSetResult>>,
    },
    RemoveBreakpoint {
        id: u32,
        respond: tokio::sync::oneshot::Sender<Result<()>>,
    },
    ListBreakpoints {
        respond: tokio::sync::oneshot::Sender<Result<Vec<models::BreakpointInfo>>>,
    },
    LookupSymbol {
        symbol: String,
        respond: tokio::sync::oneshot::Sender<Result<models::SymbolInfo>>,
    },
    ResolveType {
        type_name: String,
        respond: tokio::sync::oneshot::Sender<Result<models::TypeInfo>>,
    },
    Disassemble {
        address: u64,
        count: Option<u32>,
        respond: tokio::sync::oneshot::Sender<Result<(Vec<models::Instruction>, bool)>>,
    },
    ListDrivers {
        respond: tokio::sync::oneshot::Sender<Result<Vec<models::DriverInfo>>>,
    },
    ListHandles {
        pid: u32,
        respond: tokio::sync::oneshot::Sender<Result<Vec<models::HandleInfo>>>,
    },
    LoadExtension {
        path: String,
        respond: tokio::sync::oneshot::Sender<Result<models::ExtensionResult>>,
    },
    InvokeExtension {
        command: String,
        respond: tokio::sync::oneshot::Sender<Result<models::ExtensionResult>>,
    },
    Shutdown {
        respond: tokio::sync::oneshot::Sender<Result<()>>,
    },
    PollEvents {
        respond: tokio::sync::oneshot::Sender<Result<Vec<extensions::DebugEvent>>>,
    },
}

/// Derive "is target running" from GetExecutionStatus rather than trusting a flag.
fn is_target_running(engine: &DebugEngine) -> bool {
    match engine.control.get_execution_status() {
        Ok(status) => is_running_status(status),
        _ => false,
    }
}

fn is_running_status(status: u32) -> bool {
    matches!(
        status,
        DEBUG_STATUS_GO
            | DEBUG_STATUS_GO_HANDLED
            | DEBUG_STATUS_GO_NOT_HANDLED
            | DEBUG_STATUS_STEP_OVER
            | DEBUG_STATUS_STEP_INTO
            | DEBUG_STATUS_STEP_BRANCH
    )
}

/// Return an error unless the target is currently stopped. Fails closed: if the
/// execution status cannot be queried, that is surfaced as an error rather than
/// optimistically treating the target as stopped and issuing a data operation
/// against an unknown state.
fn require_target_stopped(engine: &DebugEngine) -> Result<()> {
    match engine.control.get_execution_status() {
        Ok(status) if is_running_status(status) => Err(DebugError::InvalidParameter {
            message: "Target is currently executing; command requires stopped state".to_string(),
        }),
        Ok(_) => Ok(()),
        Err(e) => Err(DebugError::Target {
            message: format!("could not determine target execution state: {}", e),
        }),
    }
}

/// Break the target in before a session-ending operation.
///
/// dbgeng's `EndSession` (and the underlying detach) can block indefinitely when
/// issued against a *running* target — the root cause of the intermittent
/// detach hang: it hangs exactly when the target happens to be running at detach
/// time, and returns promptly when it is already stopped. Every other
/// state-sensitive command breaks in first; detach must too. Bounded for
/// user-mode; kernel `WaitForEvent` requires an infinite timeout, and the
/// caller's `shutdown()` timeout is the ultimate backstop.
fn ensure_stopped_for_session_end(engine: &DebugEngine, interrupt_control: &DebugControl) {
    if is_target_running(engine) {
        let _ = interrupt_control.set_interrupt(DEBUG_INTERRUPT_PASSIVE);
        if engine.target_type == "kernel" {
            let _ = engine.control.wait_for_event(0, 0xFFFFFFFF);
        } else {
            let _ = engine.control.wait_for_event(0, 5_000);
        }
    }
}

/// Helper: perform a stack trace using the engine directly.
fn do_stack_trace(engine: &DebugEngine, max_frames: u32) -> Result<Vec<models::StackFrame>> {
    const MAX_FRAMES: u32 = 4096;
    let max_frames = max_frames.min(MAX_FRAMES);

    let mut frames_buf = vec![
        windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_STACK_FRAME::default();
        max_frames as usize
    ];
    let filled = engine.control.get_stack_trace(0, 0, 0, &mut frames_buf)?;

    let mut result = Vec::with_capacity(filled as usize);
    for i in 0..filled {
        let raw = &frames_buf[i as usize];
        let mut name_buf = [0u8; 256];
        let mut displ = 0u64;
        let func_name = engine
            .symbols
            .get_near_name_by_offset(raw.InstructionOffset, &mut name_buf, &mut displ)
            .ok()
            .and_then(|needed| {
                let read_len = (needed as usize).min(name_buf.len());
                let len = name_buf[..read_len].iter().position(|&b| b == 0).unwrap_or(read_len);
                let name = String::from_utf8_lossy(&name_buf[..len]).to_string();
                if name.is_empty() {
                    None
                } else {
                    Some(name)
                }
            });

        result.push(models::StackFrame {
            frame_number: raw.FrameNumber,
            instruction_pointer: raw.InstructionOffset,
            return_address: raw.ReturnOffset,
            frame_offset: raw.FrameOffset,
            stack_offset: raw.StackOffset,
            module: None,
            function: func_name,
            offset: displ,
            source_file: None,
            source_line: None,
        });
    }
    Ok(result)
}

/// Helper: get register state using the engine directly.
fn do_get_registers(engine: &DebugEngine) -> Result<models::RegisterState> {
    let count = engine.registers.get_number_registers()?;
    let mut regs = Vec::new();

    for i in 0..count {
        let (name, desc) = engine.registers.get_description(i)?;
        let mut value =
            windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_VALUE::default();
        engine.registers.get_value(i, &mut value)?;

        let raw = unsafe { value.Anonymous.RawBytes };
        let (size, is_integer) = match desc.Type {
            DEBUG_VALUE_INT8 => (1, true),
            DEBUG_VALUE_INT16 => (2, true),
            DEBUG_VALUE_INT32 => (4, true),
            DEBUG_VALUE_INT64 => (8, true),
            DEBUG_VALUE_FLOAT32 => (4, false),
            DEBUG_VALUE_FLOAT64 => (8, false),
            DEBUG_VALUE_FLOAT80 => (10, false),
            // F82Bytes is an 11-byte field in the _DEBUG_VALUE union, distinct from
            // the 10-byte F80Bytes — sizing it at 10 truncates one byte.
            DEBUG_VALUE_FLOAT82 => (11, false),
            DEBUG_VALUE_FLOAT128 => (16, false),
            DEBUG_VALUE_VECTOR64 => (8, false),
            DEBUG_VALUE_VECTOR128 => (16, false),
            _ => (8, true),
        };
        // RawBytes holds the value in native little-endian order. For integer
        // registers, present it as a conventional integer literal (most-significant
        // byte first) so e.g. rax=0xdeadbeef reads as "0x00000000deadbeef", not the
        // byte-reversed "0xefbeadde00000000". Float/vector registers keep their raw
        // little-endian byte layout.
        let hex_value = if is_integer {
            format!(
                "0x{}",
                raw[..size].iter().rev().map(|b| format!("{:02x}", b)).collect::<String>()
            )
        } else {
            format!(
                "0x{}",
                raw[..size].iter().map(|b| format!("{:02x}", b)).collect::<String>()
            )
        };
        regs.push(models::RegisterValue {
            name,
            value: hex_value,
            size: size as u32,
        });
    }

    let arch = match engine.control.get_actual_processor_type() {
        Ok(IMAGE_FILE_MACHINE_AMD64) => "x64",
        Ok(IMAGE_FILE_MACHINE_I386) => "x86",
        Ok(IMAGE_FILE_MACHINE_ARM64) => "arm64",
        _ => "unknown",
    };

    Ok(models::RegisterState {
        architecture: arch.to_string(),
        registers: regs,
    })
}

/// Resolve a type from live debug symbols via IDebugSymbols3: the type's size
/// plus each field's offset, size, and type name. Requires a stopped target with
/// symbols that carry type information (e.g. `nt!_EPROCESS` on a kernel target,
/// or a user module with private/type-bearing symbols).
fn do_resolve_type(engine: &DebugEngine, type_name: &str) -> Result<models::TypeInfo> {
    let (type_id, module) = engine.symbols.get_symbol_type(type_name)?;
    let size = engine.symbols.get_type_size(module, type_id).unwrap_or(0);

    let mut fields = Vec::new();
    let mut index = 0u32;
    loop {
        // GetFieldName errors (or returns empty) once we walk past the last field.
        let field_name = match engine.symbols.get_field_name(module, type_id, index) {
            Ok(name) if !name.is_empty() => name,
            _ => break,
        };
        let (field_type_id, offset) = engine
            .symbols
            .get_field_type_and_offset(module, type_id, &field_name)
            .unwrap_or((0, 0));
        let field_size = engine.symbols.get_type_size(module, field_type_id).unwrap_or(0);
        let field_type = engine
            .symbols
            .get_type_name(module, field_type_id)
            .unwrap_or_default();
        fields.push(models::TypeField {
            name: field_name,
            offset,
            size: field_size,
            type_name: field_type,
        });
        index += 1;
        if index > 8192 {
            break; // defensive bound against a malformed field list
        }
    }

    Ok(models::TypeInfo {
        name: type_name.to_string(),
        size,
        type_id,
        fields,
    })
}

/// Helper: try to get the process name from the OS given a PID.
#[cfg(target_os = "windows")]
fn get_process_name_from_pid(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 512];
        let len = GetModuleBaseNameW(handle, None, &mut buf);
        let _ = CloseHandle(handle);
        if len == 0 {
            return None;
        }
        let name = String::from_utf16_lossy(&buf[..len as usize]);
        Some(name)
    }
}

#[cfg(not(target_os = "windows"))]
fn get_process_name_from_pid(_pid: u32) -> Option<String> {
    None
}

/// Read a `UNICODE_STRING { u16 Length; u16 MaximumLength; u64 Buffer; }` at
/// `addr` (x64 layout: Buffer at +8 after 2-byte length fields + 4 bytes padding)
/// and decode its UTF-16LE contents. Returns None on failure or empty.
fn read_unicode_string(engine: &DebugEngine, addr: u64) -> Option<String> {
    let length = engine.data_spaces.read_u16(addr).ok()?; // in bytes
    if length == 0 {
        return None;
    }
    let buffer_ptr = engine.data_spaces.read_u64(addr + 8).ok()?;
    if buffer_ptr == 0 {
        return None;
    }
    let len = (length as usize).min(2048);
    let mut bytes = vec![0u8; len];
    let read = engine.data_spaces.read_virtual(buffer_ptr, &mut bytes).ok()?;
    bytes.truncate(read as usize);
    let utf16: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&utf16);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Enumerate loaded kernel modules by walking `nt!PsLoadedModuleList`, a doubly
/// linked list of `_KLDR_DATA_TABLE_ENTRY` threaded through `InLoadOrderLinks`.
/// List head and all field offsets are resolved from symbols (no hardcoded
/// layout), so this tracks struct changes across Windows versions. Requires a
/// kernel target with `nt` symbols; on other targets the symbol lookup fails and
/// the error propagates.
fn do_list_drivers(engine: &DebugEngine) -> Result<Vec<models::DriverInfo>> {
    let list_head = engine.symbols.get_offset_by_name("nt!PsLoadedModuleList")?;
    let ty = "nt!_KLDR_DATA_TABLE_ENTRY";
    // InLoadOrderLinks is the list linkage (offset 0 in practice, but resolved).
    let off_links = engine.symbols.get_field_offset(ty, "InLoadOrderLinks").unwrap_or(0) as u64;
    // If public symbols do not carry type information, fall back to the stable
    // x64 layout of _KLDR_DATA_TABLE_ENTRY so driver enumeration still works.
    let is_x64 = engine.control.get_actual_processor_type().ok() == Some(IMAGE_FILE_MACHINE_AMD64);
    let (off_base, off_size, off_name) = match (
        engine.symbols.get_field_offset(ty, "DllBase"),
        engine.symbols.get_field_offset(ty, "SizeOfImage"),
        engine.symbols.get_field_offset(ty, "BaseDllName"),
    ) {
        (Ok(b), Ok(s), Ok(n)) => (b as u64, s as u64, n as u64),
        _ if is_x64 => (0x30, 0x40, 0x58),
        _ => {
            return Err(DebugError::Target {
                message: "driver enumeration requires nt!_KLDR_DATA_TABLE_ENTRY type info".to_string(),
            });
        }
    };

    let mut drivers = Vec::new();
    // The head's Flink (first 8 bytes) points to the first entry's InLoadOrderLinks.
    let mut cur = engine.data_spaces.read_u64(list_head)?;
    let mut guard = 0u32;
    while cur != 0 && cur != list_head {
        let entry = cur.wrapping_sub(off_links); // base of _KLDR_DATA_TABLE_ENTRY
        let base = engine.data_spaces.read_u64(entry + off_base).unwrap_or(0);
        let size = engine.data_spaces.read_u32(entry + off_size).unwrap_or(0) as u64;
        let name = read_unicode_string(engine, entry + off_name)
            .unwrap_or_else(|| format!("driver_{:#x}", base));
        drivers.push(models::DriverInfo {
            name,
            base_address: base,
            size,
            flags: 0,
        });
        // Advance via this node's Flink.
        cur = engine.data_spaces.read_u64(cur)?;
        guard += 1;
        if guard > 8192 {
            break; // corruption / cycle guard
        }
    }
    Ok(drivers)
}

/// Symbol-resolved offsets/addresses needed to decode handle-table entries.
struct HandleCtx {
    off_typeindex: u64,
    off_body: u64,
    off_objtype_name: u64,
    cookie: u8,
    obtypeindextable: u64,
    pid: u32,
}

// Windows 10/11 x64 handle-table geometry (stable on this ABI).
const HANDLE_ENTRY_SIZE: u64 = 16;
const HANDLE_PAGE_SIZE: u64 = 4096;
const HANDLES_PER_TABLE: u64 = HANDLE_PAGE_SIZE / HANDLE_ENTRY_SIZE; // 256
const PTRS_PER_TABLE: u64 = HANDLE_PAGE_SIZE / 8; // 512

/// Decode a single `_HANDLE_TABLE_ENTRY` at `entry_addr` into a `HandleInfo`.
/// Returns None for empty/free slots.
fn decode_handle_entry(
    engine: &DebugEngine,
    ctx: &HandleCtx,
    entry_addr: u64,
    handle_val: u64,
) -> Option<models::HandleInfo> {
    let low = engine.data_spaces.read_u64(entry_addr).ok()?;
    if low == 0 {
        return None;
    }
    // Win10/11 x64 _HANDLE_TABLE_ENTRY.LowValue is a bitfield:
    //   Unlocked:1, RefCnt:16, Attributes:3, ObjectPointerBits:44
    // The _OBJECT_HEADER pointer lives in ObjectPointerBits (bits 20..63), stored
    // right-shifted by 4 (objects are 16-byte aligned). Reconstruct the canonical
    // kernel address: (ObjectPointerBits << 4) | kernel sign-extension. The old
    // code masked bits 4..47 verbatim, omitting the net >>16 shift and producing
    // a garbage address that poisoned every downstream read (TypeIndex, XOR
    // decode, and the returned object pointer).
    let object_pointer_bits = low >> 20;
    let header = (object_pointer_bits << 4) | 0xFFFF_0000_0000_0000;
    if header == 0xFFFF_0000_0000_0000 {
        return None; // no object encoded
    }
    let high = engine.data_spaces.read_u64(entry_addr + 8).unwrap_or(0);
    let granted_access = (high & 0x01FF_FFFF) as u32; // GrantedAccessBits (25 bits)

    // Object type: TypeIndex ^ (2nd-least-significant byte of header addr) ^ cookie.
    let type_index = engine.data_spaces.read_u8(header + ctx.off_typeindex).unwrap_or(0);
    let idx = type_index ^ (((header >> 8) & 0xFF) as u8) ^ ctx.cookie;
    let object_type = resolve_object_type_name(engine, ctx, idx)
        // Fail loudly rather than emit a plausible-but-wrong name.
        .unwrap_or_else(|| format!("<invalid type index {}>", idx));

    Some(models::HandleInfo {
        handle: handle_val,
        object_type,
        object: header.wrapping_add(ctx.off_body), // object body pointer
        granted_access,
        process_id: ctx.pid,
    })
}

/// Resolve an object type name via `nt!ObTypeIndexTable[idx] -> _OBJECT_TYPE.Name`.
/// Returns None if the index is out of the valid range or the slot is empty.
fn resolve_object_type_name(engine: &DebugEngine, ctx: &HandleCtx, idx: u8) -> Option<String> {
    // Index 0 is unused, 1 is the reserved "type" sentinel on Win10/11.
    if idx < 2 {
        return None;
    }
    let ptr = engine
        .data_spaces
        .read_u64(ctx.obtypeindextable + (idx as u64) * 8)
        .ok()?;
    if ptr == 0 {
        return None;
    }
    read_unicode_string(engine, ptr + ctx.off_objtype_name)
}

/// Walk one level-0 `_HANDLE_TABLE_ENTRY` array (`HANDLES_PER_TABLE` entries),
/// appending decoded handles. `base_handle` is the handle value of entry 0.
fn walk_level0_table(
    engine: &DebugEngine,
    ctx: &HandleCtx,
    table_base: u64,
    base_handle: u64,
    out: &mut Vec<models::HandleInfo>,
) {
    for i in 0..HANDLES_PER_TABLE {
        let entry_addr = table_base + i * HANDLE_ENTRY_SIZE;
        let handle_val = base_handle + i * 4; // handles step by 4
        if let Some(h) = decode_handle_entry(engine, ctx, entry_addr, handle_val) {
            out.push(h);
        }
    }
}

/// Find the `_EPROCESS` for `pid` by walking `nt!PsActiveProcessHead`.
fn find_eprocess(
    engine: &DebugEngine,
    pid: u32,
    off_links: u64,
    off_unique_id: u64,
) -> Result<u64> {
    let head = engine.symbols.get_offset_by_name("nt!PsActiveProcessHead")?;
    let mut cur = engine.data_spaces.read_u64(head)?;
    let mut guard = 0u32;
    while cur != 0 && cur != head {
        let eproc = cur.wrapping_sub(off_links);
        let upid = engine.data_spaces.read_u64(eproc + off_unique_id).unwrap_or(0);
        if upid as u32 == pid {
            return Ok(eproc);
        }
        cur = engine.data_spaces.read_u64(cur)?;
        guard += 1;
        if guard > 100_000 {
            break;
        }
    }
    Err(DebugError::Target {
        message: format!("process with pid {} not found in PsActiveProcessHead", pid),
    })
}

/// Enumerate handles for `pid` by walking its `_HANDLE_TABLE`. All struct offsets
/// and globals are resolved from symbols; the handle-entry decode and geometry are
/// Windows 10/11 x64 specific. Requires a kernel target with `nt` symbols.
fn do_list_handles(engine: &DebugEngine, pid: u32) -> Result<Vec<models::HandleInfo>> {
    let sym = &engine.symbols;
    let off_links = sym.get_field_offset("nt!_EPROCESS", "ActiveProcessLinks")? as u64;
    let off_unique_id = sym.get_field_offset("nt!_EPROCESS", "UniqueProcessId")? as u64;
    let off_objtable = sym.get_field_offset("nt!_EPROCESS", "ObjectTable")? as u64;
    let off_tablecode = sym.get_field_offset("nt!_HANDLE_TABLE", "TableCode")? as u64;
    let off_typeindex = sym.get_field_offset("nt!_OBJECT_HEADER", "TypeIndex")? as u64;
    let off_body = sym.get_field_offset("nt!_OBJECT_HEADER", "Body").unwrap_or(0x30) as u64;
    let off_objtype_name = sym.get_field_offset("nt!_OBJECT_TYPE", "Name")? as u64;

    let cookie_addr = sym.get_offset_by_name("nt!ObHeaderCookie")?;
    let cookie = engine.data_spaces.read_u8(cookie_addr)?;
    let obtypeindextable = sym.get_offset_by_name("nt!ObTypeIndexTable")?;

    let ctx = HandleCtx {
        off_typeindex,
        off_body,
        off_objtype_name,
        cookie,
        obtypeindextable,
        pid,
    };

    let eproc = find_eprocess(engine, pid, off_links, off_unique_id)?;
    let handle_table = engine.data_spaces.read_u64(eproc + off_objtable)?;
    if handle_table == 0 {
        return Ok(Vec::new());
    }
    let table_code = engine.data_spaces.read_u64(handle_table + off_tablecode)?;
    let level = table_code & 0x7;
    let base = table_code & !0x7u64;

    let mut out = Vec::new();
    match level {
        0 => {
            walk_level0_table(engine, &ctx, base, 0, &mut out);
        }
        1 => {
            // base is an array of pointers to level-0 tables.
            for p in 0..PTRS_PER_TABLE {
                let t = engine.data_spaces.read_u64(base + p * 8).unwrap_or(0);
                let base_handle = p * HANDLES_PER_TABLE * 4;
                if t != 0 {
                    walk_level0_table(engine, &ctx, t, base_handle, &mut out);
                }
            }
        }
        2 => {
            // base is an array of pointers to level-1 tables.
            for p1 in 0..PTRS_PER_TABLE {
                let mid = engine.data_spaces.read_u64(base + p1 * 8).unwrap_or(0);
                if mid == 0 {
                    continue;
                }
                for p0 in 0..PTRS_PER_TABLE {
                    let t = engine.data_spaces.read_u64(mid + p0 * 8).unwrap_or(0);
                    let base_handle =
                        (p1 * PTRS_PER_TABLE + p0) * HANDLES_PER_TABLE * 4;
                    if t != 0 {
                        walk_level0_table(engine, &ctx, t, base_handle, &mut out);
                    }
                }
            }
        }
        other => {
            return Err(DebugError::NotSupported {
                message: format!("unexpected handle table level {}", other),
            });
        }
    }
    Ok(out)
}

/// Helper: process a single command on the engine thread.
/// Returns `true` if the thread should exit.
fn handle_command(
    engine: &DebugEngine,
    interrupt_control: &DebugControl,
    cmd: EngineCommand,
) -> bool {
    match cmd {
        EngineCommand::AttachProcess { pid, respond } => {
            // Ask the engine to break in as soon as the attach completes.
            // Without this option, an already-running target may not generate
            // an initial event, leaving the data-plane context uninitialized.
            let _ = engine.control.add_engine_options(DEBUG_ENGOPT_INITIAL_BREAK);
            let result = engine.client.attach_process(0, pid, 0);
            if result.is_ok() {
                // Pump events until the target reaches a stopped state with
                // valid thread context. Re-arm the interrupt on each timeout
                // so a busy target still gets broken in.
                let deadline = std::time::Instant::now()
                    + std::time::Duration::from_millis(ATTACH_WAIT_TIMEOUT_MS as u64);
                let mut wait_result = Ok(());
                let mut status = Ok(DEBUG_STATUS_BREAK);
                // The initial breakpoint callback returns GO_HANDLED so the
                // engine consumes the breakpoint. Use a passive interrupt to
                // stop the target with valid context for the user.
                let _ = interrupt_control.set_interrupt(DEBUG_INTERRUPT_PASSIVE);
                while std::time::Instant::now() < deadline {
                    wait_result = engine.control.wait_for_event(0, 500);
                    status = engine.control.get_execution_status();
                    if matches!(status, Ok(DEBUG_STATUS_BREAK)) {
                        break;
                    }
                    if wait_result.is_err() {
                        break;
                    }
                    let _ = interrupt_control.set_interrupt(DEBUG_INTERRUPT_PASSIVE);
                }

                // On the initial break, the engine's injected breakpoint is
                // handled by the event callback returning DEBUG_STATUS_GO_HANDLED;
                // we deliberately do NOT remove breakpoints here, because that can
                // corrupt the engine's internal breakpoint tracking.

                let result = match (wait_result, status) {
                    (Ok(()), Ok(DEBUG_STATUS_BREAK)) => Ok(()),
                    (Err(e), _) | (_, Err(e)) => Err(DebugError::Target {
                        message: format!(
                            "process {} attached but failed to break in: {}",
                            pid, e
                        ),
                    }),
                    (Ok(()), Ok(other)) => Err(DebugError::Target {
                        message: format!(
                            "process {} attached but execution status is {} (expected break)",
                            pid, other
                        ),
                    }),
                };
                let _ = respond.send(result);
            } else {
                let _ = respond.send(result);
            }
            false
        }
        EngineCommand::AttachKernel { connect_string, respond } => {
            let result = engine.client.attach_kernel(0, &connect_string);
            if result.is_ok() {
                // Kernel-mode attach completes synchronously inside
                // WaitForEvent.  Unlike user-mode, a finite timeout causes
                // WaitForEvent to return E_NOTIMPL and leaves the session in
                // DEBUG_STATUS_NO_DEBUGGEE, so we must wait indefinitely until
                // the target generates its initial break-in event.
                let _ = engine.control.add_engine_options(DEBUG_ENGOPT_INITIAL_BREAK);
                match engine.control.wait_for_event(0, 0xFFFFFFFF) {
                    Ok(()) => {
                        // Force symbol reload now that the kernel module is
                        // present; without this, type information needed for
                        // kernel introspection (e.g. _KLDR_DATA_TABLE_ENTRY)
                        // may not be available.
                        let _ = engine.symbols.reload("");
                    }
                    Err(e) => {
                        let _ = respond.send(Err(e));
                        return false;
                    }
                }
            }
            let _ = respond.send(result);
            false
        }
        EngineCommand::OpenDumpFile { path, respond } => {
            let result = engine.client.open_dump_file(&path);
            if result.is_ok() {
                let _ = engine.control.wait_for_event(0, ATTACH_WAIT_TIMEOUT_MS);
            }
            let _ = respond.send(result);
            false
        }
        EngineCommand::Detach { respond } => {
            // Break in first: EndSession on a running target can hang (see
            // ensure_stopped_for_session_end).
            ensure_stopped_for_session_end(engine, interrupt_control);
            let flags = if engine.target_type == "dump" {
                DEBUG_END_PASSIVE
            } else {
                DEBUG_END_ACTIVE_DETACH
            };
            let result = engine.client.end_session(flags);
            let _ = respond.send(result);
            true
        }
        EngineCommand::Break { respond } => {
            if is_target_running(engine) {
                let _ = interrupt_control.set_interrupt(DEBUG_INTERRUPT_PASSIVE);
                // Wait for the interrupt to take effect so the target is fully
                // stopped with valid context before the command returns.
                if engine.target_type == "kernel" {
                    // Kernel-mode WaitForEvent requires an infinite timeout;
                    // a finite timeout returns E_NOTIMPL and leaves the session
                    // without a valid context.
                    if let Err(e) = engine.control.wait_for_event(0, 0xFFFFFFFF) {
                        let _ = respond.send(Err(e));
                        return false;
                    }
                } else {
                    let _ = engine.control.wait_for_event(0, 5_000);
                }
                // A WaitForEvent timeout returns S_FALSE (Ok), so verify the
                // target actually stopped rather than trusting the wait result.
                if is_target_running(engine) {
                    let _ = respond.send(Err(DebugError::Target {
                        message: "target did not stop within the interrupt timeout; it may be in an uninterruptible state".to_string(),
                    }));
                    return false;
                }
            }
            let _ = respond.send(Ok(()));
            false
        }
        EngineCommand::Resume { respond } => {
            if is_target_running(engine) {
                let _ = respond.send(Err(DebugError::InvalidParameter {
                    message: "Target is already running".to_string(),
                }));
                return false;
            }
            let result = engine.control.set_execution_status(DEBUG_STATUS_GO);
            let _ = respond.send(result);
            false
        }
        EngineCommand::Step { respond } => {
            let result = engine.control.set_execution_status(DEBUG_STATUS_STEP_INTO);
            if result.is_ok() {
                let result = engine.control.wait_for_event(0, 5000);
                let _ = respond.send(result);
            } else {
                let _ = respond.send(result);
            }
            false
        }
        EngineCommand::WaitForEvent { timeout_ms, respond } => {
            // Kernel-mode WaitForEvent rejects a finite timeout with E_NOTIMPL and
            // leaves the session without a valid context; coerce it to infinite.
            let effective = if engine.target_type == "kernel" && timeout_ms != 0xFFFFFFFF {
                0xFFFFFFFF
            } else {
                timeout_ms
            };
            let result = engine.control.wait_for_event(0, effective);
            let _ = respond.send(result);
            false
        }
        EngineCommand::ReadMemory { address, size, respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            if size > MAX_MEMORY_SIZE {
                let _ = respond.send(Err(DebugError::InvalidParameter {
                    message: format!(
                        "Memory read size {} exceeds maximum {}",
                        size, MAX_MEMORY_SIZE
                    ),
                }));
                return false;
            }
            let mut buffer = vec![0u8; size as usize];
            let result = engine
                .data_spaces
                .read_virtual(address, &mut buffer)
                .map(|read| {
                    buffer.truncate(read as usize);
                    buffer
                });
            let _ = respond.send(result);
            false
        }
        EngineCommand::WriteMemory { address, data, respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            if data.len() > MAX_MEMORY_SIZE as usize {
                let _ = respond.send(Err(DebugError::InvalidParameter {
                    message: format!(
                        "Memory write size {} exceeds maximum {}",
                        data.len(), MAX_MEMORY_SIZE
                    ),
                }));
                return false;
            }
            let result = engine
                .data_spaces
                .write_virtual(address, &data)
                .map(|w| w as usize);
            let _ = respond.send(result);
            false
        }
        EngineCommand::StackTrace { max_frames, respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            let result = do_stack_trace(engine, max_frames);
            let _ = respond.send(result);
            false
        }
        EngineCommand::ListModules { respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            let result = (|| -> Result<Vec<models::ModuleInfo>> {
                let count = engine.symbols.get_number_modules()?;
                let mut result = Vec::with_capacity(count as usize);
                for i in 0..count {
                    let (base, name, size, checksum, timestamp) = engine.symbols.get_module_info(i)?;
                    result.push(models::ModuleInfo {
                        name: name.clone(),
                        base_address: base,
                        size,
                        checksum,
                        timestamp,
                        image_name: name,
                    });
                }
                Ok(result)
            })();
            let _ = respond.send(result);
            false
        }
        EngineCommand::GetRegisters { respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            let result = do_get_registers(engine);
            let _ = respond.send(result);
            false
        }
        EngineCommand::ListProcesses { respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            // Switching the current process/thread mutates engine-wide state, so
            // save it and restore in every exit path. Safe here because all engine
            // access is serialized on this one thread; no other command observes
            // the transient switch.
            let saved_pid = engine.system.get_current_process_id();
            let saved_tid = engine.system.get_current_thread_id();
            let result = (|| -> Result<Vec<models::ProcessInfo>> {
                let count = engine.system.get_number_processes()?;
                let mut result = Vec::with_capacity(count as usize);
                // Only the live OS can be queried for a process image name, and
                // only when we are actually attached to that live process. For dump
                // and kernel targets the PID belongs to the captured system, so a
                // same-PID process on the analyst's machine would yield a wrong name.
                let query_live_os = engine.target_type == "process";
                for i in 0..count {
                    let engine_id = engine.system.get_process_id_by_index(i)?;
                    // Switch context to read this process's PEB and OS pid.
                    let (os_pid, peb) = match engine.system.set_current_process_id(engine_id) {
                        Ok(()) => (
                            engine.system.get_current_process_system_id().unwrap_or(engine_id),
                            engine.system.get_current_process_data_offset().ok(),
                        ),
                        Err(_) => (engine_id, None),
                    };
                    let name = if query_live_os {
                        get_process_name_from_pid(os_pid)
                            .unwrap_or_else(|| format!("process_{}", os_pid))
                    } else {
                        format!("process_{}", os_pid)
                    };
                    result.push(models::ProcessInfo {
                        pid: os_pid,
                        name,
                        base_address: peb,
                        peb,
                        threads: None, // would require per-process thread enumeration
                    });
                }
                Ok(result)
            })();
            // Restore the original context regardless of success/failure.
            if let Ok(pid) = saved_pid {
                let _ = engine.system.set_current_process_id(pid);
            }
            if let Ok(tid) = saved_tid {
                let _ = engine.system.set_current_thread_id(tid);
            }
            let _ = respond.send(result);
            false
        }
        EngineCommand::ListThreads { respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            // GetNumberThreads / GetThreadIdsByIndex enumerate the current process's
            // threads. Save and restore the current thread context around the loop.
            let saved_tid = engine.system.get_current_thread_id();
            let result = (|| -> Result<Vec<models::ThreadInfo>> {
                let count = engine.system.get_number_threads()?;
                let mut result = Vec::with_capacity(count as usize);
                // OS pid of the owning process (constant across this process's threads).
                let owner_pid = engine.system.get_current_process_system_id().ok();
                for i in 0..count {
                    let engine_tid = engine.system.get_thread_id_by_index(i)?;
                    // Switch context to read this thread's OS tid and TEB.
                    let (os_tid, teb) = match engine.system.set_current_thread_id(engine_tid) {
                        Ok(()) => (
                            engine.system.get_current_thread_system_id().unwrap_or(engine_tid),
                            engine.system.get_current_thread_teb().ok(),
                        ),
                        Err(_) => (engine_tid, None),
                    };
                    result.push(models::ThreadInfo {
                        tid: os_tid,
                        pid: owner_pid,
                        teb,
                        start_address: None, // would require reading the TEB/stack base
                        // The target is stopped while we enumerate, so per-thread
                        // run state is not meaningfully "running"; report unknown
                        // rather than asserting a state we did not query.
                        state: "unknown".to_string(),
                        priority: None, // would require OS-level thread priority query
                    });
                }
                Ok(result)
            })();
            // Restore the original thread context regardless of success/failure.
            if let Ok(tid) = saved_tid {
                let _ = engine.system.set_current_thread_id(tid);
            }
            let _ = respond.send(result);
            false
        }
        EngineCommand::SetBreakpoint { address, respond } => {
            let result = (|| -> Result<models::BreakpointSetResult> {
                let id = engine.control.add_breakpoint(address)?;
                Ok(models::BreakpointSetResult {
                    id,
                    address,
                    status: "set".to_string(),
                })
            })();
            let _ = respond.send(result);
            false
        }
        EngineCommand::RemoveBreakpoint { id, respond } => {
            let result = engine.control.remove_breakpoint(id);
            let _ = respond.send(result);
            false
        }
        EngineCommand::ListBreakpoints { respond } => {
            let result = engine.control.list_breakpoints();
            let _ = respond.send(result);
            false
        }
        EngineCommand::LookupSymbol { symbol, respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            let result = (|| -> Result<models::SymbolInfo> {
                let address = engine.symbols.get_offset_by_name(&symbol)?;
                let module_base = engine.symbols.get_symbol_module_base(&symbol).ok();
                // Resolve module name from base address if available
                let module_name = module_base.and_then(|base| {
                    let count = engine.symbols.get_number_modules().ok()?;
                    for i in 0..count {
                        let mod_base = engine.symbols.get_module_by_index(i).ok()?;
                        if mod_base == base {
                            let (_, name, _, _, _) = engine.symbols.get_module_info(i).ok()?;
                            return Some(name);
                        }
                    }
                    None
                });
                let (type_id, type_module) = engine.symbols.get_symbol_type(&symbol).unwrap_or((0, 0));
                // Populate size from the symbol's type when it carries type info
                // (GetTypeSize errors / returns 0 for typeless symbols).
                let size = if type_id != 0 {
                    engine
                        .symbols
                        .get_type_size(type_module, type_id)
                        .ok()
                        .filter(|&s| s != 0)
                        .map(u64::from)
                } else {
                    None
                };
                Ok(models::SymbolInfo {
                    name: symbol,
                    address,
                    module: module_name,
                    size,
                    flags: None, // would require GetSymbolFlags or similar
                })
            })();
            let _ = respond.send(result);
            false
        }
        EngineCommand::ResolveType { type_name, respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            let result = do_resolve_type(engine, &type_name);
            let _ = respond.send(result);
            false
        }
        EngineCommand::Disassemble { address, count, respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            let result = (|| -> Result<(Vec<models::Instruction>, bool)> {
                // Query the processor type once and reject unsupported ISAs before
                // touching target memory.
                let proc_type = engine.control.get_actual_processor_type().ok();
                if proc_type == Some(IMAGE_FILE_MACHINE_ARM64) {
                    return Err(DebugError::NotSupported {
                        message: "ARM64 disassembly is not supported; Zydis only handles x86/x64".to_string(),
                    });
                }
                let count = count.unwrap_or(16) as usize;
                let max_len = match proc_type {
                    Some(IMAGE_FILE_MACHINE_ARM64) => MAX_INSTRUCTION_LEN_ARM,
                    _ => MAX_INSTRUCTION_LEN_X86,
                };
                let read_size = ((count as u64).saturating_mul(max_len)) as u32;
                let max_read = MAX_MEMORY_SIZE.min(read_size);
                let mut buffer = vec![0u8; max_read as usize];
                let read = engine.data_spaces.read_virtual(address, &mut buffer)?;
                buffer.truncate(read as usize);
                let truncated = (read as u32) < max_read;
                // ARM64 was rejected above, so the target is x86 or x64.
                let arch = if proc_type == Some(IMAGE_FILE_MACHINE_AMD64) {
                    disassembler::Arch::X64
                } else {
                    disassembler::Arch::X86
                };
                let instructions = disassembler::decode_instructions(&buffer, address, arch);
                Ok((instructions.into_iter().take(count).collect(), truncated))
            })();
            let _ = respond.send(result);
            false
        }
        EngineCommand::ListDrivers { respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            let result = do_list_drivers(engine);
            let _ = respond.send(result);
            false
        }
        EngineCommand::ListHandles { pid, respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            let result = do_list_handles(engine, pid);
            let _ = respond.send(result);
            false
        }
        EngineCommand::LoadExtension { path, respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            let result = extensions::load_extension(&engine.control, &path);
            let _ = respond.send(result);
            false
        }
        EngineCommand::InvokeExtension { command, respond } => {
            if let Err(e) = require_target_stopped(engine) {
                let _ = respond.send(Err(e));
                return false;
            }
            let result = extensions::invoke_command(&engine.control, &command);
            let _ = respond.send(result);
            false
        }
        EngineCommand::PollEvents { respond } => {
            let events = engine.poll_events();
            let _ = respond.send(Ok(events));
            false
        }
        EngineCommand::Shutdown { respond } => {
            // Same root-cause fix as Detach: break in before EndSession so a
            // running target cannot wedge the engine thread (and thus hang the
            // caller waiting on the response / thread join).
            ensure_stopped_for_session_end(engine, interrupt_control);
            let flags = if engine.target_type == "dump" {
                DEBUG_END_PASSIVE
            } else {
                DEBUG_END_ACTIVE_DETACH
            };
            let _ = engine.client.end_session(flags);
            let _ = respond.send(Ok(()));
            true
        }
    }
}

fn engine_thread_loop(
    engine: DebugEngine,
    cmd_rx: mpsc::Receiver<EngineCommand>,
    interrupt_control: DebugControl,
) {
    'main: loop {
        let running = is_target_running(&engine);
        if running {
            // When the target is running we do not call WaitForEvent on a timer.
            // DbgEng's WaitForEvent can return a transient BREAK status right
            // after a resume even though the target is still running, which
            // breaks the data-plane context. Instead we stay responsive to
            // commands and only call WaitForEvent when the user explicitly
            // breaks (or detaches).
            match cmd_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(cmd) => {
                    if handle_command(&engine, &interrupt_control, cmd) {
                        break 'main;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Still running; keep listening.
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break 'main,
            }
        } else {
            // Not running: block on recv until a command arrives
            match cmd_rx.recv() {
                Ok(cmd) => {
                    if handle_command(&engine, &interrupt_control, cmd) {
                        break 'main;
                    }
                }
                Err(_) => break 'main,
            }
        }
    }
}

/// A debugging session wrapping a single dbgeng engine instance.
/// All COM interface access is confined to a single dedicated OS thread
/// to satisfy COM apartment requirements and avoid thread-affinity bugs.
pub struct DebugSession {
    pub id: String,
    pub target_type: String,
    pub target: String,
    command_tx: mpsc::Sender<EngineCommand>,
    engine_thread_handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    detached: Arc<AtomicBool>,
}

impl DebugSession {
    pub async fn create(target_type: String, target: String) -> Result<Self> {
        common::ensure_com_initialized()?;

        let (setup_tx, setup_rx) = std::sync::mpsc::channel::<Result<()>>();
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<EngineCommand>();
        let detached = Arc::new(AtomicBool::new(false));

        let thread_handle = std::thread::spawn({
            let target_type = target_type.clone();
            move || {
                if let Err(e) = common::ensure_com_initialized() {
                    let _ = setup_tx.send(Err(e));
                    return;
                }

                let client_ptr = match dbgeng::create_client() {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = setup_tx.send(Err(e));
                        return;
                    }
                };
                let client = DebugClient::new(client_ptr);
                let control = match client.query_control() {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = setup_tx.send(Err(e));
                        return;
                    }
                };
                let system = match client.query_system_objects() {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = setup_tx.send(Err(e));
                        return;
                    }
                };
                let symbols = match client.query_symbols() {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = setup_tx.send(Err(e));
                        return;
                    }
                };
                // Set a sane default symbol path.  Prefer the user's existing
                // _NT_SYMBOL_PATH; otherwise fall back to the Microsoft public
                // symbol server so kernel type information is available.
                let sym_path = std::env::var("_NT_SYMBOL_PATH")
                    .unwrap_or_else(|_| "srv*https://msdl.microsoft.com/download/symbols".to_string());
                let _ = symbols.set_symbol_path(&sym_path);

                let registers = match client.query_registers() {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = setup_tx.send(Err(e));
                        return;
                    }
                };
                let data_spaces = match client.query_data_spaces() {
                    Ok(d) => d,
                    Err(e) => {
                        let _ = setup_tx.send(Err(e));
                        return;
                    }
                };

                // Register event callbacks for breakpoint/exception notifications.
                let events_rx = match extensions::register_event_callbacks(&client.0) {
                    Ok(rx) => Some(Arc::new(Mutex::new(rx))),
                    Err(e) => {
                        let _ = setup_tx.send(Err(e));
                        return;
                    }
                };

                let interrupt_client = match client.create_client() {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = setup_tx.send(Err(e));
                        return;
                    }
                };
                let interrupt_control = match interrupt_client.query_control() {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = setup_tx.send(Err(e));
                        return;
                    }
                };

                let engine = DebugEngine {
                    client,
                    control,
                    system,
                    symbols,
                    registers,
                    data_spaces,
                    events: events_rx,
                    target_type,
                };

                let _ = setup_tx.send(Ok(()));

                engine_thread_loop(engine, cmd_rx, interrupt_control);

                // Balance the CoInitializeEx call from ensure_com_initialized.
                common::com_uninitialize();
            }
        });

        // Wait for the engine thread to finish initialization
        let setup_result = tokio::task::spawn_blocking(move || setup_rx.recv())
            .await
            .map_err(|e| DebugError::Com {
                message: format!("setup thread join: {}", e),
            })?
            .map_err(|_| DebugError::Com {
                message: "setup channel closed".to_string(),
            })?;
        setup_result?;

        Ok(Self {
            id: String::new(),
            target_type,
            target,
            command_tx: cmd_tx,
            engine_thread_handle: Mutex::new(Some(thread_handle)),
            detached,
        })
    }

    /// Explicit async shutdown that awaits the engine thread.
    /// Prefer this over Drop when you can await. Idempotent: repeated calls (or a
    /// subsequent Drop) are no-ops.
    pub async fn shutdown(&self) -> Result<()> {
        if self.detached.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.command_tx.send(EngineCommand::Shutdown { respond: tx });
        // Defense in depth: the break-in in the Shutdown handler makes EndSession
        // return promptly, but bound the wait and the join anyway so a wedged
        // engine thread can never hang the caller (a detach must always return).
        const SHUTDOWN_STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
        let _ = tokio::time::timeout(SHUTDOWN_STEP_TIMEOUT, rx).await;
        let handle = self.engine_thread_handle.lock().ok().and_then(|mut h| h.take());
        if let Some(handle) = handle {
            let join = tokio::task::spawn_blocking(move || handle.join());
            let _ = tokio::time::timeout(SHUTDOWN_STEP_TIMEOUT, join).await;
        }
        Ok(())
    }

    pub async fn attach_process(&self, pid: u32) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::AttachProcess { pid, respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "AttachProcess response channel closed".to_string(),
        })?
    }

    pub async fn attach_kernel(&self, connect_string: &str) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::AttachKernel {
                connect_string: connect_string.to_string(),
                respond: tx,
            })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "AttachKernel response channel closed".to_string(),
        })?
    }

    pub async fn open_dump_file(&self, path: &str) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::OpenDumpFile {
                path: path.to_string(),
                respond: tx,
            })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "OpenDumpFile response channel closed".to_string(),
        })?
    }

    pub async fn detach(&self) -> Result<()> {
        if self.detached.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.detached.store(true, Ordering::SeqCst);

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::Detach { respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "Detach response channel closed".to_string(),
        })?
    }

    pub async fn break_execution(&self) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::Break { respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "Break response channel closed".to_string(),
        })?
    }

    pub async fn resume(&self) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::Resume { respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "Resume response channel closed".to_string(),
        })?
    }

    pub async fn step(&self) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::Step { respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "Step response channel closed".to_string(),
        })?
    }

    pub async fn wait_for_event(&self, timeout_ms: u32) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::WaitForEvent { timeout_ms, respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "WaitForEvent response channel closed".to_string(),
        })?
    }

    pub async fn read_memory(&self, address: u64, size: u32) -> Result<Vec<u8>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::ReadMemory {
                address,
                size,
                respond: tx,
            })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "ReadMemory response channel closed".to_string(),
        })?
    }

    pub async fn write_memory(&self, address: u64, data: &[u8]) -> Result<usize> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::WriteMemory {
                address,
                data: data.to_vec(),
                respond: tx,
            })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "WriteMemory response channel closed".to_string(),
        })?
    }

    pub async fn stack_trace(&self, max_frames: u32) -> Result<Vec<models::StackFrame>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::StackTrace {
                max_frames,
                respond: tx,
            })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "StackTrace response channel closed".to_string(),
        })?
    }

    pub async fn list_modules(&self) -> Result<Vec<models::ModuleInfo>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::ListModules { respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "ListModules response channel closed".to_string(),
        })?
    }

    pub async fn get_registers(&self) -> Result<models::RegisterState> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::GetRegisters { respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "GetRegisters response channel closed".to_string(),
        })?
    }

    pub async fn list_processes(&self) -> Result<Vec<models::ProcessInfo>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::ListProcesses { respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "ListProcesses response channel closed".to_string(),
        })?
    }

    pub async fn list_threads(&self) -> Result<Vec<models::ThreadInfo>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::ListThreads { respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "ListThreads response channel closed".to_string(),
        })?
    }

    pub async fn set_breakpoint(&self, address: u64) -> Result<models::BreakpointSetResult> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::SetBreakpoint {
                address,
                respond: tx,
            })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "SetBreakpoint response channel closed".to_string(),
        })?
    }

    pub async fn remove_breakpoint(&self, id: u32) -> Result<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::RemoveBreakpoint { id, respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "RemoveBreakpoint response channel closed".to_string(),
        })?
    }

    pub async fn list_breakpoints(&self) -> Result<Vec<models::BreakpointInfo>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::ListBreakpoints { respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "ListBreakpoints response channel closed".to_string(),
        })?
    }

    pub async fn lookup_symbol(&self, symbol: &str) -> Result<models::SymbolInfo> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::LookupSymbol {
                symbol: symbol.to_string(),
                respond: tx,
            })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "LookupSymbol response channel closed".to_string(),
        })?
    }

    pub async fn resolve_type(&self, type_name: &str) -> Result<models::TypeInfo> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::ResolveType {
                type_name: type_name.to_string(),
                respond: tx,
            })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "ResolveType response channel closed".to_string(),
        })?
    }

    pub async fn disassemble(
        &self,
        address: u64,
        count: Option<u32>,
    ) -> Result<(Vec<models::Instruction>, bool)> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::Disassemble {
                address,
                count,
                respond: tx,
            })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "Disassemble response channel closed".to_string(),
        })?
    }

    pub async fn list_drivers(&self) -> Result<Vec<models::DriverInfo>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::ListDrivers { respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "ListDrivers response channel closed".to_string(),
        })?
    }

    pub async fn list_handles(&self, pid: u32) -> Result<Vec<models::HandleInfo>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::ListHandles { pid, respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "ListHandles response channel closed".to_string(),
        })?
    }

    pub async fn load_extension(&self, path: &str) -> Result<models::ExtensionResult> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::LoadExtension {
                path: path.to_string(),
                respond: tx,
            })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "LoadExtension response channel closed".to_string(),
        })?
    }

    pub async fn invoke_extension(&self, command: &str) -> Result<models::ExtensionResult> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::InvokeExtension {
                command: command.to_string(),
                respond: tx,
            })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "InvokeExtension response channel closed".to_string(),
        })?
    }

    pub async fn poll_events(&self) -> Result<Vec<extensions::DebugEvent>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.command_tx
            .send(EngineCommand::PollEvents { respond: tx })
            .map_err(|_| DebugError::Com {
                message: "command channel closed".to_string(),
            })?;
        rx.await.map_err(|_| DebugError::Com {
            message: "PollEvents response channel closed".to_string(),
        })?
    }
}

impl Drop for DebugSession {
    fn drop(&mut self) {
        // If shutdown() already ran, the flag is set and the channel is closed.
        if self.detached.swap(true, Ordering::SeqCst) {
            return;
        }
        // Send a graceful shutdown signal, but do NOT block on join.
        // The engine thread will process the Shutdown command and exit,
        // or it will detect the channel disconnect and exit on its own.
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let _ = self.command_tx.send(EngineCommand::Shutdown { respond: tx });
        // Drop the JoinHandle without joining — the thread will exit
        // when the command channel closes or when it processes Shutdown.
        if let Ok(mut h) = self.engine_thread_handle.lock() {
            let _ = h.take();
        }
    }
}
