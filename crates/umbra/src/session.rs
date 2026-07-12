use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use common::{Result, DebugError};
use models::{SessionInfo, AttachResult, SessionCreateParams, MemoryRegion, MemoryWriteResult, RegisterState, StackTraceResult, ModuleListResult, ProcessListResult, ThreadListResult, SymbolLookupResult, TypeResolveResult, DisassemblyResult, BreakpointSetResult, BreakpointListResult, DriverListResult, HandleListResult, ExtensionResult, EtwResult};
use debugger::DebugEvent;
use debugger::DebugSession;
use uuid::Uuid;

const MAX_SESSIONS: usize = 16;

pub struct SessionEntry {
    pub id: String,
    pub session: Arc<DebugSession>,
}

#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, SessionEntry>>>,
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager")
            .field("session_count", &"<opaque>")
            .finish()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Look up a session and return a cloned handle, releasing the map lock
    /// immediately. Callers must NOT hold the map's read guard across a blocking
    /// debug operation: tokio's `RwLock` is write-preferring, so a single slow op
    /// holding the read guard would let one queued writer (attach/detach) stall
    /// every other session's requests.
    async fn get(&self, session_id: &str) -> Result<Arc<DebugSession>> {
        let sessions = self.sessions.read().await;
        sessions
            .get(session_id)
            .map(|e| e.session.clone())
            .ok_or_else(|| DebugError::SessionNotFound { id: session_id.to_string() })
    }

    pub async fn create(&self, params: SessionCreateParams) -> Result<AttachResult> {
        let id = params.session_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let target = params.target.clone();

        // Phase 1: Check collision and capacity under write lock
        {
            let sessions = self.sessions.write().await;
            if sessions.contains_key(&id) {
                return Err(DebugError::InvalidParameter {
                    message: format!(
                        "Session ID '{}' already exists. Destroy it first before reusing the ID.",
                        id
                    ),
                });
            }
            if sessions.len() >= MAX_SESSIONS {
                return Err(DebugError::InvalidParameter {
                    message: format!(
                        "Maximum number of sessions ({}) reached. Destroy an existing session first.",
                        MAX_SESSIONS
                    ),
                });
            }
        } // lock dropped here

        // Phase 2: Create the session (slow COM operations, no lock held)
        let mut session = DebugSession::create(params.target_type.clone(), params.target.clone()).await?;
        session.id = id.clone();

        if params.target_type == "process" {
            match params.target.parse::<u32>() {
                Ok(pid) => {
                    if let Err(e) = session.attach_process(pid).await {
                        let _ = session.shutdown().await;
                        return Err(e);
                    }
                }
                Err(_) => {
                    return Err(common::DebugError::InvalidParameter {
                        message: format!("Invalid PID for process target: {}", params.target),
                    });
                }
            }
        } else if params.target_type == "kernel" {
            if let Err(e) = session.attach_kernel(&params.target).await {
                let _ = session.shutdown().await;
                return Err(e);
            }
        } else if params.target_type == "dump" {
            if let Err(e) = session.open_dump_file(&params.target).await {
                let _ = session.shutdown().await;
                return Err(e);
            }
        } else {
            return Err(DebugError::InvalidParameter {
                message: format!(
                    "Unknown target_type '{}'. Supported: process, kernel, dump",
                    params.target_type
                ),
            });
        }

        // Phase 3: Re-acquire lock and re-check for collision before inserting
        {
            let mut sessions = self.sessions.write().await;
            if sessions.contains_key(&id) {
                // Someone else inserted this ID while we were creating — clean up our session
                let _ = session.shutdown().await;
                return Err(DebugError::InvalidParameter {
                    message: format!(
                        "Session ID '{}' was created concurrently by another request. Try again with a different ID.",
                        id
                    ),
                });
            }
            if sessions.len() >= MAX_SESSIONS {
                let _ = session.shutdown().await;
                return Err(DebugError::InvalidParameter {
                    message: format!(
                        "Maximum number of sessions ({}) reached concurrently. Try again.",
                        MAX_SESSIONS
                    ),
                });
            }
            sessions.insert(id.clone(), SessionEntry { id: id.clone(), session: Arc::new(session) });
        }

        // Every branch above either attaches successfully or returns early, so a
        // session that reaches here is always attached.
        Ok(AttachResult {
            session_id: id,
            status: "attached".to_string(),
            target,
        })
    }

    pub async fn destroy(&self, session_id: String) -> Result<String> {
        // Clean up any ETW trace owned by this session before shutting down.
        // stop() flushes ETW buffers and can block; run off the async runtime.
        let sid = session_id.clone();
        let _ = tokio::task::spawn_blocking(move || etw::stop_trace(&sid)).await;
        let entry = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(&session_id).ok_or_else(|| {
                DebugError::SessionNotFound { id: session_id.clone() }
            })?
        };
        let _ = entry.session.shutdown().await;
        Ok(format!("Session {} destroyed", session_id))
    }

    pub async fn destroy_all(&self) -> Result<()> {
        let entries: Vec<SessionEntry> = {
            let mut sessions = self.sessions.write().await;
            sessions.drain().map(|(_, entry)| entry).collect()
        };
        for entry in entries {
            // Best-effort: stop any ETW trace this session owns.
            // stop() flushes ETW buffers and can block; run off the async runtime.
            let sid = entry.id.clone();
            let _ = tokio::task::spawn_blocking(move || etw::stop_trace(&sid)).await;
            if let Err(e) = entry.session.shutdown().await {
                tracing::warn!("Failed to shutdown session {}: {}", entry.id, e);
            }
        }
        // Final sweep: force-stop any ETW trace that outlived its owner so a
        // real-time session is never orphaned across process shutdown.
        let _ = tokio::task::spawn_blocking(etw::force_stop_trace).await;
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<SessionInfo>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.values().map(|e| SessionInfo {
            id: e.id.clone(),
            target_type: e.session.target_type.clone(),
            target: e.session.target.clone(),
            status: "active".to_string(),
        }).collect())
    }

    pub async fn break_execution(&self, session_id: &str) -> Result<String> {
        let session = self.get(session_id).await?;
        session.break_execution().await?;
        Ok("Execution broken".to_string())
    }

    pub async fn resume(&self, session_id: &str) -> Result<String> {
        let session = self.get(session_id).await?;
        session.resume().await?;
        Ok("Execution resumed".to_string())
    }

    pub async fn step(&self, session_id: &str) -> Result<String> {
        let session = self.get(session_id).await?;
        session.step().await?;
        Ok("Step executed".to_string())
    }

    pub async fn read_memory(&self, session_id: &str, address: u64, size: u32) -> Result<MemoryRegion> {
        let session = self.get(session_id).await?;
        let data = session.read_memory(address, size).await?;
        let hex = common::to_hex(&data);
        // A short buffer means ReadVirtual returned fewer bytes than requested,
        // typically because the range crossed into unmapped memory.
        let truncated = data.len() < size as usize;
        Ok(MemoryRegion {
            address,
            size: data.len(),
            data,
            hex,
            truncated,
        })
    }

    pub async fn write_memory(&self, session_id: &str, address: u64, data: Vec<u8>) -> Result<MemoryWriteResult> {
        let session = self.get(session_id).await?;
        let written = session.write_memory(address, &data).await?;
        Ok(MemoryWriteResult {
            address,
            bytes_written: written,
            status: "ok".to_string(),
        })
    }

    pub async fn get_registers(&self, session_id: &str) -> Result<RegisterState> {
        let session = self.get(session_id).await?;
        session.get_registers().await
    }

    pub async fn stack_trace(&self, session_id: &str, max_frames: Option<u32>) -> Result<StackTraceResult> {
        let session = self.get(session_id).await?;
        let max = max_frames.unwrap_or(64);
        let frames = session.stack_trace(max).await?;
        Ok(StackTraceResult { frames })
    }

    pub async fn list_modules(&self, session_id: &str) -> Result<ModuleListResult> {
        let session = self.get(session_id).await?;
        let modules = session.list_modules().await?;
        Ok(ModuleListResult { modules })
    }

    pub async fn list_processes(&self, session_id: &str) -> Result<ProcessListResult> {
        let session = self.get(session_id).await?;
        let processes = session.list_processes().await?;
        Ok(ProcessListResult { processes })
    }

    pub async fn list_threads(&self, session_id: &str) -> Result<ThreadListResult> {
        let session = self.get(session_id).await?;
        let threads = session.list_threads().await?;
        Ok(ThreadListResult { threads })
    }

    pub async fn lookup_symbol(&self, session_id: &str, symbol: String) -> Result<SymbolLookupResult> {
        let session = self.get(session_id).await?;
        let sym = session.lookup_symbol(&symbol).await?;
        Ok(SymbolLookupResult { symbols: vec![sym] })
    }

    pub async fn resolve_type(&self, session_id: &str, type_name: String) -> Result<TypeResolveResult> {
        let session = self.get(session_id).await?;
        let t = session.resolve_type(&type_name).await?;
        Ok(TypeResolveResult { types: vec![t] })
    }

    pub async fn disassemble(&self, session_id: &str, address: u64, count: Option<u32>) -> Result<DisassemblyResult> {
        let session = self.get(session_id).await?;
        let (instructions, truncated) = session.disassemble(address, count).await?;
        let end_address = instructions.last().map(|i| i.address + i.length as u64).unwrap_or(address);
        Ok(DisassemblyResult {
            instructions,
            start_address: address,
            end_address,
            truncated,
        })
    }

    pub async fn set_breakpoint(&self, session_id: &str, address: u64) -> Result<BreakpointSetResult> {
        let session = self.get(session_id).await?;
        session.set_breakpoint(address).await
    }

    pub async fn remove_breakpoint(&self, session_id: &str, id: u32) -> Result<String> {
        let session = self.get(session_id).await?;
        session.remove_breakpoint(id).await?;
        Ok(format!("Breakpoint {} removed", id))
    }

    pub async fn list_breakpoints(&self, session_id: &str) -> Result<BreakpointListResult> {
        let session = self.get(session_id).await?;
        let breakpoints = session.list_breakpoints().await?;
        Ok(BreakpointListResult { breakpoints })
    }

    pub async fn list_drivers(&self, session_id: &str) -> Result<DriverListResult> {
        let session = self.get(session_id).await?;
        let drivers = session.list_drivers().await?;
        Ok(DriverListResult { drivers })
    }

    pub async fn list_handles(&self, session_id: &str, pid: u32) -> Result<HandleListResult> {
        let session = self.get(session_id).await?;
        let handles = session.list_handles(pid).await?;
        Ok(HandleListResult { handles })
    }

    pub async fn invoke_extension(&self, session_id: &str, command: String) -> Result<ExtensionResult> {
        let session = self.get(session_id).await?;
        session.invoke_extension(&command).await
    }

    pub async fn etw_start(&self, session_id: &str, provider_name: &str) -> Result<String> {
        // Confirm the session exists, then release the lock before touching ETW.
        self.get(session_id).await?;
        // start_and_process spins up a real-time ETW session, which can block;
        // run it off the async runtime like stop/destroy do, so it cannot stall
        // other concurrent tool calls.
        let session_id = session_id.to_string();
        let provider_name = provider_name.to_string();
        tokio::task::spawn_blocking(move || etw::start_trace(&session_id, &provider_name))
            .await
            .map_err(|e| DebugError::Com {
                message: format!("ETW start thread panicked: {}", e),
            })?
    }

    pub async fn etw_stop(&self, session_id: &str) -> Result<String> {
        self.get(session_id).await?;
        // stop() flushes ETW buffers and can block; run off the async runtime.
        let session_id = session_id.to_string();
        tokio::task::spawn_blocking(move || etw::stop_trace(&session_id))
            .await
            .map_err(|e| DebugError::Com {
                message: format!("ETW stop thread panicked: {}", e),
            })?
    }

    pub async fn etw_events(&self, session_id: &str) -> Result<EtwResult> {
        self.get(session_id).await?;
        etw::events(session_id)
    }

    pub async fn poll_events(&self, session_id: &str) -> Result<Vec<DebugEvent>> {
        let session = self.get(session_id).await?;
        session.poll_events().await
    }
}
