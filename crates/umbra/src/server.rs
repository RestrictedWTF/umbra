use rmcp::{handler::server::wrapper::Parameters, tool, tool_router, tool_handler, ServerHandler};
use models::*;
use crate::session::SessionManager;
use crate::ttd_manager::TtdManager;
use common::{validate_command_arg, validate_debugger_command};
use std::sync::Arc;

#[derive(Clone)]
pub struct DebugMcpServer {
    pub session_manager: Arc<SessionManager>,
    pub ttd_manager: Arc<TtdManager>,
}

impl DebugMcpServer {
    pub fn new() -> Self {
        Self {
            session_manager: Arc::new(SessionManager::new()),
            ttd_manager: Arc::new(TtdManager::new()),
        }
    }

    fn to_json<T: serde::Serialize>(value: &T) -> String {
        serde_json::to_string_pretty(value).unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}).to_string())
    }
}

#[tool_router]
impl DebugMcpServer {
    #[tool(description = "Create a new debugging session and attach to a target")]
    async fn debug_attach(&self, Parameters(params): Parameters<SessionCreateParams>) -> String {
        match self.session_manager.create(params).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Destroy a debugging session and detach from target")]
    async fn debug_detach(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.destroy(params.session_id).await {
            Ok(result) => result,
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "List all active debugging sessions")]
    async fn session_list(&self) -> String {
        match self.session_manager.list().await {
            Ok(sessions) => Self::to_json(&SessionListResult { sessions }),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Break execution in the target")]
    async fn debug_break(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.break_execution(&params.session_id).await {
            Ok(result) => result,
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Resume execution in the target")]
    async fn debug_resume(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.resume(&params.session_id).await {
            Ok(result) => result,
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Step execution in the target")]
    async fn debug_step(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.step(&params.session_id).await {
            Ok(result) => result,
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Read memory from the target")]
    async fn debug_read_memory(&self, Parameters(params): Parameters<MemoryReadParams>) -> String {
        match self.session_manager.read_memory(&params.session_id, params.address.into(), params.size).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Write memory to the target")]
    async fn debug_write_memory(&self, Parameters(params): Parameters<MemoryWriteParams>) -> String {
        match self.session_manager.write_memory(&params.session_id, params.address.into(), params.data).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Get register values from the target")]
    async fn debug_get_registers(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.get_registers(&params.session_id).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Get stack trace from the target")]
    async fn debug_stack_trace(&self, Parameters(params): Parameters<StackTraceParams>) -> String {
        match self.session_manager.stack_trace(&params.session_id, params.max_frames).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "List loaded modules in the target")]
    async fn debug_list_modules(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.list_modules(&params.session_id).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "List processes in the target debugging session")]
    async fn debug_list_processes(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.list_processes(&params.session_id).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "List threads in the target debugging session")]
    async fn debug_list_threads(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.list_threads(&params.session_id).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Lookup a symbol by name in the target debugging session")]
    async fn symbols_lookup(&self, Parameters(params): Parameters<SymbolLookupParams>) -> String {
        match self.session_manager.lookup_symbol(&params.session_id, params.symbol).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Resolve a type's layout (size and field offsets) from a live debugging session's symbols, e.g. nt!_EPROCESS")]
    async fn debug_resolve_type(&self, Parameters(params): Parameters<ResolveTypeParams>) -> String {
        match self.session_manager.resolve_type(&params.session_id, params.type_name).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Disassemble instructions at a given address in the target debugging session")]
    async fn debug_disassemble(&self, Parameters(params): Parameters<DisassembleParams>) -> String {
        match self.session_manager.disassemble(&params.session_id, params.address.into(), params.count).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Set a breakpoint at an address in the target debugging session")]
    async fn debug_set_breakpoint(&self, Parameters(params): Parameters<BreakpointSetParams>) -> String {
        match self.session_manager.set_breakpoint(&params.session_id, params.address.into()).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Remove a breakpoint by ID in the target debugging session")]
    async fn debug_remove_breakpoint(&self, Parameters(params): Parameters<BreakpointRemoveParams>) -> String {
        match self.session_manager.remove_breakpoint(&params.session_id, params.id).await {
            Ok(result) => result,
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "List all breakpoints in the target debugging session")]
    async fn debug_list_breakpoints(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.list_breakpoints(&params.session_id).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "List kernel drivers in the target debugging session")]
    async fn kernel_list_drivers(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.list_drivers(&params.session_id).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "List handles for a process in the target debugging session")]
    async fn kernel_list_handles(&self, Parameters(params): Parameters<KernelHandleListParams>) -> String {
        match self.session_manager.list_handles(&params.session_id, params.pid).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Invoke an extension command in the target debugging session")]
    async fn extensions_invoke(&self, Parameters(params): Parameters<ExtensionInvokeParams>) -> String {
        match validate_command_arg(&params.extension) {
            Ok(_) => {},
            Err(e) => return serde_json::json!({"error": e.to_string()}).to_string(),
        }
        match validate_command_arg(&params.command) {
            Ok(_) => {},
            Err(e) => return serde_json::json!({"error": e.to_string()}).to_string(),
        }
        let ext = params.extension.clone();
        let cmd = params.command.clone();
        let command = if ext.is_empty() {
            match params.args.as_deref() {
                Some(a) => match validate_command_arg(a) {
                    Ok(a) => format!("{} {}", cmd, a),
                    Err(e) => return serde_json::json!({"error": e.to_string()}).to_string(),
                },
                None => cmd.to_string(),
            }
        } else {
            match params.args.as_deref() {
                Some(a) => match validate_command_arg(a) {
                    Ok(a) => format!("!{}.{} {}", ext, cmd, a),
                    Err(e) => return serde_json::json!({"error": e.to_string()}).to_string(),
                },
                None => format!("!{}.{}", ext, cmd),
            }
        };
        // Reject host/script execution verbs up front (also enforced at the sink).
        if let Err(e) = validate_debugger_command(&command) {
            return serde_json::json!({"error": e.to_string()}).to_string();
        }
        match self.session_manager.invoke_extension(&params.session_id, command).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Start an ETW trace for a provider in the target debugging session")]
    async fn etw_start(&self, Parameters(params): Parameters<EtwStartParams>) -> String {
        match self.session_manager.etw_start(&params.session_id, &params.provider_name).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Stop an ETW trace in the target debugging session")]
    async fn etw_stop(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.etw_stop(&params.session_id).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Get ETW events collected in the target debugging session")]
    async fn etw_events(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.etw_events(&params.session_id).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Poll pending debugger events (breakpoints, exceptions, module loads, etc.) from the target debugging session")]
    async fn debug_poll_events(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.session_manager.poll_events(&params.session_id).await {
            Ok(events) => Self::to_json(&events),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Open a TTD (Time Travel Debugging) .run trace file for replay; returns a TTD session id and the trace's first/last positions")]
    async fn ttd_open(&self, Parameters(params): Parameters<TtdOpenParams>) -> String {
        match self.ttd_manager.open(&params.trace_path, params.session_id).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Seek to a specific position (sequence:step) in an opened TTD trace")]
    async fn ttd_seek(&self, Parameters(params): Parameters<TtdSeekParams>) -> String {
        match self.ttd_manager.seek(&params.session_id, params.sequence, params.step).await {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Close an opened TTD trace and free its replay engine and cursor")]
    async fn ttd_close(&self, Parameters(params): Parameters<GenericSessionParams>) -> String {
        match self.ttd_manager.close(&params.session_id).await {
            Ok(result) => result,
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "Resolve a type from a PDB file (offline, no session required)")]
    async fn pdb_resolve_type(&self, Parameters(params): Parameters<PdbResolveTypeParams>) -> String {
        match symbols::resolve_type_from_pdb(&params.pdb_path, &params.type_name) {
            Ok(result) => Self::to_json(&result),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    #[tool(description = "List all named types in a PDB file (offline, no session required)")]
    async fn pdb_list_types(&self, Parameters(params): Parameters<PdbListTypesParams>) -> String {
        match symbols::list_types_in_pdb(&params.pdb_path) {
            Ok(types) => Self::to_json(&types),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }
}

#[tool_handler(name = "umbra", version = "0.1.0")]
impl ServerHandler for DebugMcpServer {}
