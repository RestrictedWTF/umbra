use common::{DebugError, Result};
use models::{EtwEvent, EtwResult};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ferrisetw::{
    provider::Provider,
    parser::Parser,
    trace::UserTrace,
};

/// Validate a canonical `8-4-4-4-12` hex GUID (no braces). ferrisetw's
/// `Provider::by_guid` PANICS on a malformed GUID (non-hex bytes or misplaced
/// dashes), so any GUID-shaped input must be checked before it is handed over.
fn is_valid_guid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, &c) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// Known ETW provider name → GUID mapping.
fn resolve_provider_guid(name: &str) -> Option<String> {
    let map: HashMap<&str, &str> = [
        ("Microsoft-Windows-Kernel-Process", "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"),
        ("Microsoft-Windows-Kernel-File", "edd08927-9cc4-4e65-b970-c2560fb5c289"),
        ("Microsoft-Windows-Kernel-Registry", "8c57af29-5519-4f1c-89d7-012003a327b5"),
        ("Microsoft-Windows-Kernel-Network", "7c11e9a3-5e3e-4e46-bad5-2a9b336b6f6e"),
        ("Microsoft-Windows-DNS-Client", "1c95126e-7eea-49a9-a3fe-a378b03d3b2e"),
    ]
    .iter()
    .cloned()
    .collect();

    // Exact match first
    if let Some(guid) = map.get(name) {
        return Some(guid.to_string());
    }

    // Case-insensitive match
    let lower = name.to_lowercase();
    for (k, v) in &map {
        if k.to_lowercase() == lower {
            return Some(v.to_string());
        }
    }

    // If the input is a valid GUID (optionally brace-wrapped), use it directly.
    let guid_like = name.trim().trim_start_matches('{').trim_end_matches('}');
    if is_valid_guid(guid_like) {
        return Some(guid_like.to_string());
    }

    None
}

/// Shared ETW state across all sessions.
struct EtwState {
    trace: Option<UserTrace>,
    events: Arc<Mutex<Vec<EtwEvent>>>,
    /// Which debug session owns this trace, so other sessions can't stop/read it.
    owner_session_id: Option<String>,
}

impl Default for EtwState {
    fn default() -> Self {
        Self {
            trace: None,
            events: Arc::new(Mutex::new(Vec::new())),
            owner_session_id: None,
        }
    }
}

lazy_static::lazy_static! {
    static ref ETW_STATE: Mutex<EtwState> = Mutex::new(EtwState::default());
}

/// Upper bound on buffered ETW events. A high-volume provider (e.g. Kernel-File)
/// can emit events far faster than a client polls `etw_events`; without a cap the
/// backing Vec would grow until the process is OOM-killed. When full, new events
/// are dropped (best-effort), mirroring the bounded debugger-event channel.
const MAX_ETW_EVENTS: usize = 100_000;

/// Start an ETW trace for the given provider.
/// If a trace is already running, returns an error.
pub fn start_trace(session_id: &str, provider_name: &str) -> Result<String> {
    let guid_str = resolve_provider_guid(provider_name).ok_or_else(|| {
        DebugError::InvalidParameter {
            message: format!(
                "Unknown ETW provider '{}'. Known providers: Microsoft-Windows-Kernel-Process, \
                 Microsoft-Windows-Kernel-File, Microsoft-Windows-Kernel-Registry, \
                 Microsoft-Windows-Kernel-Network, Microsoft-Windows-DNS-Client. \
                 Or pass a GUID directly.",
                provider_name
            ),
        }
    })?;

    let mut state = ETW_STATE.lock().map_err(|_| DebugError::Com {
        message: "ETW state lock poisoned".to_string(),
    })?;

    // Prevent silently killing another session's trace. ETW is system-global -
    // only one real-time trace per trace name is allowed by the OS.
    if state.trace.is_some() {
        return Err(DebugError::InvalidParameter {
            message: "ETW trace already running. Only one system-wide trace is supported at a time. Stop it before starting another.".to_string(),
        });
    }

    let events = state.events.clone();
    let provider_name_owned = provider_name.to_string();

    let provider = Provider::by_guid(&guid_str[..])
        .add_callback(move |record, schema_locator| {
            // Use the event's own ETW timestamp rather than the drain-time wall
            // clock, which was skewed by buffer-flush latency and collapsed many
            // events onto the same instant. raw_timestamp() is a FILETIME
            // (100ns ticks since 1601-01-01) in the default system-time mode;
            // convert to unix-epoch milliseconds.
            const FILETIME_TO_UNIX_100NS: i64 = 116_444_736_000_000_000;
            let unix_ms = (record.raw_timestamp() - FILETIME_TO_UNIX_100NS) / 10_000;
            let timestamp = unix_ms.to_string();

            let mut payload = serde_json::Map::new();

            // Best-effort schema-based parsing. ferrisetw does not expose the
            // event's property list publicly, so we probe a broad set of common
            // field names across the supported providers rather than enumerating.
            if let Ok(schema) = schema_locator.event_schema(record) {
                let parser = Parser::create(record, &schema);
                for field in &[
                    // process / thread
                    "ProcessID", "ProcessId", "ThreadID", "ThreadId",
                    "ParentProcessID", "ParentProcessId", "ExitStatus",
                    "ImageName", "ImageFileName", "CommandLine",
                    // file / registry
                    "FileName", "FileKey", "Path", "KeyName", "KeyHandle",
                    "ValueName", "RelativeName",
                    // network / DNS
                    "QueryName", "QueryType", "QueryResults", "Address",
                    "daddr", "saddr", "dport", "sport", "connid",
                    // generic status/handle/object
                    "Status", "Result", "ReturnCode", "Handle", "Object",
                    "Irp", "IoSize",
                ] {
                    if let Ok(val) = parser.try_parse::<u32>(field) {
                        payload.insert(field.to_string(), serde_json::Value::from(val));
                    } else if let Ok(val) = parser.try_parse::<u64>(field) {
                        payload.insert(field.to_string(), serde_json::Value::from(val));
                    } else if let Ok(val) = parser.try_parse::<String>(field) {
                        payload.insert(field.to_string(), serde_json::Value::from(val));
                    }
                }
            }

            let event = EtwEvent {
                provider_id: provider_name_owned.clone(),
                event_id: record.event_id(),
                timestamp,
                process_id: record.process_id(),
                thread_id: record.thread_id(),
                payload: serde_json::Value::Object(payload),
            };

            if let Ok(mut buf) = events.lock() {
                if buf.len() < MAX_ETW_EVENTS {
                    buf.push(event);
                }
                // else: buffer full — drop (best-effort). Poll etw_events sooner.
            }
        })
        .build();

    // Make the real-time session name unique per process. ETW sessions are
    // kernel objects that survive a hard crash of this process; a fixed name
    // would (a) collide with a session leaked by a prior crashed run and (b)
    // collide with a second Umbra instance. A per-process suffix avoids both.
    // (A session leaked by a hard crash still persists in the kernel until it is
    // stopped or the machine reboots; graceful shutdown auto-stops it.)
    let trace_name = format!("umbra-etw-{}-{}", provider_name, std::process::id());

    let trace = UserTrace::new()
        .named(trace_name)
        .enable(provider)
        .start_and_process()
        .map_err(|e| DebugError::Com {
            message: format!("ETW start_and_process failed: {:?}", e),
        })?;

    state.trace = Some(trace);
    state.owner_session_id = Some(session_id.to_string());

    Ok(format!("ETW trace started for provider: {}", provider_name))
}

/// Stop the currently running ETW trace.
/// Only the session that started the trace may stop it.
pub fn stop_trace(session_id: &str) -> Result<String> {
    let mut state = ETW_STATE.lock().map_err(|_| DebugError::Com {
        message: "ETW state lock poisoned".to_string(),
    })?;

    if let Some(ref owner) = state.owner_session_id {
        if owner != session_id {
            return Err(DebugError::InvalidParameter {
                message: format!("ETW trace was started by session '{}' and cannot be stopped by session '{}'", owner, session_id),
            });
        }
    }

    if let Some(trace) = state.trace.take() {
        trace.stop().map_err(|e| DebugError::Com {
            message: format!("ETW stop failed: {:?}", e),
        })?;
    }

    state.owner_session_id = None;
    Ok("ETW trace stopped".to_string())
}

/// Stop whatever trace is running, ignoring ownership. A real-time ETW session
/// left running by a session that died without stopping it would otherwise lock
/// out ALL future tracing (only one system-wide trace is allowed). Called on
/// process shutdown as a final sweep so no orphan survives; a no-op if nothing
/// is running.
pub fn force_stop_trace() -> Result<String> {
    let mut state = ETW_STATE.lock().map_err(|_| DebugError::Com {
        message: "ETW state lock poisoned".to_string(),
    })?;

    if let Some(trace) = state.trace.take() {
        trace.stop().map_err(|e| DebugError::Com {
            message: format!("ETW force-stop failed: {:?}", e),
        })?;
    }
    state.owner_session_id = None;
    Ok("ETW trace force-stopped".to_string())
}

/// Retrieve and clear collected ETW events.
/// Only the session that started the trace may read its events.
pub fn events(session_id: &str) -> Result<EtwResult> {
    let state = ETW_STATE.lock().map_err(|_| DebugError::Com {
        message: "ETW state lock poisoned".to_string(),
    })?;

    if let Some(ref owner) = state.owner_session_id {
        if owner != session_id {
            return Err(DebugError::InvalidParameter {
                message: format!("ETW trace was started by session '{}' and cannot be read by session '{}'", owner, session_id),
            });
        }
    }

    let events = {
        let mut buf = state.events.lock().map_err(|_| DebugError::Com {
            message: "ETW events lock poisoned".to_string(),
        })?;
        std::mem::take(&mut *buf)
    };

    let status = if state.trace.is_some() {
        "running"
    } else {
        "stopped"
    }
    .to_string();

    Ok(EtwResult { events, status })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_validation_rejects_malformed() {
        assert!(is_valid_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"));
        assert!(!is_valid_guid("gggggggg-gggg-gggg-gggg-gggggggggggg")); // non-hex
        assert!(!is_valid_guid("22fb2cd6-0e7b-422b-a0c7")); // too short
        assert!(!is_valid_guid("22fb2cd60e7b422ba0c72fad1fd0e716")); // no dashes
        assert!(!is_valid_guid("22fb2cd6x0e7b-422b-a0c7-2fad1fd0e716")); // dash misplaced
    }

    #[test]
    fn resolves_named_and_valid_guid_providers_only() {
        assert!(resolve_provider_guid("Microsoft-Windows-DNS-Client").is_some());
        assert!(resolve_provider_guid("microsoft-windows-dns-client").is_some()); // case-insensitive
        assert!(resolve_provider_guid("{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}").is_some());
        assert!(resolve_provider_guid("not-a-provider").is_none());
        // A GUID-shaped but non-hex string must be rejected (would panic by_guid).
        assert!(resolve_provider_guid("gggggggg-gggg-gggg-gggg-gggggggggggg").is_none());
    }
}
