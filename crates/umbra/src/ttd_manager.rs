use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use common::{DebugError, Result};
use models::{TtdOpenResult, TtdSeekResult};
use uuid::Uuid;

/// Manages open TTD replay traces, keyed by a TTD session id. TTD traces are a
/// separate concept from live/dump debug sessions (a replay cursor over a static
/// file), so they get their own manager rather than sharing `SessionManager`.
pub struct TtdManager {
    traces: RwLock<HashMap<String, Arc<Mutex<ttd::TtdTrace>>>>,
}

impl Default for TtdManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TtdManager {
    pub fn new() -> Self {
        Self {
            traces: RwLock::new(HashMap::new()),
        }
    }

    /// Open a `.run` trace and register it under `session_id` (or a fresh UUID).
    pub async fn open(&self, trace_path: &str, session_id: Option<String>) -> Result<TtdOpenResult> {
        let id = session_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        if self.traces.read().await.contains_key(&id) {
            return Err(DebugError::InvalidParameter {
                message: format!("TTD session '{}' already exists", id),
            });
        }
        // Opening loads/initializes the whole trace and can block; run off-runtime.
        let path = trace_path.to_string();
        let trace = tokio::task::spawn_blocking(move || ttd::open_trace(&path))
            .await
            .map_err(|e| DebugError::Com {
                message: format!("TTD open thread panicked: {}", e),
            })??;

        let first = ttd::position_to_model(trace.first_position());
        let last = ttd::position_to_model(trace.last_position());
        self.traces
            .write()
            .await
            .insert(id.clone(), Arc::new(Mutex::new(trace)));

        Ok(TtdOpenResult {
            session_id: id,
            first,
            last,
            status: "opened".to_string(),
        })
    }

    pub async fn seek(&self, session_id: &str, sequence: u64, step: u64) -> Result<TtdSeekResult> {
        let trace = {
            let traces = self.traces.read().await;
            traces.get(session_id).cloned()
        }
        .ok_or_else(|| DebugError::SessionNotFound {
            id: session_id.to_string(),
        })?;
        let guard = trace.lock().await;
        ttd::seek(&guard, sequence, step)
    }

    pub async fn close(&self, session_id: &str) -> Result<String> {
        // Removing the entry drops the Arc<Mutex<TtdTrace>>; when the last handle
        // goes away the trace's Drop releases the replay engine and cursor.
        if self.traces.write().await.remove(session_id).is_some() {
            Ok(format!("TTD session {} closed", session_id))
        } else {
            Err(DebugError::SessionNotFound {
                id: session_id.to_string(),
            })
        }
    }

    /// Close every open trace (process shutdown). Dropping the map entries frees
    /// each replay engine via `TtdTrace::drop`.
    pub async fn close_all(&self) {
        self.traces.write().await.clear();
    }
}
