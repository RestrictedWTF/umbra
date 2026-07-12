//! Time Travel Debugging (TTD) replay support via Microsoft's TTD ReplayApi.
//!
//! A replay cursor over a static `.run` trace does not share dbgeng's live
//! execution model, so TTD traces are managed separately from debug sessions
//! (see `ttd_open` / `ttd_seek`), rather than being forced into `EngineCommand`.

mod csts;
mod ffi;

use common::Result;
use models::{TtdPosition, TtdSeekResult};

pub use ffi::{Position, TtdTrace};

/// Open a TTD trace file (`.run`).
pub fn open_trace(path: &str) -> Result<TtdTrace> {
    TtdTrace::open(path)
}

/// Convert an FFI `Position` into the wire `TtdPosition`.
pub fn position_to_model(p: Position) -> TtdPosition {
    TtdPosition {
        sequence: p.major,
        step: p.minor,
    }
}

/// Seek a trace's cursor to `sequence:step` and return the resulting position.
///
/// The reported position comes from the cursor after the seek (the engine clamps
/// out-of-range requests), and `status` distinguishes an exact landing (`"ok"`),
/// an out-of-range request (`"out_of_range"`), and a request the engine moved
/// elsewhere (`"clamped"`) — rather than always claiming `"ok"`.
pub fn seek(trace: &TtdTrace, sequence: u64, step: u64) -> Result<TtdSeekResult> {
    let requested = Position { major: sequence, minor: step };
    let first = trace.first_position();
    let last = trace.last_position();

    trace.set_position(requested);
    let actual = trace.current_position();

    let status = if pos_key(requested) < pos_key(first) || pos_key(requested) > pos_key(last) {
        "out_of_range"
    } else if pos_key(actual) != pos_key(requested) {
        "clamped"
    } else {
        "ok"
    };

    Ok(TtdSeekResult {
        position: position_to_model(actual),
        status: status.to_string(),
    })
}

/// Order positions lexicographically by `(sequence, step)`.
fn pos_key(p: Position) -> (u64, u64) {
    (p.major, p.minor)
}
