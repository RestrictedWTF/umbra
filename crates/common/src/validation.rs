use crate::{DebugError, Result};

/// Characters that let a single dbgeng command string fan out into multiple
/// commands, a nested/scripted command, or an I/O redirection. Rejecting them
/// removes the structural tricks that make any verb list bypassable:
/// `.block {.shell calc}` (nesting), `$< script.txt` (script sourcing),
/// `cmd1; cmd2` (chaining), and `cmd > file` (redirection).
const FORBIDDEN_CHARS: &[char] = &[
    '"', '\'', '`', ';', '|', '<', '>', '{', '}', '\n', '\r', '\0',
];

/// dbgeng meta-commands (dot-commands) that are safe to run from a context
/// reachable by autonomous agents: pure inspection, symbol/source-path
/// management, and execution-context navigation. This is a strict allowlist —
/// anything not on it is denied, which is what closes the host-affecting verbs
/// (`.shell`, `.load`/`.loadby`, `.create`/`.attach`, `.writemem`/`.dump`/
/// `.logopen`/`.logappend`/`.write_cmd`) and the `.if`/`.foreach`/`.for`/
/// `.while`/`.do`/`.block` control-flow wrappers, all in one rule.
const ALLOWED_META_COMMANDS: &[&str] = &[
    ".reload", ".sympath", ".srcpath", ".symfix", ".symopt", ".sympath+",
    ".srcpath+", ".effmach", ".frame", ".thread", ".process", ".context",
    ".formats", ".ttime", ".time", ".lastevent", ".exr", ".cxr", ".ecxr",
    ".trap", ".chain", ".echo", ".cls", ".lines", ".prefer_dml", ".help",
];

/// Regular (non-dot, non-bang) command verbs that must be denied even though
/// they do not touch the host directly. dbgeng expands aliases at *execution*
/// time, so allowing `aS bang .shell` followed by `bang` would let a denied
/// verb run under a benign-looking name. Blocking alias definition closes that.
const BLOCKED_REGULAR_VERBS: &[&str] = &["as", "ad"];

/// Validate a command *argument* — an extension name, an extension DLL path, or
/// the trailing arguments appended to an inspection command. Rejects the
/// shell/script metacharacters in [`FORBIDDEN_CHARS`] so an argument cannot
/// smuggle a second command or a redirection past the verb check.
pub fn validate_command_arg(s: &str) -> Result<String> {
    if let Some(c) = s.chars().find(|c| FORBIDDEN_CHARS.contains(c)) {
        return Err(DebugError::InvalidParameter {
            message: format!("argument contains forbidden character {:?}", c),
        });
    }
    Ok(s.to_string())
}

fn denied(verb: &str) -> DebugError {
    DebugError::InvalidParameter {
        message: format!(
            "Command '{}' is not permitted. This surface is reachable by autonomous agents, so \
             it is restricted to read-only inspection: host/process/file/DLL-loading verbs, alias \
             definition, command chaining, nesting, scripting, and redirection are all denied.",
            verb
        ),
    }
}

/// Validate a command string destined for `IDebugControl::Execute`.
///
/// This is a security boundary, not just an injection filter: `extensions_invoke`
/// is reachable by autonomous (and potentially prompt-injected) agents, so the
/// command must not be able to execute host code, spawn processes, or write
/// files. The strategy is defence-in-depth:
///
/// 1. Structurally reject the characters that enable chaining / nesting /
///    scripting / redirection (see [`FORBIDDEN_CHARS`]).
/// 2. Classify the leading verb and apply a **default-deny allowlist** to the
///    dot-command class (where every host-affecting verb lives), reject the
///    `!!` shell alias, and block alias-definition verbs.
///
/// A prefix *denylist* (the previous approach) is fundamentally defeatable via
/// nesting, aliasing, and verb enumeration; an allowlist fails safe instead.
/// Returns the original string unchanged on success.
pub fn validate_debugger_command(s: &str) -> Result<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(DebugError::InvalidParameter {
            message: "empty command".to_string(),
        });
    }

    // (1) Structural defense — no chaining, nesting, scripting, or redirection.
    if let Some(c) = trimmed.chars().find(|c| FORBIDDEN_CHARS.contains(c)) {
        return Err(DebugError::InvalidParameter {
            message: format!(
                "command contains forbidden character {:?}; chaining, nesting, scripting, and \
                 redirection are not allowed",
                c
            ),
        });
    }

    // (2) Classify the verb (first whitespace-delimited token).
    let verb_raw = trimmed.split_whitespace().next().unwrap_or("");
    let verb = verb_raw.to_ascii_lowercase();

    // `!!` is a built-in alias for `.shell` — deny before the general bang rule.
    if verb.starts_with("!!") {
        return Err(denied("!! (.shell alias)"));
    }

    if verb.starts_with('.') {
        // Dot-command: strict allowlist. Compare up to any '/' so that
        // `.reload/f` is judged by its `.reload` base verb.
        let base = verb.split('/').next().unwrap_or(verb.as_str());
        if !ALLOWED_META_COMMANDS.contains(&base) {
            return Err(denied(verb_raw));
        }
    } else if verb.starts_with('!') {
        // Bang/extension command: inspection-scoped. Loading new extension DLLs
        // is denied (`.load`/`.loadby` are not in the meta allowlist), so only
        // trusted, engine-loaded extensions are reachable here.
    } else {
        // Regular command: debuggee/inspection scoped, but block alias creation.
        let base = verb.split('/').next().unwrap_or(verb.as_str());
        if BLOCKED_REGULAR_VERBS.contains(&base) {
            return Err(denied(verb_raw));
        }
    }

    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(cmd: &str) -> bool {
        validate_debugger_command(cmd).is_ok()
    }

    #[test]
    fn blocks_host_code_execution_verbs() {
        // Direct shell / process spawn.
        assert!(!allowed(".shell calc.exe"));
        assert!(!allowed(".shell_quote whoami"));
        assert!(!allowed("!! calc.exe"));
        assert!(!allowed(".create c:\\evil.exe"));
        assert!(!allowed(".attach 4"));
    }

    #[test]
    fn blocks_dll_loading() {
        // Loading a DLL runs its DllMain / DebugExtensionInitialize = code exec.
        assert!(!allowed(".load c:\\path\\evil.dll"));
        assert!(!allowed(".loadby evil dbgeng"));
        assert!(!allowed(".LOAD c:\\evil.dll")); // case-insensitive
    }

    #[test]
    fn blocks_file_write_verbs() {
        assert!(!allowed(".writemem c:\\x.bin 401000 L100"));
        assert!(!allowed(".dump /f c:\\x.dmp"));
        assert!(!allowed(".logappend c:\\x.log"));
        assert!(!allowed(".logopen c:\\x.log"));
        assert!(!allowed(".write_cmd c:\\x.txt"));
        assert!(!allowed(".dumpcab c:\\x.cab"));
    }

    #[test]
    fn blocks_control_flow_nesting_bypass() {
        assert!(!allowed(".block {.shell calc.exe}"));
        assert!(!allowed(".if (1) {.shell calc.exe}"));
        assert!(!allowed(".foreach (a {x}) {.shell calc}"));
        assert!(!allowed(".for (r $t0=0; @$t0<1; r $t0=@$t0+1) {.shell}"));
    }

    #[test]
    fn blocks_alias_definition_bypass() {
        // dbgeng expands aliases at execution time, so alias creation is denied.
        assert!(!allowed("aS bang .shell"));
        assert!(!allowed("as bang .shell"));
        assert!(!allowed("ad bang"));
    }

    #[test]
    fn blocks_chaining_scripting_and_redirection() {
        assert!(!allowed("u 401000; .shell calc")); // ';' chaining
        assert!(!allowed("dd 1000 > c:\\x.bin")); // '>' redirection
        assert!(!allowed("$<c:\\script.txt")); // script source
        assert!(!allowed("$$>a<c:\\s.txt arg")); // block-script source
        assert!(!allowed("$$<c:\\s.txt"));
    }

    #[test]
    fn blocks_empty() {
        assert!(!allowed(""));
        assert!(!allowed("   "));
    }

    #[test]
    fn allows_read_only_inspection() {
        // Regular inspection / debuggee commands.
        assert!(allowed("u 00401000"));
        assert!(allowed("dd 1000 L4"));
        assert!(allowed("dt nt!_EPROCESS"));
        assert!(allowed("x nt!*CreateFile*"));
        assert!(allowed("r"));
        assert!(allowed("r rax"));
        assert!(allowed("k"));
        assert!(allowed("kb"));
        assert!(allowed("lm"));
        assert!(allowed("bp 401000"));
        assert!(allowed("bl"));
        assert!(allowed("ln 401000"));
    }

    #[test]
    fn allows_safe_meta_commands() {
        assert!(allowed(".reload"));
        assert!(allowed(".reload /f"));
        assert!(allowed(".sympath"));
        assert!(allowed(".effmach x86"));
        assert!(allowed(".frame 3"));
        assert!(allowed(".process"));
        assert!(allowed(".chain"));
    }

    #[test]
    fn allows_trusted_bang_extension_inspection() {
        // Bangs into engine-loaded (trusted) extensions are inspection; new DLLs
        // cannot be loaded, so these are safe.
        assert!(allowed("!analyze -v"));
        assert!(allowed("!process 0 0"));
        assert!(allowed("!handle"));
        assert!(allowed("!peb"));
    }

    #[test]
    fn arg_validator_rejects_metacharacters() {
        assert!(validate_command_arg("nt!_EPROCESS").is_ok());
        assert!(validate_command_arg("-v").is_ok());
        assert!(validate_command_arg("a; .shell").is_err());
        assert!(validate_command_arg("a > b").is_err());
        assert!(validate_command_arg("a {b}").is_err());
    }
}
