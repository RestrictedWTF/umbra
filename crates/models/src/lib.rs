use serde::{Serialize, Deserialize, Serializer, de::{self, Deserializer, Visitor}};
use schemars::{JsonSchema, SchemaGenerator, Schema, json_schema};
use std::{borrow::Cow, fmt};

// === Session DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionInfo {
    pub id: String,
    pub target_type: String,
    pub target: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttachResult {
    pub session_id: String,
    pub status: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionListResult {
    pub sessions: Vec<SessionInfo>,
}

// === Process / Thread DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    #[serde(default, with = "crate::hexfmt::opt")]
    #[schemars(with = "Option<String>")]
    pub base_address: Option<u64>,
    #[serde(default, with = "crate::hexfmt::opt")]
    #[schemars(with = "Option<String>")]
    pub peb: Option<u64>,
    pub threads: Option<Vec<u32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ThreadInfo {
    pub tid: u32,
    pub pid: Option<u32>,
    #[serde(default, with = "crate::hexfmt::opt")]
    #[schemars(with = "Option<String>")]
    pub teb: Option<u64>,
    #[serde(default, with = "crate::hexfmt::opt")]
    #[schemars(with = "Option<String>")]
    pub start_address: Option<u64>,
    pub state: String,
    pub priority: Option<i32>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProcessListResult {
    pub processes: Vec<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ThreadListResult {
    pub threads: Vec<ThreadInfo>,
}

// === Register DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterValue {
    pub name: String,
    pub value: String, // hex-encoded raw bytes, e.g. "0xdeadbeef"
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterState {
    pub architecture: String,
    pub registers: Vec<RegisterValue>,
}

// === Memory DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryRegion {
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub address: u64,
    pub size: usize,
    pub data: Vec<u8>,
    pub hex: String,
    pub truncated: bool, // true if the read was capped at MAX_MEMORY_SIZE
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryWriteResult {
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub address: u64,
    pub bytes_written: usize,
    pub status: String,
}

// === Stack / Module DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StackFrame {
    pub frame_number: u32,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub instruction_pointer: u64,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub return_address: u64,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub frame_offset: u64,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub stack_offset: u64,
    pub module: Option<String>,
    pub function: Option<String>,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub offset: u64,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StackTraceResult {
    pub frames: Vec<StackFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ModuleInfo {
    pub name: String,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub base_address: u64,
    pub size: Option<u64>,
    pub checksum: Option<u32>,
    pub timestamp: Option<u32>,
    pub image_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ModuleListResult {
    pub modules: Vec<ModuleInfo>,
}

// === Breakpoint DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakpointInfo {
    pub id: u32,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub address: u64,
    pub enabled: bool,
    /// Configured trigger pass count (the breakpoint fires on the Nth hit).
    pub pass_count: u32,
    /// Passes remaining before this breakpoint next triggers (dbgeng
    /// `CurrentPassCount`). This is NOT a cumulative hit tally — it counts down.
    pub current_pass_count: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakpointListResult {
    pub breakpoints: Vec<BreakpointInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakpointSetResult {
    pub id: u32,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub address: u64,
    pub status: String,
}

// === Symbol DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SymbolInfo {
    pub name: String,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub address: u64,
    pub module: Option<String>,
    pub size: Option<u64>,
    pub flags: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SymbolLookupResult {
    pub symbols: Vec<SymbolInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TypeInfo {
    pub name: String,
    pub size: u32,
    pub type_id: u32,
    pub fields: Vec<TypeField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TypeField {
    pub name: String,
    pub offset: u32,
    pub size: u32,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TypeResolveResult {
    pub types: Vec<TypeInfo>,
}

// === Disassembly DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Instruction {
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub length: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DisassemblyResult {
    pub instructions: Vec<Instruction>,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub start_address: u64,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub end_address: u64,
    pub truncated: bool, // true if read buffer was capped
}

// === Kernel DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DriverInfo {
    pub name: String,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub base_address: u64,
    pub size: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DriverListResult {
    pub drivers: Vec<DriverInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HandleInfo {
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub handle: u64,
    pub object_type: String,
    #[serde(with = "crate::hexfmt")]
    #[schemars(with = "String")]
    pub object: u64,
    pub granted_access: u32,
    pub process_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HandleListResult {
    pub handles: Vec<HandleInfo>,
}

// === Extension DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtensionResult {
    pub output: String,
    pub success: bool,
}

// === ETW DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EtwEvent {
    pub provider_id: String,
    pub event_id: u16,
    pub timestamp: String,
    pub process_id: u32,
    pub thread_id: u32,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EtwResult {
    pub events: Vec<EtwEvent>,
    pub status: String,
}

// === TTD DTOs ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TtdPosition {
    pub sequence: u64,
    pub step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TtdSeekResult {
    pub position: TtdPosition,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TtdOpenParams {
    pub trace_path: String,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TtdOpenResult {
    pub session_id: String,
    pub first: TtdPosition,
    pub last: TtdPosition,
    pub status: String,
}

// === MCP Parameter DTOs ===

/// An address value that can be supplied as either a JSON integer or a string.
/// Strings may be decimal ("18446735296321093504") or hex with an optional
/// "0x"/"0X" prefix ("0xfffff8045ae0ff80").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address(pub u64);

impl From<Address> for u64 {
    fn from(value: Address) -> Self {
        value.0
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Symmetric with deserialization: emit a `0x`-prefixed hex string so a
        // value parsed from a string round-trips out as a string, and so kernel
        // pointers above 2^53 are never emitted as precision-lossy JSON numbers.
        serializer.serialize_str(&format!("0x{:x}", self.0))
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AddressVisitor;

        impl<'de> Visitor<'de> for AddressVisitor {
            type Value = Address;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an integer address or a hex/decimal string")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Address(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value < 0 {
                    return Err(E::custom(format!("address cannot be negative: {value}")));
                }
                Ok(Address(value as u64))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                parse_address(value).map_err(E::custom)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                parse_address(&value).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(AddressVisitor)
    }
}

fn parse_address(value: &str) -> Result<Address, String> {
    parse_u64_str(value).map(Address)
}

/// Parse a `u64` from a decimal string or a hex string with an optional
/// `0x`/`0X` prefix. Shared by the `Address` type and the [`hexfmt`] helpers.
fn parse_u64_str(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("numeric string is empty".to_string());
    }
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex value '{value}': {e}"))
    } else {
        value.parse::<u64>().map_err(|e| format!("invalid decimal value '{value}': {e}"))
    }
}

/// serde helpers that render `u64` address/pointer fields as `0x`-prefixed hex
/// strings on the wire, and accept a hex string, a decimal string, or a JSON
/// number on the way in. Response DTOs use this for every address-shaped field:
/// a bare JSON number above 2^53 is silently rounded when a JS/TS MCP host
/// re-parses the result, which for a debugger means reading or breakpointing the
/// wrong address. The matching `#[schemars(with = "String")]` keeps the emitted
/// JSON schema honest.
pub mod hexfmt {
    use serde::de::{self, Deserializer, Visitor};
    use serde::Serializer;
    use std::fmt;

    pub fn serialize<S: Serializer>(value: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{:x}", value))
    }

    struct HexVisitor;
    impl<'de> Visitor<'de> for HexVisitor {
        type Value = u64;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a u64 as a hex/decimal string or a JSON number")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
            u64::try_from(v).map_err(|_| E::custom("value cannot be negative"))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<u64, E> {
            super::parse_u64_str(v).map_err(E::custom)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        d.deserialize_any(HexVisitor)
    }

    /// Same encoding for `Option<u64>`: `null` stays null, otherwise a hex string.
    pub mod opt {
        use serde::de::Deserializer;
        use serde::{Deserialize, Serializer};

        pub fn serialize<S: Serializer>(value: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
            match value {
                Some(v) => s.serialize_str(&format!("0x{:x}", v)),
                None => s.serialize_none(),
            }
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum HexOrNum {
            Num(u64),
            Str(String),
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
            let opt: Option<HexOrNum> = Option::deserialize(d)?;
            match opt {
                None => Ok(None),
                Some(HexOrNum::Num(n)) => Ok(Some(n)),
                Some(HexOrNum::Str(s)) => {
                    super::super::parse_u64_str(&s).map(Some).map_err(serde::de::Error::custom)
                }
            }
        }
    }
}

/// Deserialize a byte buffer from EITHER a JSON array of bytes (`[144, 195]`) or
/// a hex string (`"0x90c3"`, `"90 c3"`), so callers are not forced to hand-build
/// decimal byte arrays for `debug_write_memory`.
fn bytes_flexible<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BytesOrHex {
        Bytes(Vec<u8>),
        Hex(String),
    }
    match BytesOrHex::deserialize(d)? {
        BytesOrHex::Bytes(b) => Ok(b),
        BytesOrHex::Hex(s) => {
            let s = s.trim();
            let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
            let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.len() % 2 != 0 {
                return Err(de::Error::custom("hex byte string must have an even number of digits"));
            }
            (0..compact.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).map_err(de::Error::custom))
                .collect()
        }
    }
}

impl JsonSchema for Address {
    fn schema_name() -> Cow<'static, str> {
        "Address".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::Address").into()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "anyOf": [
                gen.subschema_for::<String>().to_value(),
                gen.subschema_for::<u64>().to_value(),
            ],
            "description": "An integer address or a hex/decimal string (e.g. 0xfffff8045ae0ff80)."
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionCreateParams {
    pub target_type: String,
    pub target: String,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GenericSessionParams {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct KernelHandleListParams {
    pub session_id: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryReadParams {
    pub session_id: String,
    pub address: Address,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryWriteParams {
    pub session_id: String,
    pub address: Address,
    /// Bytes to write. Accepts either a JSON array of byte values
    /// (`[144, 195]`) or a hex string (`"0x90c3"` / `"90 c3"`).
    #[serde(deserialize_with = "crate::bytes_flexible")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StackTraceParams {
    pub session_id: String,
    pub max_frames: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SymbolLookupParams {
    pub session_id: String,
    pub symbol: String,
    pub module: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DisassembleParams {
    pub session_id: String,
    pub address: Address,
    pub count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakpointSetParams {
    pub session_id: String,
    pub address: Address,
    pub flags: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakpointRemoveParams {
    pub session_id: String,
    pub id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtensionInvokeParams {
    pub session_id: String,
    pub extension: String,
    pub command: String,
    pub args: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EtwStartParams {
    pub session_id: String,
    pub provider_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TtdSeekParams {
    pub session_id: String,
    pub sequence: u64,
    pub step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PdbResolveTypeParams {
    pub pdb_path: String,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PdbListTypesParams {
    pub pdb_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResolveTypeParams {
    pub session_id: String,
    pub type_name: String,
}

#[cfg(test)]
mod tests {
    use super::Address;
    use serde_json;

    fn parse(s: &str) -> serde_json::Result<Address> {
        serde_json::from_str(s)
    }

    #[test]
    fn address_accepts_integer() {
        assert_eq!(parse("18446735296321093504").unwrap().0, 0xfffff8045ae0ff80);
    }

    #[test]
    fn address_accepts_hex_string() {
        assert_eq!(parse("\"0xfffff8045ae0ff80\"").unwrap().0, 0xfffff8045ae0ff80);
    }

    #[test]
    fn address_accepts_uppercase_hex_prefix() {
        assert_eq!(parse("\"0XDeadBeef\"").unwrap().0, 0xdeadbeef);
    }

    #[test]
    fn address_accepts_decimal_string() {
        assert_eq!(parse("\"18446735296321093504\"").unwrap().0, 0xfffff8045ae0ff80);
    }

    #[test]
    fn address_rejects_invalid_hex() {
        assert!(parse("\"0xGGG\"").is_err());
    }

    #[test]
    fn address_rejects_garbage_string() {
        assert!(parse("\"not-an-address\"").is_err());
    }

    #[test]
    fn address_rejects_negative_integer() {
        assert!(parse("-1").is_err());
    }

    #[test]
    fn address_rejects_empty_string() {
        assert!(parse("\"\"").is_err());
    }

    #[test]
    fn address_serializes_as_hex_string() {
        // Symmetric with input, and precision-safe for values above 2^53.
        assert_eq!(serde_json::to_value(Address(0xdeadbeef)).unwrap(), serde_json::json!("0xdeadbeef"));
    }

    #[test]
    fn large_pointer_fields_round_trip_as_hex_strings() {
        let addr = 0xfffff8045ae0ff80u64; // > 2^53
        let r = super::MemoryWriteResult { address: addr, bytes_written: 4, status: "ok".to_string() };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["address"], serde_json::json!("0xfffff8045ae0ff80"));
        let back: super::MemoryWriteResult = serde_json::from_value(v).unwrap();
        assert_eq!(back.address, addr);
    }

    #[test]
    fn optional_pointer_fields_serialize_as_hex_or_null() {
        let t = super::ThreadInfo {
            tid: 1, pid: Some(4), teb: Some(0xfffff80012340000), start_address: None,
            state: "unknown".to_string(), priority: None,
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["teb"], serde_json::json!("0xfffff80012340000"));
        assert_eq!(v["start_address"], serde_json::Value::Null);
    }

    #[test]
    fn write_data_accepts_hex_string_or_byte_array() {
        let a: super::MemoryWriteParams =
            serde_json::from_str(r#"{"session_id":"s","address":"0x1000","data":"0x90c3"}"#).unwrap();
        assert_eq!(a.data, vec![0x90, 0xc3]);
        let b: super::MemoryWriteParams =
            serde_json::from_str(r#"{"session_id":"s","address":"0x1000","data":"90 c3"}"#).unwrap();
        assert_eq!(b.data, vec![0x90, 0xc3]);
        let c: super::MemoryWriteParams =
            serde_json::from_str(r#"{"session_id":"s","address":"0x1000","data":[144,195]}"#).unwrap();
        assert_eq!(c.data, vec![144, 195]);
    }
}
