use models::Instruction;

/// Target instruction-set architecture for decoding. Zydis only handles x86 and
/// x86-64; there is deliberately no ARM variant, so an ARM64 target must be
/// rejected by the caller rather than being silently mis-decoded as x86.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86,
    X64,
}

/// Decode x86/x86-64 instructions from a byte slice using Zydis.
///
/// Returns decoded instructions, skipping any bytes that cannot be decoded. The
/// `start_address` is the base instruction pointer used for address formatting.
pub fn decode_instructions(bytes: &[u8], start_address: u64, arch: Arch) -> Vec<Instruction> {
    let decoder = match arch {
        Arch::X64 => zydis::Decoder::new64(),
        Arch::X86 => zydis::Decoder::new32(),
    };
    let formatter = zydis::Formatter::intel();
    let mut result = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        let slice = &bytes[offset..];
        let ip = start_address + offset as u64;

        match decoder.decode_first::<zydis::VisibleOperands>(slice) {
            Ok(Some(insn)) => {
                let len = insn.length as usize;
                let raw = &slice[..len];

                // Take the mnemonic from Zydis' structured field, NOT from the
                // first whitespace token of the formatted string: for prefixed
                // instructions (rep/lock/bnd/...) the formatter emits the prefix
                // first, which the old splitn() logic mistook for the mnemonic.
                let mnem = insn.mnemonic.static_string().unwrap_or("???");

                // Format for the operand text. On a formatter error, still emit
                // the instruction (with an empty operand string) rather than
                // leaving a silent gap in the listing for a range Zydis decoded.
                let (mnemonic, operands) = match formatter.format(Some(ip), &insn) {
                    Ok(formatted) => split_mnemonic_operands(&formatted, mnem),
                    Err(_) => (mnem.to_string(), String::new()),
                };

                result.push(Instruction {
                    address: ip,
                    bytes: raw.to_vec(),
                    mnemonic,
                    operands,
                    length: len as u8,
                });
                offset += len;
            }
            _ => {
                // Undecodable byte: skip it and keep going so we don't loop
                // forever on invalid encodings.
                offset += 1;
            }
        }
    }

    result
}

/// Split a formatted instruction into `(mnemonic, operands)` using the known
/// structured mnemonic to locate the boundary. Any tokens before the mnemonic
/// (instruction prefixes such as `rep`/`lock`) are kept with the mnemonic, so a
/// `rep movsb` reports mnemonic `"rep movsb"` — never `"rep"` with the real
/// opcode buried in the operands.
fn split_mnemonic_operands(formatted: &str, mnem: &str) -> (String, String) {
    match formatted.find(mnem) {
        Some(pos) => {
            let prefix = formatted[..pos].trim();
            let after = formatted[pos + mnem.len()..].trim_start();
            let mnemonic = if prefix.is_empty() {
                mnem.to_string()
            } else {
                format!("{} {}", prefix, mnem)
            };
            (mnemonic, after.to_string())
        }
        None => {
            // Mnemonic token not present in the formatted text (unexpected):
            // fall back to a whitespace split so we still return something.
            let mut parts = formatted.splitn(2, ' ');
            (
                parts.next().unwrap_or(mnem).to_string(),
                parts.next().unwrap_or("").to_string(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_plain_instruction() {
        assert_eq!(
            split_mnemonic_operands("mov rax, rbx", "mov"),
            ("mov".to_string(), "rax, rbx".to_string())
        );
    }

    #[test]
    fn keeps_prefix_with_mnemonic() {
        assert_eq!(
            split_mnemonic_operands("rep movsb", "movsb"),
            ("rep movsb".to_string(), "".to_string())
        );
        assert_eq!(
            split_mnemonic_operands("lock inc dword ptr [rax]", "inc"),
            ("lock inc".to_string(), "dword ptr [rax]".to_string())
        );
    }

    #[test]
    fn decodes_real_instructions() {
        // 48 01 d8 = add rax, rbx ; 90 = nop
        let insns = decode_instructions(&[0x48, 0x01, 0xd8, 0x90], 0x1000, Arch::X64);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic, "add");
        assert!(insns[0].operands.contains("rax"));
        assert_eq!(insns[0].address, 0x1000);
        assert_eq!(insns[1].mnemonic, "nop");
        assert_eq!(insns[1].address, 0x1003);
    }

    #[test]
    fn prefixed_instruction_mnemonic_is_not_the_prefix() {
        // F3 A4 = rep movsb — the regression: mnemonic used to come out as "rep".
        let insns = decode_instructions(&[0xf3, 0xa4], 0x2000, Arch::X64);
        assert_eq!(insns.len(), 1);
        assert!(insns[0].mnemonic.contains("movs"));
        assert_ne!(insns[0].mnemonic, "rep");
    }
}
