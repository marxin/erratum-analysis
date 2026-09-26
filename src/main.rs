use object::Architecture::Arm;
use object::{Object, ObjectSection};
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_BUILD_DIR: &str = "llvm-build";

#[derive(Default)]
struct ScanStats {
    object_bytes: u64,
    match_count: usize,
    snippet_bytes: u64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

use disarm64::{InsnOpcode, decoder};

fn run() -> Result<(), Box<dyn Error>> {
    // let insn = decoder::decode(0x9100052a).unwrap().definition();
    // dbg!(insn);
    // todo!();

    let root = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_BUILD_DIR));

    if !root.is_dir() {
        return Err(format!("{} is not a directory", root.display()).into());
    }

    let objdump = env::var_os("LLVM_OBJDUMP").unwrap_or_else(|| "llvm-objdump".into());

    let mut object_files = Vec::new();
    collect_object_files(&root, &mut object_files)?;
    object_files.sort_unstable();

    let mut stats = ScanStats::default();
    for path in &object_files {
        if let Err(error) = inspect_file(path, &objdump, &mut stats) {
            eprintln!("warning: {}: {error}", path.display());
        }
    }

    let affected_fraction = if stats.object_bytes == 0 {
        0.0
    } else {
        stats.snippet_bytes as f64 / stats.object_bytes as f64
    };
    eprintln!(
        "scanned {} object files ({} bytes); found {} affected snippets ({} bytes, {:.8}% of object bytes)",
        object_files.len(),
        stats.object_bytes,
        stats.match_count,
        stats.snippet_bytes,
        affected_fraction * 100.0
    );
    Ok(())
}

fn collect_object_files(dir: &Path, output: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_object_files(&path, output)?;
        } else if file_type.is_file() && path.extension().is_some_and(|extension| extension == "o")
        {
            output.push(path);
        }
    }
    Ok(())
}

fn inspect_file(
    path: &Path,
    objdump: &std::ffi::OsStr,
    stats: &mut ScanStats,
) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(path)?;
    stats.object_bytes += bytes.len() as u64;
    let file = object::File::parse(bytes.as_slice())?;
    let little_endian = file.is_little_endian();

    for section in file.sections() {
        if section.name()? != "__text" || section.segment_name()? != Some("__TEXT") {
            continue;
        }

        let data = section.data()?;
        let instructions: Vec<u32> = data
            .chunks_exact(4)
            .map(|bytes| {
                let bytes: [u8; 4] = bytes.try_into().expect("chunks are four bytes");
                if little_endian {
                    u32::from_le_bytes(bytes)
                } else {
                    u32::from_be_bytes(bytes)
                }
            })
            .collect();

        for start in 0..instructions.len() {
            if !is_adrp(instructions[start]) {
                continue;
            }

            let adrp_register = rd(instructions[start]);
            if start + 1 >= instructions.len()
                || is_excluded_second_instruction(instructions[start + 1], adrp_register)
            {
                continue;
            }

            // There must be one non-branch instruction between ADRP and the
            // load/store, and there may be a second one.
            for load_index in [start + 2, start + 3] {
                if load_index >= instructions.len()
                    || instructions[start + 1..load_index]
                        .iter()
                        .any(|instruction| is_branch_exception_or_system(*instruction))
                    || (load_index == start + 3
                        && is_adrp_writing_register(instructions[start + 2], adrp_register))
                    || !is_load_store_unsigned_immediate(instructions[load_index])
                    || rd(instructions[start]) != rn(instructions[load_index])
                {
                    continue;
                }

                if let Err(error) = disassemble_snippet(
                    objdump,
                    path,
                    section.address() + (start * 4) as u64,
                    section.address() + ((load_index + 1) * 4) as u64,
                ) {
                    eprintln!("warning: could not disassemble snippet: {error}");
                }
                stats.match_count += 1;
                stats.snippet_bytes += ((load_index - start + 1) * 4) as u64;
            }
        }
    }

    Ok(())
}

fn disassemble_snippet(
    objdump: &std::ffi::OsStr,
    path: &Path,
    start_address: u64,
    stop_address: u64,
) -> Result<(), Box<dyn Error>> {
    let output = Command::new(objdump)
        .arg("--disassemble")
        .arg("--section=__text")
        .arg(format!("--start-address=0x{start_address:x}"))
        .arg(format!("--stop-address=0x{stop_address:x}"))
        .arg(path)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "llvm-objdump exited with {}: {}",
            output.status,
            stderr.trim()
        )
        .into());
    }

    print_objdump_without_symbols(&String::from_utf8_lossy(&output.stdout));
    Ok(())
}

fn print_objdump_without_symbols(output: &str) {
    for line in output.lines().filter_map(objdump_line_without_symbols) {
        println!("{line}");
    }
}

fn objdump_line_without_symbols(line: &str) -> Option<String> {
    // Omit labels such as `0000000000000078 <function>:`.
    if line.contains('<') && line.trim_end().ends_with(">:") {
        return None;
    }

    let mut line = line.to_owned();
    // Remove symbolic operand annotations such as ` <function+0x20>`.
    while let Some(start) = line.find(" <") {
        let Some(relative_end) = line[start + 2..].find('>') else {
            break;
        };
        let end = start + 2 + relative_end;
        line.replace_range(start..=end, "");
    }
    line.truncate(line.trim_end().len());
    Some(line)
}

const ADRP_MARK: u32 = 0x9f00_0000;
const ADRP_OPCODE: u32 = 0x9000_0000;
// Branches, Exception Generating and System instructions category (ARM Manual category of instructions)
const BRANCH_EXCEPT_SYS_MASK: u32 = 0x1c00_0000;
const BRANCH_EXCEPT_SYS_OPCODE: u32 = 0x1400_0000;
// LDR (unsigned offset)
const LDR_UNSIGNED_MASK: u32 = 0xffc0_0000;
const LDR_UNSIGNED_OPCODE: u32 = 0xf940_0000;
// ADD (immediate)
const ADD_IMM_MASK: u32 = 0xffc0_0000;
const ADD_IMM_OPCODE: u32 = 0x9100_0000;
// Load/store register (unsigned immediate) (ARM Manual category of instructions)
const LDR_STR_UNSIGNED_MASK: u32 = 0x3b00_0000;
const LDR_STR_UNSIGNED_OPCODE: u32 = 0x3900_0000;

const REGISTER_MASK: u32 = (1 << 5) - 1;

enum ArmInsn {
    Adrp { rd: u32 },
    BranchExceptSys,
    Ldr { rt: u32, rn: u32 },
    Add { rd: u32, rn: u32 },
    LdrStr { rt: u32, rn: u32 },
    Unrecognized,
}

enum ErratumVariant {
    // Sequence 1 with 3 instructions
    Sequence1A,
    // Sequence 1 with 4 instructions
    Sequence1B,
    // Sequence 2
    Sequence2,
}

impl ArmInsn {
    fn from_opcode(insn: u32) -> Self {
        if insn & ADRP_MARK == ADRP_OPCODE {
            Self::Adrp {
                rd: insn & REGISTER_MASK,
            }
        } else if insn & BRANCH_EXCEPT_SYS_MASK == BRANCH_EXCEPT_SYS_OPCODE {
            Self::BranchExceptSys
        } else if insn & LDR_UNSIGNED_MASK == LDR_UNSIGNED_OPCODE {
            Self::Ldr {
                rt: insn & REGISTER_MASK,
                rn: (insn >> 5) & REGISTER_MASK,
            }
        } else if insn & ADD_IMM_MASK == ADD_IMM_OPCODE {
            Self::Add {
                rd: insn & REGISTER_MASK,
                rn: (insn >> 5) & REGISTER_MASK,
            }
        } else if insn & LDR_STR_UNSIGNED_MASK == LDR_STR_UNSIGNED_OPCODE {
            Self::LdrStr {
                rt: insn & REGISTER_MASK,
                rn: (insn >> 5) & REGISTER_MASK,
            }
        } else {
            Self::Unrecognized
        }
    }

    fn classify_sequence1(insns: &[ArmInsn]) -> Option<ErratumVariant> {
        if insns.len() < 3 {
            return None;
        }

        // 1) ADRP
        let ArmInsn::Adrp { rd: register } = insns[0] else {
            return None;
        };

        // 2) A load or store instruction:
        // ...
        // This must not write to Rn.
        match insns[1] {
            Self::Add { .. } | Self::Adrp { .. } | Self::BranchExceptSys => return None,
            ArmInsn::Ldr { rn, .. } if rn == register => return None,
            _ => {}
        }

        // 3) Variant A (optional 3rd instruction)
        if insns.len() >= 4 {
            // This cannot be a branch.
            // This cannot write Rn.
            match insns[2] {
                Self::BranchExceptSys => return None,
                Self::Add { rd, .. } if rd == register => return None,
                Self::Ldr { rn, .. } if rn == register => return None,
                _ => {}
            }

            // 4) Load/store register (unsigned immediate)" encoding class, using Rn as the base address register.
            if let Self::LdrStr { rn, .. } = insns[3]
                && rn == register
            {
                return Some(ErratumVariant::Sequence1A);
            }
        }

        // 3) Variant B
        if let Self::LdrStr { rn, .. } = insns[3]
            && rn == register
        {
            Some(ErratumVariant::Sequence1B)
        } else {
            None
        }
    }

    fn classify_sequence2(insns: &[ArmInsn]) -> Option<ErratumVariant> {
        if insns.len() < 3 {
            return None;
        }

        // 1) ADRP
        let ArmInsn::Adrp { rd: register } = insns[0] else {
            return None;
        };

        // 2) Another instruction which writes to Rn.
        // - This cannot be a branch or an ADRP.
        // - This cannot read Rn.
        match insns[1] {
            Self::BranchExceptSys | Self::Adrp { .. } => return None,
            Self::Add { rd, .. } if rd != register => return None,
            Self::Add { rn, .. } if rn == register => return None,
            _ => {}
        }

        // 3) Another instruction.
        // This cannot be a branch.
        // This cannot write Rn.
        match insns[2] {
            Self::BranchExceptSys => return None,
            Self::Add { rd, .. } if rd == register => return None,
            Self::Adrp { rd, .. } if rd == register => return None,
            Self::Ldr { rn, .. } if rn == register => return None,
            _ => {}
        }

        // 4) Load/store register (unsigned immediate)" encoding class, using Rn as the base address register.
        if let Self::LdrStr { rn, .. } = insns[3]
            && rn == register
        {
            Some(ErratumVariant::Sequence2)
        } else {
            None
        }
    }

    fn classify_erratum_843419(insns: &[ArmInsn]) -> Option<ErratumVariant> {
        Self::classify_sequence1(insns).or_else(|| Self::classify_sequence2(insns))
    }
}

fn is_adrp(instruction: u32) -> bool {
    instruction & ADRP_MARK == ADRP_OPCODE
}

fn is_adrp_writing_register(instruction: u32, register: u32) -> bool {
    is_adrp(instruction) && rd(instruction) == register
}

fn is_branch_exception_or_system(instruction: u32) -> bool {
    instruction & BRANCH_EXCEPT_SYS_MASK == BRANCH_EXCEPT_SYS_OPCODE
}

fn is_excluded_second_instruction(instruction: u32, adrp_register: u32) -> bool {
    let uses_same_register = rd(instruction) == adrp_register && rn(instruction) == adrp_register;
    if !uses_same_register {
        return false;
    }

    // ADD Xd, Xn, ... (immediate, shifted-register, or extended-register form).
    let is_add_x = instruction & ADD_IMM_MASK == ADD_IMM_OPCODE; //;|| instruction & 0xff00_0000 == 0x8b00_0000;
    // LDR Xt, [Xn, #imm] (unsigned-immediate form).
    let is_ldr_x = instruction & LDR_UNSIGNED_MASK == LDR_UNSIGNED_OPCODE;

    is_add_x || is_ldr_x
}

fn is_load_store_unsigned_immediate(instruction: u32) -> bool {
    instruction & LDR_STR_UNSIGNED_MASK == LDR_STR_UNSIGNED_OPCODE
}

fn rd(instruction: u32) -> u32 {
    instruction & 0x1f
}

fn rn(instruction: u32) -> u32 {
    (instruction >> 5) & 0x1f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_instruction_classes() {
        assert!(is_adrp(0x9000_0003));
        assert!(!is_adrp(0x1000_0003)); // ADR, not ADRP

        assert!(is_branch_exception_or_system(0x1400_0000)); // B
        assert!(is_branch_exception_or_system(0xd400_0001)); // SVC
        assert!(!is_branch_exception_or_system(0xd100_0400)); // SUB

        assert!(is_load_store_unsigned_immediate(0xf940_0060)); // LDR X0, [X3]
        assert!(is_load_store_unsigned_immediate(0xb900_0060)); // STR W0, [X3]
        assert!(!is_load_store_unsigned_immediate(0xf840_8460)); // post-indexed LDR
    }

    #[test]
    fn extracts_registers() {
        assert_eq!(rd(0x9000_0003), 3);
        assert_eq!(rn(0xf940_0060), 3);
    }

    #[test]
    fn strips_symbols_from_objdump_lines() {
        assert_eq!(
            objdump_line_without_symbols("0000000000001000 <function>:"),
            None
        );
        assert_eq!(
            objdump_line_without_symbols("    10184: 9000000a  adrp x10, 0x10000 <function+0x20>"),
            Some("    10184: 9000000a  adrp x10, 0x10000".into())
        );
    }

    #[test]
    fn recognizes_adrp_that_redefines_the_original_register() {
        assert!(is_adrp_writing_register(0x9000_0008, 8));
        assert!(!is_adrp_writing_register(0x9000_0009, 8));
        assert!(!is_adrp_writing_register(0x9100_2108, 8));
    }

    #[test]
    fn excludes_second_instruction_that_redefines_the_adrp_register() {
        assert!(is_excluded_second_instruction(0x9100_2108, 8)); // ADD X8, X8, #8
        assert!(is_excluded_second_instruction(0x8b09_0108, 8)); // ADD X8, X8, X9
        assert!(is_excluded_second_instruction(0xf940_0508, 8)); // LDR X8, [X8, #8]

        assert!(!is_excluded_second_instruction(0x9100_2109, 8)); // ADD X9, X8, #8
        assert!(!is_excluded_second_instruction(0xf940_0509, 8)); // LDR X9, [X8, #8]
        assert!(!is_excluded_second_instruction(0xf900_0508, 8)); // STR X8, [X8, #8]
    }
}
