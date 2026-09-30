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

fn run() -> Result<(), Box<dyn Error>> {
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
        "\nScanned {} object files ({} MiB); found {} affected snippets ({} bytes, {:.8}% of object bytes)",
        object_files.len(),
        stats.object_bytes as f32 / (1024.0 * 1024.0),
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
        let section_name = section.name()?;
        if section_name != "__text" && section_name != ".text" {
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

        let decoded: Vec<ArmInsn> = instructions
            .iter()
            .copied()
            .map(ArmInsn::from_opcode)
            .collect();

        for start in 0..decoded.len() {
            let end = (start + ErratumVariant::MAX_INSTRUCTION_COUNT).min(decoded.len());
            let Some(variant) = ArmInsn::classify_erratum_843419(&decoded[start..end]) else {
                continue;
            };
            let instruction_count = variant.instruction_count();
            println!("===\nerratum 843419: {}", variant.name());
            println!("{:?}", &decoded[start..start + instruction_count]);

            if let Err(error) = disassemble_snippet(
                objdump,
                path,
                section_name,
                section.address() + (start * 4) as u64,
                section.address() + ((start + instruction_count) * 4) as u64,
            ) {
                eprintln!("warning: could not disassemble snippet: {error}");
            }
            stats.match_count += 1;
            stats.snippet_bytes += (instruction_count * 4) as u64;
        }
    }

    Ok(())
}

fn disassemble_snippet(
    objdump: &std::ffi::OsStr,
    path: &Path,
    section_name: &str,
    start_address: u64,
    stop_address: u64,
) -> Result<(), Box<dyn Error>> {
    let output = Command::new(objdump)
        .arg("--disassemble")
        .arg("-r")
        .arg(format!("--section={section_name}"))
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

// ====== Erratum decoding logic =======

const ADRP_MARK: u32 = 0x9f00_0000;
const ADRP_OPCODE: u32 = 0x9000_0000;
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

#[derive(Debug)]
enum ArmInsn {
    Adrp { rd: u32 },
    Branch,
    Ldr { rt: u32, rn: u32 },
    Add { rd: u32, rn: u32 },
    LdrStr { rn: u32 },
    Unrecognized,
}

enum ErratumVariant {
    // Sequence 1 with 4 instructions
    Sequence1A,
    // Sequence 1 with 3 instructions
    Sequence1B,
    // Sequence 2
    Sequence2,
}

impl ErratumVariant {
    const MAX_INSTRUCTION_COUNT: usize = 4;

    fn instruction_count(&self) -> usize {
        match self {
            Self::Sequence1A | Self::Sequence2 => 4,
            Self::Sequence1B => 3,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Sequence1A => "sequence 1A",
            Self::Sequence1B => "sequence 1B",
            Self::Sequence2 => "sequence 2",
        }
    }
}

impl ArmInsn {
    fn is_final_load_store_imm(insn: &ArmInsn, register: u32) -> bool {
        match insn {
            Self::LdrStr { rn, .. } if *rn == register => true,
            Self::Ldr { rn, .. } if *rn == register => true,
            _ => false,
        }
    }

    fn is_branch(insn: u32) -> bool {
        // B, BL
        (insn & 0x7c000000) == 0x14000000
           // B.cond and BC.cond
           || (insn & 0xff000000) == 0x54000000
           // CBZ, CBNZ
           || (insn & 0x7e000000) == 0x34000000
           // TBZ, TBNZ
           || (insn & 0x7e000000) == 0x36000000
           // BR, BLR, RET and authenticated/register control transfers
           || (insn & 0xfe000000) == 0xd6000000
    }

    fn from_opcode(insn: u32) -> Self {
        if insn & ADRP_MARK == ADRP_OPCODE {
            Self::Adrp {
                rd: insn & REGISTER_MASK,
            }
        } else if insn & LDR_UNSIGNED_MASK == LDR_UNSIGNED_OPCODE {
            // Note Ldr is a actually a part of LdrStr, parse it earlier.
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
                // rt is not used
                rn: (insn >> 5) & REGISTER_MASK,
            }
        } else if Self::is_branch(insn) {
            Self::Branch
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
            Self::Add { .. } | Self::Adrp { .. } | Self::Branch => return None,
            ArmInsn::Ldr { rt, .. } if rt == register => return None,
            _ => {}
        }

        // 3) Variant A (optional 3rd instruction)
        if insns.len() >= 4 {
            // This cannot be a branch.
            // This cannot write Rn.
            match insns[2] {
                Self::Branch => {}
                Self::Add { rd, .. } if rd == register => {}
                Self::Ldr { rt, .. } if rt == register => {}
                ArmInsn::Adrp { rd } if rd == register => {}
                _ => {
                    // 4) Load/store register (unsigned immediate)" encoding class, using Rn as the base address register.
                    if Self::is_final_load_store_imm(&insns[3], register) {
                        return Some(ErratumVariant::Sequence1A);
                    }
                }
            }
        }

        // 3) Variant B
        Self::is_final_load_store_imm(&insns[2], register).then_some(ErratumVariant::Sequence1B)
    }

    fn classify_sequence2(insns: &[ArmInsn]) -> Option<ErratumVariant> {
        if insns.len() < 4 {
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
            Self::Branch | Self::Adrp { .. } => return None,
            Self::Add { rd, .. } if rd != register => return None,
            Self::Add { rn, .. } if rn == register => return None,
            Self::Ldr { rt, .. } if rt != register => return None,
            Self::Ldr { rn, .. } if rn == register => return None,
            _ => {}
        }

        // 3) Another instruction.
        // This cannot be a branch.
        // This cannot write Rn.
        match insns[2] {
            Self::Branch => return None,
            Self::Add { rd, .. } if rd == register => return None,
            Self::Adrp { rd, .. } if rd == register => return None,
            Self::Ldr { rt, .. } if rt == register => return None,
            _ => {}
        }

        // 4) Load/store register (unsigned immediate)" encoding class, using Rn as the base address register.
        Self::is_final_load_store_imm(&insns[3], register).then_some(ErratumVariant::Sequence2)
    }

    fn classify_erratum_843419(insns: &[ArmInsn]) -> Option<ErratumVariant> {
        // Let's ignore Sequence2 now!
        Self::classify_sequence1(insns)
    }
}
