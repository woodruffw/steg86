use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Result};
use bit_vec::BitVec;
use goblin::{elf, mach, pe, Object};
use iced_x86::{Code, Decoder, DecoderOptions, Encoder, Instruction, OpKind};
use lazy_static::lazy_static;

/// The magic byte that identifies a steg86-instrumented file.
static STEG86_MAGIC: u8 = b'w';

/// A counter corresponding to protocol changes in steg86.
static STEG86_VERSION: u8 = 1;

/// The maximum capacity, in bytes, of a steg86-instrumented file.
/// Inputs may not be larger than this value.
static STEG86_MAX_CAPACITY_BYTES: u16 = u16::MAX;

/// The size, in bits, of the entire steg86 header.
/// This must be kept synchronized with the sizes of the above fields.
static STEG86_HEADER_SIZE_BITS: usize = 32;

/// The minimum capacity, in bits, required to encode a steg86 message.
/// This corresponds to the size of the steg86 header, plus a single message
/// byte.
static STEG86_MINIMUM_CAPACITY_BITS: usize = STEG86_HEADER_SIZE_BITS + 8;

lazy_static! {
    /// The set of all "supported" x86 and x86_64 opcodes, i.e. ones that
    /// steg86 knows how to detect and instrument.
    #[rustfmt::skip]
    static ref SUPPORTED_OPCODES: HashSet<Code> = [
        // ADD
        Code::Add_rm8_r8, Code::Add_r8_rm8,
        Code::Add_rm16_r16, Code::Add_r16_rm16,
        Code::Add_rm32_r32, Code::Add_r32_rm32,
        Code::Add_rm64_r64, Code::Add_r64_rm64,

        // ADC
        Code::Adc_rm8_r8, Code::Adc_r8_rm8,
        Code::Adc_rm16_r16, Code::Adc_r16_rm16,
        Code::Adc_rm32_r32, Code::Adc_r32_rm32,
        Code::Adc_rm64_r64, Code::Adc_r64_rm64,

        // AND
        Code::And_rm8_r8, Code::And_r8_rm8,
        Code::And_rm16_r16, Code::And_r16_rm16,
        Code::And_rm32_r32, Code::And_r32_rm32,
        Code::And_rm64_r64, Code::And_r64_rm64,

        // OR
        Code::Or_rm8_r8, Code::Or_r8_rm8,
        Code::Or_rm16_r16, Code::Or_r16_rm16,
        Code::Or_rm32_r32, Code::Or_r32_rm32,
        Code::Or_rm64_r64, Code::Or_r64_rm64,

        // XOR
        Code::Xor_rm8_r8, Code::Xor_r8_rm8,
        Code::Xor_rm16_r16, Code::Xor_r16_rm16,
        Code::Xor_rm32_r32, Code::Xor_r32_rm32,
        Code::Xor_rm64_r64, Code::Xor_r64_rm64,

        // SUB
        Code::Sub_rm8_r8, Code::Sub_r8_rm8,
        Code::Sub_rm16_r16, Code::Sub_r16_rm16,
        Code::Sub_rm32_r32, Code::Sub_r32_rm32,
        Code::Sub_rm64_r64, Code::Sub_r64_rm64,

        // SBB
        Code::Sbb_rm8_r8, Code::Sbb_r8_rm8,
        Code::Sbb_rm16_r16, Code::Sbb_r16_rm16,
        Code::Sbb_rm32_r32, Code::Sbb_r32_rm32,
        Code::Sbb_rm64_r64, Code::Sbb_r64_rm64,

        // MOV
        Code::Mov_rm8_r8, Code::Mov_r8_rm8,
        Code::Mov_rm16_r16, Code::Mov_r16_rm16,
        Code::Mov_rm32_r32, Code::Mov_r32_rm32,
        Code::Mov_rm64_r64, Code::Mov_r64_rm64,

        // CMP
        Code::Cmp_rm8_r8, Code::Cmp_r8_rm8,
        Code::Cmp_rm16_r16, Code::Cmp_r16_rm16,
        Code::Cmp_rm32_r32, Code::Cmp_r32_rm32,
        Code::Cmp_rm64_r64, Code::Cmp_r64_rm64,

        // TEST
        Code::Test_rm8_r8,
        Code::Test_rm16_r16,
        Code::Test_rm32_r32,
        Code::Test_rm64_r64,
    ]
    .iter()
    .cloned()
    .collect();
}

/// An array of 2-tuples of opcodes that are semantically paired, each
/// pair representing a single potential bit of information.
/// The first member represents `false` (`0`), and the second member represents
/// `true` (`1`).
#[rustfmt::skip]
static SEMANTIC_PAIRS: &[(Code, Code)] = &[
    // ADD
    (Code::Add_rm8_r8, Code::Add_r8_rm8),
    (Code::Add_rm16_r16, Code::Add_r16_rm16),
    (Code::Add_rm32_r32, Code::Add_r32_rm32),
    (Code::Add_rm64_r64, Code::Add_r64_rm64),

    // ADC
    (Code::Adc_rm8_r8, Code::Adc_r8_rm8),
    (Code::Adc_rm16_r16, Code::Adc_r16_rm16),
    (Code::Adc_rm32_r32, Code::Adc_r32_rm32),
    (Code::Adc_rm64_r64, Code::Adc_r64_rm64),

    // AND
    (Code::And_rm8_r8, Code::And_r8_rm8),
    (Code::And_rm16_r16, Code::And_r16_rm16),
    (Code::And_rm32_r32, Code::And_r32_rm32),
    (Code::And_rm64_r64, Code::And_r64_rm64),

    // OR
    (Code::Or_rm8_r8, Code::Or_r8_rm8),
    (Code::Or_rm16_r16, Code::Or_r16_rm16),
    (Code::Or_rm32_r32, Code::Or_r32_rm32),
    (Code::Or_rm64_r64, Code::Or_r64_rm64),

    // XOR
    (Code::Xor_rm8_r8, Code::Xor_r8_rm8),
    (Code::Xor_rm16_r16, Code::Xor_r16_rm16),
    (Code::Xor_rm32_r32, Code::Xor_r32_rm32),
    (Code::Xor_rm64_r64, Code::Xor_r64_rm64),

    // SUB
    (Code::Sub_rm8_r8, Code::Sub_r8_rm8),
    (Code::Sub_rm16_r16, Code::Sub_r16_rm16),
    (Code::Sub_rm32_r32, Code::Sub_r32_rm32),
    (Code::Sub_rm64_r64, Code::Sub_r64_rm64),

    // SBB
    (Code::Sbb_rm8_r8, Code::Sbb_r8_rm8),
    (Code::Sbb_rm16_r16, Code::Sbb_r16_rm16),
    (Code::Sbb_rm32_r32, Code::Sbb_r32_rm32),
    (Code::Sbb_rm64_r64, Code::Sbb_r64_rm64),

    // MOV
    (Code::Mov_rm8_r8, Code::Mov_r8_rm8),
    (Code::Mov_rm16_r16, Code::Mov_r16_rm16),
    (Code::Mov_rm32_r32, Code::Mov_r32_rm32),
    (Code::Mov_rm64_r64, Code::Mov_r64_rm64),

    // CMP
    (Code::Cmp_rm8_r8, Code::Cmp_r8_rm8),
    (Code::Cmp_rm16_r16, Code::Cmp_r16_rm16),
    (Code::Cmp_rm32_r32, Code::Cmp_r32_rm32),
    (Code::Cmp_rm64_r64, Code::Cmp_r64_rm64),
];

lazy_static! {
    /// The set of all commutative opcodes, i.e. the ones
    /// with two different registers as operands where their
    /// order does not change the computation
    #[rustfmt::skip]
    static ref COMMUTATIVE_OPCODES: HashSet<Code> = [
        // TEST
        Code::Test_rm8_r8,
        Code::Test_rm16_r16,
        Code::Test_rm32_r32,
        Code::Test_rm64_r64,
    ]
    .iter()
    .cloned()
    .collect();
}

/// Represents some potentially instrumentable program instruction text.
#[derive(Clone, Debug)]
pub struct Text {
    /// The "bitness" of the instructions. This is always `16`, `32`, or `64`.
    bitness: u32,

    /// The start offset of this instruction text, within some (unspecified) input file.
    start_offset: usize,

    /// The end offset of this instruction text, within some (unspecified) input file.
    end_offset: usize,

    /// The raw instruction data.
    data: Vec<u8>,
}

/// Represents the steganographic suitability of some instruction text.
#[derive(Debug)]
pub struct StegProfile {
    /// The total number of instructions.
    pub instruction_count: usize,

    /// The number of available semantic pairs.
    pub semantic_pairs: usize,

    /// The number of available commutative instructions.
    pub commutative_instructions: usize,

    /// The total potential information capacity, in bits. This will always be strictly less
    /// than `semantic_pairs`, to accommodate the steg86 header.
    pub information_capacity: usize,

    /// An array of instruction text offsets, one for each pair in `semantic_pairs`.
    information_offsets: Vec<usize>,
}

impl Text {
    /// Generate a steganographic profile for this `Text`, or `Err` if the text is
    /// unsuitable for steg86 (e.g., if it has too few semantic pairs).
    pub fn profile(&self) -> Result<StegProfile> {
        let mut icount = 0;
        let mut pair_count = 0;
        let mut commutative_count = 0;
        let mut offsets = Vec::new();
        let mut decoder = Decoder::new(self.bitness, &self.data, DecoderOptions::NONE);

        for instruction in &mut decoder {
            // Iterating over the decoder yields Code::INVALID on errors, so handle them first.
            if instruction.code() == Code::INVALID {
                return Err(anyhow!(
                    "encountered an invalid instruction at text offset {} (file offset {})",
                    decoder.position(),
                    self.start_offset + decoder.position(),
                ));
            }

            icount += 1;

            // Is our opcode one of the ones the has a semantic dual?
            // If not, skip it.
            if !SUPPORTED_OPCODES.contains(&instruction.code()) {
                continue;
            }

            // Is our opcode register-to-register?
            // If not, skip it.
            if instruction.op0_kind() != OpKind::Register
                || instruction.op1_kind() != OpKind::Register
            {
                continue;
            }

            // Are we handling a semantic pair, or a commutative instruction?
            // Increment the appropriate counter.
            if COMMUTATIVE_OPCODES.contains(&instruction.code()) {
                // If it's commutative and the registers are equal, skip it.
                if instruction.op0_register() == instruction.op1_register() {
                    continue;
                }

                commutative_count += 1;
            } else {
                pair_count += 1;
            }

            // We don't set a different base IP, so ip here always corresponds
            // to our text offset.
            offsets.push(instruction.ip() as usize);
        }

        // Fail if we don't have enough bits of information to store *at least* the steg86
        // header and a single byte of message data.
        if offsets.len() < STEG86_MINIMUM_CAPACITY_BITS {
            return Err(anyhow!(
                "insufficient steganographic capacity: expected at least {} bits, got {}",
                STEG86_MINIMUM_CAPACITY_BITS,
                offsets.len()
            ));
        }

        // Sanity check: we should have exactly as many offsets as the
        // total number of semantic pairs and commutative instructions.
        if offsets.len() != pair_count + commutative_count {
            return Err(anyhow!(
                "serious internal error: mismatch between offset count and potential instruction count ({} != {})",
                offsets.len(),
                pair_count + commutative_count,
            ));
        }

        Ok(StegProfile {
            instruction_count: icount,
            semantic_pairs: pair_count,
            commutative_instructions: commutative_count,
            information_capacity: offsets.len() - STEG86_HEADER_SIZE_BITS,
            information_offsets: offsets,
        })
    }

    /// Embed a message into this `Text`.
    ///
    /// `message` must be less than `STEG86_MAX_CAPACITY_BYTES`, and will
    /// not be embedded if it exceeds the information capacity of the
    /// `Text.
    ///
    /// Returns a modified `Text` on success, or `Err` on any failure.
    pub fn embed(&self, message: &[u8]) -> Result<Self> {
        log::debug!("given {} bytes to embed", message.len());

        if message.len() > (STEG86_MAX_CAPACITY_BYTES as usize) {
            return Err(anyhow!(
                "message exceeds maximum format length by {} bits",
                (message.len() - (STEG86_MAX_CAPACITY_BYTES as usize)) * 8
            ));
        }

        let profile = self.profile()?;
        if message.len() * 8 > profile.information_capacity {
            return Err(anyhow!(
                "message exceeds steganographic capacity by {} bits",
                (message.len() * 8) - profile.information_capacity
            ));
        }

        // Build the bitstring.
        let bits = {
            // NOTE(ww): BitVec::append silently fails across multiple calls,
            // so we construct a Vec<u8> instead and throw it into the BitVec
            // in a single shot. This wasted about two hours of my time.
            // See: https://github.com/contain-rs/bit-vec/issues/63
            let mut bytes = vec![STEG86_MAGIC, STEG86_VERSION];
            bytes.extend_from_slice(&(message.len() as u16).to_le_bytes());
            bytes.extend_from_slice(message);
            BitVec::from_bytes(&bytes)
        };

        let mut text_copy = (*self).clone();
        let mut decoder = Decoder::new(self.bitness, &self.data, DecoderOptions::NONE);
        let mut encoder = Encoder::new(self.bitness);

        for (bit, &offset) in bits.iter().zip(profile.information_offsets.iter()) {
            log::debug!("encoding bit {} at text offset {}", bit, offset);

            // First, decode the instruction at `ip` in the original text.
            // Barf if it isn't one of our supported opcodes.
            let instruction = {
                decoder.try_set_position(offset)?;
                // NOTE(ww): This unwrap isn't strictly safe, but a decoder error
                // here indicates that we've messed up earlier in profiling.
                let instruction = decoder.iter().next().unwrap();

                if !SUPPORTED_OPCODES.contains(&instruction.code()) {
                    return Err(anyhow!(
                        "expected a supported opcode at text offset {} but got {:?}",
                        offset,
                        instruction.code()
                    ));
                }

                instruction
            };

            let r0 = instruction.op0_register();
            let r1 = instruction.op1_register();
            // Next, transform that instruction as per our needed bit of information.
            // If we're already right, just continue.
            let old_code = instruction.code();
            let commutative = COMMUTATIVE_OPCODES.contains(&old_code);
            let new_code = if commutative {
                old_code
            } else {
                // NOTE(ww): This unwrap is safe, since every opcode in SUPPORTED_OPCODES
                // also appears in a SEMANTIC_PAIRS tuple.
                let tuple = SEMANTIC_PAIRS
                    .iter()
                    .find(|&&t| old_code == t.0 || old_code == t.1)
                    .unwrap();

                match (bit, tuple.0 == old_code) {
                    (false, true) | (true, false) => {
                        log::debug!(
                            "bit at text offset {} is already correct ({}), skipping",
                            offset,
                            bit
                        );
                        continue;
                    }
                    (false, false) => tuple.0,
                    (true, true) => tuple.1,
                }
            };
            let (new_r0, new_r1) = if !commutative {
                (r0, r1)
            } else {
                match (bit, (r0 as usize) < (r1 as usize)) {
                    (true, false) | (false, true) => (r1, r0),
                    (true, true) | (false, false) => {
                        log::debug!(
                            "bit at text offset {} is already correct ({}), skipping",
                            offset,
                            bit
                        );
                        continue;
                    }
                }
            };

            log::debug!("{:?} => {:?}", old_code, new_code);

            // Here's where the magic happens.
            let new_instruction = Instruction::with2(new_code, new_r0, new_r1)?;
            let new_len = encoder
                .encode(&new_instruction, offset as u64)
                .map_err(|s| anyhow!(s))?;

            // Next, confirm that our new instruction is the same size as the old one.
            // Barf if it isn't.
            if new_len != instruction.len() {
                return Err(anyhow!(
                    "translated instruction has mismatched size ({} != {})",
                    instruction.len(),
                    new_len,
                ));
            }

            // Finally, yank the newly encoded instruction from the encoded and insert it
            // into our copy of the instruction text.
            text_copy
                .data
                .splice(offset..(offset + new_len), encoder.take_buffer());
        }

        if self.data.len() != text_copy.data.len() {
            return Err(anyhow!(
                "text mismatch: {} (original) vs {} (new); probably corrupted",
                self.data.len(),
                text_copy.data.len()
            ));
        }

        log::debug!("survived transformation!");

        Ok(text_copy)
    }

    /// Extract a message from this `Text`.
    ///
    /// Returns the message bytes on success, or `Err` on any failure.
    pub fn extract(&self) -> Result<Vec<u8>> {
        let profile = self.profile()?;
        let mut decoder = Decoder::new(self.bitness, &self.data, DecoderOptions::NONE);

        // First, exact the steg86 header.
        let header_bytes = {
            log::debug!("extracting steg86 header");

            let mut header_bits = BitVec::new();
            header_bits.reserve(STEG86_HEADER_SIZE_BITS);

            for &offset in profile
                .information_offsets
                .iter()
                .take(STEG86_HEADER_SIZE_BITS)
            {
                let instruction = {
                    decoder.try_set_position(offset)?;
                    // NOTE(ww): This unwrap isn't strictly safe, but a decoder error
                    // here indicates that we've messed up earlier in profiling.
                    let instruction = decoder.iter().next().unwrap();
                    let code = instruction.code();

                    if !SUPPORTED_OPCODES.contains(&code) {
                        return Err(anyhow!(
                            "expected a supported opcode at text offset {} but got {:?}",
                            offset,
                            code
                        ));
                    }

                    instruction
                };

                let code = instruction.code();
                if COMMUTATIVE_OPCODES.contains(&code) {
                    let (r0, r1) = (instruction.op0_register(), instruction.op1_register());
                    header_bits.push((r0 as usize) < (r1 as usize));
                } else {
                    let tuple = SEMANTIC_PAIRS
                        .iter()
                        .find(|&&t| code == t.0 || code == t.1)
                        .unwrap();

                    header_bits.push(code != tuple.0);
                }
            }

            header_bits.to_bytes()
        };

        // Validate the header.
        if header_bytes.len() != 4 {
            return Err(anyhow!("short steg86 header?"));
        } else if header_bytes[0] != STEG86_MAGIC {
            return Err(anyhow!(
                "bad steg86 magic (expected {}, got {})",
                STEG86_MAGIC,
                header_bytes[0]
            ));
        } else if header_bytes[1] != STEG86_VERSION {
            return Err(anyhow!(
                "incompatible steg86 version (expected {}, got {})",
                STEG86_VERSION,
                header_bytes[1],
            ));
        }

        // Grab the message length, in bytes, from the header.
        let message_len = u16::from_le_bytes([header_bytes[2], header_bytes[3]]) as usize;
        if message_len == 0 {
            return Err(anyhow!("no data follows valid steg86 header"));
        }

        log::debug!(
            "successfully extracted a steg86 header; now expecting {} bytes of data",
            message_len
        );

        // Finally, extract the message itself.
        // TODO(ww): De-dupe the decode loop here.
        let message_bytes = {
            let mut message_bits = BitVec::new();
            message_bits.reserve(profile.information_capacity);

            for &offset in profile
                .information_offsets
                .iter()
                .skip(STEG86_HEADER_SIZE_BITS)
                .take(message_len * 8)
            {
                let instruction = {
                    decoder.try_set_position(offset)?;
                    // NOTE(ww): This unwrap isn't strictly safe, but a decoder error
                    // here indicates that we've messed up earlier in profiling.
                    let instruction = decoder.iter().next().unwrap();
                    let code = instruction.code();

                    if !SUPPORTED_OPCODES.contains(&code) {
                        return Err(anyhow!(
                            "expected a supported opcode at text offset {} but got {:?}",
                            offset,
                            code
                        ));
                    }

                    instruction
                };

                let code = instruction.code();
                if COMMUTATIVE_OPCODES.contains(&code) {
                    let (r0, r1) = (instruction.op0_register(), instruction.op1_register());
                    message_bits.push((r0 as usize) < (r1 as usize));
                } else {
                    let tuple = SEMANTIC_PAIRS
                        .iter()
                        .find(|&&t| code == t.0 || code == t.1)
                        .unwrap();

                    message_bits.push(code != tuple.0);
                }
            }

            message_bits.to_bytes()
        };

        if message_bytes.len() != message_len {
            return Err(anyhow!(
                "message length mismatch: expected {} bytes, got {}",
                message_len,
                message_bytes.len()
            ));
        }

        Ok(message_bytes)
    }

    /// "Patch" the given input file with this `Text`, returning the patched bytes.
    pub fn patch_program(&self, path: &Path) -> Result<Vec<u8>> {
        let mut program_buffer = fs::read(path)?;

        if self.end_offset > program_buffer.len() {
            return Err(anyhow!("proposed patch exceeds input's size"));
        }

        program_buffer.splice(self.start_offset..self.end_offset, self.data.clone());

        Ok(program_buffer)
    }

    pub fn from_raw(path: &Path, bitness: u32) -> Result<Self> {
        let program_buffer = fs::read(path)?;

        #[allow(clippy::redundant_field_names)]
        Ok(Text {
            bitness: bitness,
            start_offset: 0,
            end_offset: program_buffer.len(),
            data: program_buffer,
        })
    }

    /// Extract the `Text` for a supported program binary.
    pub fn from_program(path: &Path) -> Result<Self> {
        let program_buffer = fs::read(path)?;

        match Object::parse(&program_buffer)? {
            Object::Elf(elf) => Self::from_elf(&elf, &program_buffer),
            Object::Mach(macho) => Self::from_macho(&macho),
            Object::PE(pe) => Self::from_pe(&pe, &program_buffer),
            _ => Err(anyhow!("unknown or unsupported format")),
        }
    }

    /// Create a `Text` from a valid ELF binary.
    fn from_elf(elf: &elf::Elf, program_buffer: &[u8]) -> Result<Self> {
        let bitness = match elf.header.e_machine {
            elf::header::EM_386 => 32,
            elf::header::EM_X86_64 => 64,
            _ => return Err(anyhow!("unknown ELF e_machine: {}", elf.header.e_machine)),
        };

        if let Some(text_section) = elf.section_headers.iter().find(|&sect| {
            elf.shdr_strtab
                .get_at(sect.sh_name)
                .map_or(false, |name| name == ".text")
        }) {
            let size = text_section.sh_size as usize;
            let offset = text_section.sh_offset as usize;
            if size >= program_buffer.len() || offset >= program_buffer.len() {
                return Err(anyhow!("invalid size for .text section"));
            }

            let mut section_buf = vec![0u8; size];
            (&program_buffer[offset..]).read_exact(&mut section_buf)?;

            #[allow(clippy::redundant_field_names)]
            Ok(Text {
                bitness: bitness,
                start_offset: offset,
                end_offset: offset + size,
                data: section_buf,
            })
        } else {
            Err(anyhow!("couldn't find .text section; maybe stripped?"))
        }
    }

    /// Create a `Text` from a valid (single-arch) Mach-O binary.
    fn from_macho(macho: &mach::Mach) -> Result<Self> {
        let macho = match macho {
            mach::Mach::Fat(_) => return Err(anyhow!("fat Mach-O binaries are not supported")),
            mach::Mach::Binary(macho) => macho,
        };

        let bitness = match macho.header.cputype {
            mach::constants::cputype::CPU_TYPE_X86 => 32,
            mach::constants::cputype::CPU_TYPE_X86_64 => 64,
            _ => return Err(anyhow!("unknown Mach-O CPU type: {}", macho.header.cputype)),
        };

        if let Some(text_segment) = macho
            .segments
            .iter()
            .find(|&seg| seg.name().map_or(false, |name| name == "__TEXT"))
        {
            if let Some(text_section) = text_segment
                .sections()?
                .iter()
                .find(|&sect| sect.0.name().map_or(false, |name| name == "__text"))
            {
                #[allow(clippy::redundant_field_names)]
                Ok(Text {
                    bitness: bitness,
                    start_offset: text_section.0.offset as usize,
                    end_offset: (text_section.0.offset as usize) + (text_section.0.size as usize),
                    data: text_section.1.into(),
                })
            } else {
                Err(anyhow!("couldn't find __text section; maybe stripped?"))
            }
        } else {
            Err(anyhow!("couldn't find __TEXT segment; maybe stripped?"))
        }
    }

    /// Create a `Text` from a valid PE/PE32+ binary.
    fn from_pe(pe: &pe::PE, program_buffer: &[u8]) -> Result<Self> {
        let bitness = match pe.header.coff_header.machine {
            pe::header::COFF_MACHINE_X86 => 32,
            pe::header::COFF_MACHINE_X86_64 => 64,
            _ => {
                return Err(anyhow!(
                    "unknown PE (COFF) machine: {}",
                    pe.header.coff_header.machine
                ))
            }
        };

        if let Some(text_section) = pe
            .sections
            .iter()
            .find(|&sect| sect.name().map_or(false, |name| name == ".text"))
        {
            // NOTE(ww): Intuitively, SizeOfRawData would be correct here.
            // In practice, however, PE/PE32+s have page-aligned .text sections filled with
            // trailing NULs. As such, we need to use the actual loader size rather than
            // the size claimed by the section header.
            let size = text_section.virtual_size as usize;
            let offset = text_section.pointer_to_raw_data as usize;

            let mut section_buf = vec![0u8; size];
            (&program_buffer[offset..]).read_exact(&mut section_buf)?;

            #[allow(clippy::redundant_field_names)]
            Ok(Text {
                bitness: bitness,
                start_offset: offset,
                end_offset: offset + size,
                data: section_buf,
            })
        } else {
            Err(anyhow!("couldn't find .text section"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use super::*;

    // Create a `Text` with `desired_bits` bits of steganographic capacity.
    fn dummy_text(desired_bits: usize) -> Text {
        let xor_eax_eax = vec![0x31_u8, 0xc0_u8];
        let xors: Vec<u8> = iter::repeat(xor_eax_eax)
            .take(desired_bits)
            .flatten()
            .collect();

        Text {
            bitness: 64,
            start_offset: 0,
            end_offset: 0,
            data: xors,
        }
    }

    #[test]
    fn test_profile() {
        // TODO: Test failure on an invalid instruction in text.

        // Text without enough steganographic density for the header and
        // a single byte of message fails to profile.
        {
            let too_short = dummy_text(STEG86_HEADER_SIZE_BITS);

            let err = too_short.profile().unwrap_err();
            assert_eq!(
                err.to_string(),
                "insufficient steganographic capacity: expected at least 40 bits, got 32"
            );
        }

        {
            // Room for the header, plus 10 bytes (80 bits) of message.
            let nbits = STEG86_HEADER_SIZE_BITS + 80;
            let enough = dummy_text(nbits);
            let profile = enough.profile().unwrap();

            assert_eq!(profile.instruction_count, nbits);
            assert_eq!(profile.semantic_pairs, nbits);
            assert_eq!(
                profile.information_capacity,
                nbits - STEG86_HEADER_SIZE_BITS
            );
        }
    }

    #[test]
    fn test_embed() {
        // Embedding fails on messages that exceed STEG86_MAX_CAPACITY_BYTES.
        {
            let message = vec![1_u8; STEG86_MAX_CAPACITY_BYTES as usize + 1];
            let impossible = dummy_text(STEG86_HEADER_SIZE_BITS + 64);

            let err = impossible.embed(&message).unwrap_err();
            assert_eq!(
                err.to_string(),
                "message exceeds maximum format length by 8 bits"
            );
        }

        // Embedding fails when a message requires more bits than the text has available.
        {
            let message = b"abcdef";
            let too_short = dummy_text(STEG86_HEADER_SIZE_BITS + ((message.len() - 1) * 8));

            let err = too_short.embed(message).unwrap_err();
            assert_eq!(
                err.to_string(),
                "message exceeds steganographic capacity by 8 bits"
            );
        }

        // Embedding succeeds when the message does fit.
        {
            let message = b"abcdef";
            let just_right = dummy_text(STEG86_HEADER_SIZE_BITS + (message.len() * 8));

            let new_text = just_right.embed(message).unwrap();
            assert_eq!(new_text.data.len(), just_right.data.len());
        }
    }

    #[test]
    fn test_extract() {
        // TODO: Test failure on lack on insufficient semantic_pairs.

        // Extraction fails without a valid header.
        {
            let no_header = dummy_text(STEG86_HEADER_SIZE_BITS + 8);

            let err = no_header.extract().unwrap_err();
            assert_eq!(err.to_string(), "bad steg86 magic (expected 119, got 0)");
        }

        // TODO: Test bad steg86 version.
        // TODO: Test bad message length.

        // Extraction succeeds when everything goes right.
        {
            let message = b"abcdef";
            let just_right = dummy_text(STEG86_HEADER_SIZE_BITS + (message.len() * 8));
            let new_text = just_right.embed(message).unwrap();

            assert_eq!(message.to_vec(), new_text.extract().unwrap());
        }
    }

    // TODO: Come up with some binary format tests.

    // TODO: Tests for commutative instructions like TEST.
}
