#![allow(unused)]
use std::ffi::CStr;
use std::fmt::Display;
use std::{fs, io::Write};

use clap::{Parser, Subcommand};
use log::{debug, error, info};
use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, IntoBytes};
use zerocopy_derive::{FromBytes, Immutable, IntoBytes};

#[derive(Debug, Subcommand)]
enum Command {
    /// Convert the given a.out file to ELF, appending .elf.
    Convert {
        #[arg(index = 1)]
        file_name: String,
    },
    /// Only parse the given file.
    Parse {
        #[arg(index = 1)]
        file_name: String,
        /// Print section previews and more
        #[clap(long, short)]
        debug: bool,
        /// Dump symbol table entries and more
        #[clap(long, short)]
        verbose: bool,
    },
}

/// Convert Plan 9 a.out to ELF
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Command to run
    #[command(subcommand)]
    cmd: Command,
}

// See https://9p.io/magic/man2html/6/a.out
// and 9front sys/include/a.out.h
#[derive(FromBytes, Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct Aout {
    magic: u32,
    text_size: U32,         /* binary code segment */
    data_size: U32,         /* initialized data */
    bss_size: U32,          /* uninitialized data */
    symbol_table_size: U32, /* symbol table */
    entry_point: U32,       /* entry point */
    sp_size: U32,           /* pc/sp offset table */
    pc_size: U32,           /* pc/line number table */
}

#[derive(FromBytes, Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct AoutSymbolHeader {
    spacer: [u8; 4],
    value: U32,
    sym_type: u8,
}

#[derive(Clone, Debug)]
struct AoutSymbol<'a> {
    header: AoutSymbolHeader,
    name: &'a str,
}

// https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
// https://gist.github.com/DhavalKapil/2243db1b732b211d0c16fd5d9140ab0b

#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(u16)]
enum ElfType {
    None,
    Relocatable,
    Executable,
    SharedObject,
    Core,
    LoOS = 0xfe00,
    HiOS = 0xfeff,
    LoProc = 0xff00,
    HiProc = 0xffff,
}

#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(u8)]
enum ElfClass {
    None,
    Elf32,
    Elf64,
}

#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(u8)]
enum ElfDataEncoding {
    Invalid,
    LittleEndian,
    BigEndian,
}

#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(u8)]
enum ElfOsAbi {
    None,
    HpUx,
    NetBsd,
    Linux,
    SunSolaris,
    Aix,
    Irix,
    FreeBsd,
    Tru64Unix,
    NovellModesto,
    OpenBsd,
    OpenVms,
    HpNonStopKernel,
}

// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct ElfId {
    magic: [u8; 4],
    class: ElfClass,
    data_encoding: ElfDataEncoding,
    header_version: u8,
    os_abi: ElfOsAbi,
    abi_version: u8,
    _res: [u8; 7],
}

// NOTE: This is the complete list from Wikipedia as of 2025-06-04.
// Plan 9 a.out only supports few targets as of now, so we do not need them all.
#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(u16)]
enum ElfMachine {
    None = 0x00,
    AttWe32100 = 0x01,
    Sparc = 0x02,
    X86 = 0x03,
    M68k = 0x04,
    M88k = 0x05,
    IntelMcu = 0x06,
    Intel80860 = 0x07,
    Mips = 0x08,
    IbmSystem370 = 0x09,
    MipsRs3000LittleEndian = 0x0A,
    // 0x0B – 0x0E Reserved for future use
    HpPaRisc = 0x0F,
    Intel80960 = 0x13,
    PowerPC = 0x14,
    PowerPC64 = 0x15,
    S390 = 0x16,
    IbmSpuSpc = 0x17,
    // 0x18 – 0x23 Reserved for future use
    NecV800 = 0x24,
    FujitsuFr20 = 0x25,
    TrwRh32 = 0x26,
    MotorolaRce = 0x27,
    Aarch32 = 0x28,
    DigitalAlpha = 0x29,
    SuperH = 0x2A,
    SparcVersion9 = 0x2B,
    SiemensTriCoreEmbeddedProcessor = 0x2C,
    ArgonautRiscCore = 0x2D,
    HitachiH8300 = 0x2E,
    HitachiH8300H = 0x2F,
    HitachiH8S = 0x30,
    HitachiH8_500 = 0x31,
    Ia64 = 0x32,
    StanfordMipsX = 0x33,
    MotorolaColdFire = 0x34,
    MotorolaM68Hc12 = 0x35,
    FujitsuMmaMultimediaAccelerator = 0x36,
    SiemensPcp = 0x37,
    SonyNCpuEmbeddedRisc = 0x38,
    DensoNdr1Microprocessor = 0x39,
    MotorolaStarCoreProcessor = 0x3A,
    ToyotaMe16Processor = 0x3B,
    STMicroelectronicsST100 = 0x3C,
    AdvancedLogicTinyJEmbeddedProcessor = 0x3D,
    Amd64 = 0x3E,
    SonyDsp = 0x3F,
    DigitalPdp10 = 0x40,
    DigitalPdp11 = 0x41,
    SiemensFx66Microcontroller = 0x42,
    STMicroelectronicsST9Plus8_16bitMicrocontroller = 0x43,
    STMicroelectronicsST7_8bitMicrocontroller = 0x44,
    MotorolaMC68HC16Microcontroller = 0x45,
    MotorolaMC68HC11Microcontroller = 0x46,
    MotorolaMC68HC08Microcontroller = 0x47,
    MotorolaMC68HC05Microcontroller = 0x48,
    SiliconGraphicsSVx = 0x49,
    STMicroelectronicsST19_8bitMicrocontroller = 0x4A,
    DigitalVax = 0x4B,
    Axis32bitEmbeddedProcessor = 0x4C,
    Infineon32bitEmbeddedProcessor = 0x4D,
    Element14_64bitDsp = 0x4E,
    LsiLogic16bitDsp = 0x4F,
    Tms320C6000Family = 0x8C,
    McstElbrusE2k = 0xAF,
    Aarch64 = 0xB7,
    ZilogZ80 = 0xDC,
    RiscV = 0xF3,
    BerkeleyPacketFilter = 0xF7,
    WDC65C816 = 0x101,
    LoongArch = 0x102,
}

// NOTE: extracted for convenience, not an official thing.
#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct ElfExtra {
    flags: u32,
    elf_header_size: u16,
    program_header_entry_size: u16,
    program_header_entry_count: u16,
    section_header_entry_size: u16,
    section_header_entry_count: u16,
    section_header_index_entry: u16,
}

// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct Elf32Header {
    id: ElfId,
    elf_type: ElfType,
    machine: ElfMachine,
    version: u32,
    entry: u32,
    program_header_offset: u32,
    section_header_offset: u32,
    extra: ElfExtra,
}

// NOTE: only entry point address and program/section header offsets differ.
#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct Elf64Header {
    id: ElfId,
    elf_type: ElfType,
    machine: ElfMachine,
    version: u32,
    entry: u64,
    program_header_offset: u64,
    section_header_offset: u64,
    extra: ElfExtra,
}

#[derive(Immutable, Clone, Copy, Debug)]
#[repr(C)]
enum ElfHeader {
    Elf32(Elf32Header),
    Elf64(Elf64Header),
}

// NOTE: These are fixed by our convention. Be careful with section changes.
const SYM_STRING_TABLE_INDEX: u32 = 4;
const SH_STRING_TABLE_INDEX: u32 = 5;

impl ElfId {
    fn new(class: ElfClass) -> Self {
        Self {
            magic: ELF_MAGIC,
            class,
            data_encoding: ElfDataEncoding::LittleEndian,
            header_version: 1, // fixed
            os_abi: ElfOsAbi::None,
            abi_version: 0,
            _res: [0, 0, 0, 0, 0, 0, 0],
        }
    }
}

// NOTE: Many things are hardcoded here.
impl ElfHeader {
    fn new(
        program_header_entry_count: usize,
        section_header_entry_count: usize,
        entry: u32,
        machine: ElfMachine,
    ) -> Self {
        let is_64bit = is_64bit(machine);
        let elf_header_size = if is_64bit {
            ELF64_HEADER_SIZE
        } else {
            ELF32_HEADER_SIZE
        };
        let elf_program_header_size = if is_64bit {
            ELF64_PROGRAM_HEADER_SIZE
        } else {
            ELF32_PROGRAM_HEADER_SIZE
        };
        let elf_section_header_size = if is_64bit {
            ELF64_SECTION_HEADER_SIZE
        } else {
            ELF32_SECTION_HEADER_SIZE
        };

        let extra = ElfExtra {
            flags: 0x00,
            elf_header_size: elf_header_size as u16,
            program_header_entry_size: elf_program_header_size as u16,
            program_header_entry_count: program_header_entry_count as u16,
            section_header_entry_size: elf_section_header_size as u16,
            section_header_entry_count: section_header_entry_count as u16,
            section_header_index_entry: SH_STRING_TABLE_INDEX as u16,
        };

        // NOTE: There are only few entries, so they always fit in u32.
        let ph_size = (program_header_entry_count * elf_program_header_size) as u32;
        let ph_offset = elf_header_size as u32;
        let sh_offset = ph_offset + ph_size;

        match machine {
            ElfMachine::Amd64 => ElfHeader::Elf32(Elf32Header {
                id: ElfId::new(ElfClass::Elf32),
                elf_type: ElfType::Executable,
                machine,
                version: 1,
                entry,
                program_header_offset: ph_offset,
                section_header_offset: sh_offset,
                extra,
            }),
            ElfMachine::RiscV => ElfHeader::Elf64(Elf64Header {
                id: ElfId::new(ElfClass::Elf64),
                elf_type: ElfType::Executable,
                machine,
                version: 1,
                entry: entry as u64,
                program_header_offset: ph_offset as u64,
                section_header_offset: sh_offset as u64,
                extra,
            }),
            _ => todo!("support more targets"),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            ElfHeader::Elf32(h) => h.as_bytes(),
            ElfHeader::Elf64(h) => h.as_bytes(),
        }
    }
}

#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(u32)]
enum ElfProgramType {
    Null,
    Load,
    Dynamic,
    Note,
    Interpreted,
    ProgramHeader,
}

// https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html
#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct Elf32ProgramHeader {
    program_type: ElfProgramType,
    offset: u32,
    virtual_addr: u32,
    physical_addr: u32,
    file_size: u32,
    memory_size: u32,
    flags: u32,
    align: u32,
}

#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct Elf64ProgramHeader {
    program_type: ElfProgramType,
    flags: u32,
    offset: u64,
    virtual_addr: u64,
    physical_addr: u64,
    file_size: u64,
    memory_size: u64,
    align: u64,
}

#[derive(Immutable, Clone, Copy, Debug)]
#[repr(C)]
enum ElfProgramHeader {
    Elf32(Elf32ProgramHeader),
    Elf64(Elf64ProgramHeader),
}

impl ElfProgramHeader {
    fn as_bytes(&self) -> &[u8] {
        match self {
            ElfProgramHeader::Elf32(h) => h.as_bytes(),
            ElfProgramHeader::Elf64(h) => h.as_bytes(),
        }
    }
}

// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html
#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(u32)]
enum ElfSectionType {
    Null,
    ProgBits,
    SymbolTable,
    SymbolStringTable,
    RelocationEntriesWithAddends,
    SymbolHashTable,
    Dynamic,
    Note,
    NoBits,
    Rel,
    Shlib,
    DynamicSymbols,
    // mind the gap
    InitArray = 14,
    FiniArray,
    PreinitArray,
    Group,
    SymbolTableIndex,
    LoOS = 0x60000000,
    HiOS = 0x6fffffff,
    LoProc = 0x70000000,
    HiProc = 0x7fffffff,
    LoUser = 0x80000000,
    HiUser = 0xffffffff,
}

// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html
#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct Elf32SectionHeader {
    name: u32,
    section_type: ElfSectionType,
    flags: u32,
    addr: u32,
    offset: u32,
    size: u32,
    link: u32,
    info: u32,
    addr_align: u32,
    entry_size: u32,
}

#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct Elf64SectionHeader {
    name: u32,
    section_type: ElfSectionType,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addr_align: u64,
    entry_size: u64,
}

#[derive(Immutable, Clone, Copy, Debug)]
#[repr(C)]
enum ElfSectionHeader {
    Elf32(Elf32SectionHeader),
    Elf64(Elf64SectionHeader),
}

impl ElfSectionHeader {
    fn as_bytes(&self) -> &[u8] {
        match self {
            ElfSectionHeader::Elf32(h) => h.as_bytes(),
            ElfSectionHeader::Elf64(h) => h.as_bytes(),
        }
    }
}

// `man elf`
// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.symtab.html
#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct Elf32SymbolTableEntry {
    name_offset: u32, // offset into string table
    value: u32,
    size: u32,
    info: u8,
    other: u8,
    section_index: u16,
}

#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct Elf64SymbolTableEntry {
    name_offset: u32, // offset into string table
    info: u8,
    other: u8,
    section_index: u16,
    value: u64,
    size: u64,
}

// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.symtab.html
#[derive(Immutable, Clone, Copy, Debug)]
#[repr(C)]
enum ElfSymbolTableEntry {
    Elf32(Elf32SymbolTableEntry),
    Elf64(Elf64SymbolTableEntry),
}

impl ElfSymbolTableEntry {
    fn as_bytes(&self) -> &[u8] {
        match self {
            ElfSymbolTableEntry::Elf32(e) => e.as_bytes(),
            ElfSymbolTableEntry::Elf64(e) => e.as_bytes(),
        }
    }
}

const AOUT_HEADER_SIZE: usize = std::mem::size_of::<Aout>();

const ELF32_HEADER_SIZE: usize = std::mem::size_of::<Elf32Header>();
const ELF64_HEADER_SIZE: usize = std::mem::size_of::<Elf64Header>();

const ELF32_PROGRAM_HEADER_SIZE: usize = std::mem::size_of::<Elf32ProgramHeader>();
const ELF64_PROGRAM_HEADER_SIZE: usize = std::mem::size_of::<Elf64ProgramHeader>();

const ELF32_SECTION_HEADER_SIZE: usize = std::mem::size_of::<Elf32SectionHeader>();
const ELF64_SECTION_HEADER_SIZE: usize = std::mem::size_of::<Elf64SectionHeader>();

const ELF32_SYMBOL_TABLE_ENTRY_SIZE: usize = std::mem::size_of::<Elf32SymbolTableEntry>();
const ELF64_SYMBOL_TABLE_ENTRY_SIZE: usize = std::mem::size_of::<Elf64SymbolTableEntry>();

// https://www.gnu.org/software/grub/manual/multiboot/multiboot.html
const MULTIBOOT_HEADER_SIZE: usize = 0x48;

// TODO: Multiboot struct

const PAD_BASIC_SIZE: usize = 4;
const PAD_EXTRA_SIZE: usize = 8;
const PAD_SIZE: usize = PAD_BASIC_SIZE + PAD_EXTRA_SIZE;

fn aout_mach_to_elf(aout: &Aout) -> ElfMachine {
    let m = aout.magic;
    match m {
        0x978a_0000 => ElfMachine::Amd64,
        0x178e_0000 => ElfMachine::RiscV,
        _ => todo!("Architecture not yet supported: {m:08x}"),
    }
}

fn align_4k(v: u32) -> u32 {
    ((v - 1) / 4096 + 1) * 4096
}

// 🧝✨
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

// sys/man/6/a.out
const SYM_TEXT: u8 = b'T';
const SYM_STATIC_TEXT: u8 = b't';
const SYM_LEAF_FN: u8 = b'L';
const SYM_STATIC_LEAF_FN: u8 = b'l';
const SYM_DATA: u8 = b'D';
const SYM_STATIC_DATA: u8 = b'd';
const SYM_BSS_SEGMENT: u8 = b'B';
const SYM_STATIC_BSS_SEGMENT: u8 = b'b';
const SYM_AUTO_VAR: u8 = b'a';
const SYM_FN_PARAM: u8 = b'p';
const SYM_FRAME_SYMBOL: u8 = b'm';
const SYM_SRC_COMP: u8 = b'f';
const SYM_SRC_FILE: u8 = b'z';
const SYM_SRC_OFFSET: u8 = b'Z';
const SYM_E: u8 = b'e';
const SYM_G: u8 = b'g';
const SYM_I: u8 = b'I';
const SYM_O: u8 = b'o';
const SYM_S: u8 = b'S';
const SYM_U: u8 = b'u';
const SYM_V: u8 = b'v';
const SYM_W: u8 = b'w';
const SYM__: u8 = b'_';
const SYM_0: u8 = b'0';
const SYM_CURLY: u8 = b'{';

#[derive(Debug, Eq, PartialEq)]
enum AoutSymbolType {
    TextSegment,
    StaticTextSegment,
    LeafFunction,
    StaticLeafFunction,
    DataSegment,
    StaticDataSegment,
    BssSegment,
    StaticBssSegment,
    AutoVariable,
    FunctionParam,
    FrameSymbol,
    SourceFileNameComp,
    SourceFileName,
    SourceFileOffset,
    ____X,
    Curly,
    E,
    G,
    I,
    M,
    O,
    S,
    U,
    V,
    W,
    Zero,
    Unknown,
}

fn aout_symbol_type(s: &AoutSymbol) -> AoutSymbolType {
    // First bit needs to be discarded.
    match s.header.sym_type & !0x80 {
        SYM_TEXT => AoutSymbolType::TextSegment,
        SYM_STATIC_TEXT => AoutSymbolType::StaticTextSegment,
        SYM_LEAF_FN => AoutSymbolType::LeafFunction,
        SYM_STATIC_LEAF_FN => AoutSymbolType::StaticLeafFunction,
        SYM_DATA => AoutSymbolType::DataSegment,
        SYM_STATIC_DATA => AoutSymbolType::StaticDataSegment,
        SYM_STATIC_BSS_SEGMENT => AoutSymbolType::StaticBssSegment,
        SYM_BSS_SEGMENT => AoutSymbolType::BssSegment,
        SYM_AUTO_VAR => AoutSymbolType::AutoVariable,
        SYM_FN_PARAM => AoutSymbolType::FunctionParam,
        SYM_FRAME_SYMBOL => AoutSymbolType::FrameSymbol,
        SYM_SRC_COMP => AoutSymbolType::SourceFileNameComp,
        SYM_SRC_FILE => AoutSymbolType::SourceFileName,
        SYM_SRC_OFFSET => AoutSymbolType::SourceFileOffset,
        SYM_E => AoutSymbolType::E,
        SYM_G => AoutSymbolType::G,
        SYM_I => AoutSymbolType::I,
        SYM_O => AoutSymbolType::O,
        SYM_S => AoutSymbolType::S,
        SYM_U => AoutSymbolType::U,
        SYM_V => AoutSymbolType::V,
        SYM_W => AoutSymbolType::W,
        SYM__ => AoutSymbolType::____X,
        SYM_0 => AoutSymbolType::Zero,
        SYM_CURLY => AoutSymbolType::Curly,
        // TODO: What else?
        _ => AoutSymbolType::Unknown,
    }
}

fn aout_syms_to_elf(
    aout_syms: Vec<AoutSymbol>,
    is_64bit: bool,
) -> (Vec<ElfSymbolTableEntry>, Vec<u8>) {
    // TODO: enums, ElfInfo struct
    const SYM_LOCAL: u8 = 0 << 4;
    const SYM_GLOBAL: u8 = 1 << 4;
    const SYM_FUNCTION: u8 = 2;

    // NOTE: For now, text symbols only.
    let mut t_syms = aout_syms.iter().filter(|s| {
        let t = s.get_type();
        t == AoutSymbolType::TextSegment || t == AoutSymbolType::StaticTextSegment
    });
    let mut t_syms: Vec<&AoutSymbol> = t_syms.collect();
    t_syms.sort_by_key(|e| e.header.value);

    // string table
    let f = [0u8].as_bytes();
    let mut sym_str_tab = f.to_vec();

    let mut elf_sym_tab: Vec<ElfSymbolTableEntry> = vec![];
    // first is a 0-byte
    let mut name_offset: u32 = 1;

    // first is the undefined symbol by convention
    if is_64bit {
        let e = Elf64SymbolTableEntry {
            name_offset: 0,
            value: 0,
            size: 0,
            info: 0,
            other: 0,
            section_index: 0,
        };
        elf_sym_tab.push(ElfSymbolTableEntry::Elf64(e));
    } else {
        let e = Elf32SymbolTableEntry {
            name_offset: 0,
            value: 0,
            size: 0,
            info: 0,
            other: 0,
            section_index: 0,
        };
        elf_sym_tab.push(ElfSymbolTableEntry::Elf32(e));
    };

    // https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-79797.html
    // > In executable and shared object files, st_value holds a virtual address.

    for s in t_syms.windows(2) {
        // symbol name
        let curr_name = s[0].name;
        sym_str_tab.extend_from_slice(curr_name.as_bytes());
        sym_str_tab.extend_from_slice(f);

        // symbol
        let curr_value: u32 = s[0].header.value.into();
        let next_value: u32 = s[1].header.value.into();
        let size = next_value - curr_value;
        let value = curr_value;
        if is_64bit {
            let e = Elf64SymbolTableEntry {
                name_offset,
                value: value as u64,
                size: size as u64,
                info: SYM_LOCAL | SYM_FUNCTION,
                other: 0,
                section_index: 1,
            };
            elf_sym_tab.push(ElfSymbolTableEntry::Elf64(e));
        } else {
            let e = Elf32SymbolTableEntry {
                name_offset,
                value,
                size,
                info: SYM_LOCAL | SYM_FUNCTION,
                other: 0,
                section_index: 1,
            };
            elf_sym_tab.push(ElfSymbolTableEntry::Elf32(e));
        };

        // account for 0-byte
        name_offset += curr_name.len() as u32 + 1;
    }

    (elf_sym_tab, sym_str_tab)
}

const VIRTUAL_BASE_AMD64: u64 = 0x8000_0000;
const VIRTUAL_BASE_RISCV64: u64 = 0x0000_0000;

fn is_64bit(machine: ElfMachine) -> bool {
    match machine {
        ElfMachine::Amd64 => false,
        ElfMachine::RiscV => true,
        _ => todo!(),
    }
}

// TODO: Something with the memory sizes is strange.
fn aout_to_elf(d: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok((aout, _)) = Aout::read_from_prefix(d) {
        let machine_target = aout_mach_to_elf(&aout);

        let is_64bit = is_64bit(machine_target);

        let virtual_base = match machine_target {
            ElfMachine::Amd64 => VIRTUAL_BASE_AMD64,
            ElfMachine::RiscV => VIRTUAL_BASE_RISCV64,
            _ => todo!(),
        };

        let entry: u32 = aout.entry_point.into();

        // TODO: calculate
        let program_header_entry_count = 3;
        // TODO: calculate
        let section_header_entry_count = 6;

        // a.out only gives us sizes
        let ts: u32 = aout.text_size.into();
        let ds: u32 = aout.data_size.into();
        let ss: u32 = aout.symbol_table_size.into();

        // so offsets have to be calculated
        let t_offset = AOUT_HEADER_SIZE + PAD_EXTRA_SIZE;
        let d_offset = t_offset + ts as usize;
        let s_offset = d_offset + ds as usize;

        let data_load_addr = entry + align_4k(ts);

        // the offset in the ELF file, needed to calculate other offsets
        let main_offset = if is_64bit {
            (ELF64_HEADER_SIZE
                + program_header_entry_count * ELF64_PROGRAM_HEADER_SIZE
                + section_header_entry_count * ELF64_SECTION_HEADER_SIZE
                + PAD_SIZE) as u32
        } else {
            (ELF32_HEADER_SIZE
                + program_header_entry_count * ELF32_PROGRAM_HEADER_SIZE
                + section_header_entry_count * ELF32_SECTION_HEADER_SIZE
                + PAD_SIZE) as u32
        };

        // we will reappend this later
        let data = &d[t_offset..];

        // ----------- program headers
        let program_headers = {
            let mut program_headers: Vec<ElfProgramHeader> = vec![];

            const PH_FLAG_READ: u32 = 1 << 2;
            const PH_FLAG_WRITE: u32 = 1 << 1;
            const PH_FLAG_EXEC: u32 = 1 << 0;

            if is_64bit {
                // text segment
                let virtual_addr = virtual_base + entry as u64;
                let ph = Elf64ProgramHeader {
                    program_type: ElfProgramType::Load,
                    offset: main_offset as u64,
                    virtual_addr,
                    physical_addr: entry as u64,
                    file_size: ts as u64,
                    memory_size: ts as u64,
                    flags: PH_FLAG_READ | PH_FLAG_EXEC,
                    align: 4 * 1024,
                };
                program_headers.push(ElfProgramHeader::Elf64(ph));

                // data segment
                let offset = (main_offset + ts) as u64;
                let virtual_addr = virtual_base + data_load_addr as u64;
                let ph = Elf64ProgramHeader {
                    program_type: ElfProgramType::Load,
                    offset,
                    virtual_addr,
                    physical_addr: data_load_addr as u64,
                    file_size: ds as u64,
                    memory_size: ds as u64,
                    flags: PH_FLAG_READ | PH_FLAG_WRITE,
                    align: 4 * 1024,
                };
                program_headers.push(ElfProgramHeader::Elf64(ph));

                // retain original symbol table
                let offset = offset + ds as u64;
                let ph = Elf64ProgramHeader {
                    program_type: ElfProgramType::Null,
                    offset,
                    virtual_addr: 0,
                    physical_addr: 0,
                    file_size: ss as u64,
                    memory_size: ss as u64,
                    flags: PH_FLAG_READ,
                    align: 4,
                };
                program_headers.push(ElfProgramHeader::Elf64(ph));
            } else {
                // text segment
                let ph = Elf32ProgramHeader {
                    program_type: ElfProgramType::Load,
                    offset: main_offset,
                    virtual_addr: virtual_base as u32 + entry,
                    physical_addr: entry,
                    file_size: ts,
                    memory_size: ts,
                    flags: PH_FLAG_READ | PH_FLAG_EXEC,
                    align: 4 * 1024,
                };
                program_headers.push(ElfProgramHeader::Elf32(ph));

                // data segment
                let offset = main_offset + ts;
                let ph = Elf32ProgramHeader {
                    program_type: ElfProgramType::Load,
                    offset,
                    virtual_addr: virtual_base as u32 + data_load_addr,
                    physical_addr: data_load_addr,
                    file_size: ds,
                    memory_size: ds,
                    flags: PH_FLAG_READ | PH_FLAG_WRITE,
                    align: 4 * 1024,
                };
                program_headers.push(ElfProgramHeader::Elf32(ph));

                // retain original symbol table
                let offset = offset + ds;
                let ph = Elf32ProgramHeader {
                    program_type: ElfProgramType::Null,
                    offset,
                    virtual_addr: 0,
                    physical_addr: 0,
                    file_size: ss,
                    memory_size: ss,
                    flags: PH_FLAG_READ,
                    align: 4,
                };
                program_headers.push(ElfProgramHeader::Elf32(ph));
            }

            program_headers
        };

        let sym_table_data = &d[s_offset..s_offset + ss as usize];
        let syms = parse_aout_symbols(sym_table_data, false);
        let (elf_sym_tab, sym_str_tab) = aout_syms_to_elf(syms, is_64bit);

        // section header string table
        let sh_str_tab = {
            let f = [0u8].as_bytes();
            let te = c".text".to_bytes_with_nul();
            let da = c".data".to_bytes_with_nul();
            let sy = c".symtab".to_bytes_with_nul();
            let st = c".strtab".to_bytes_with_nul();
            let sh = c".shstrtab".to_bytes_with_nul();
            [f, te, da, sy, st, sh].concat()
        };

        let elf_sym_tab_entry_size = if is_64bit {
            ELF64_SYMBOL_TABLE_ENTRY_SIZE
        } else {
            ELF32_SYMBOL_TABLE_ENTRY_SIZE
        };

        // https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html#sh_flags
        let section_headers = {
            const SH_FLAG_WRITE: u32 = 1 << 0;
            const SH_FLAG_ALLOC: u32 = 1 << 1;
            const SH_FLAG_EXEC: u32 = 1 << 2;

            let mut section_headers: Vec<ElfSectionHeader> = vec![];

            if is_64bit {
                // NOTE: empty section, necessary for symbol resolution to work
                let sh = Elf64SectionHeader {
                    name: 0,
                    section_type: ElfSectionType::Null,
                    flags: 0,
                    addr: 0,
                    offset: 0,
                    size: 0,
                    link: 0,
                    info: 0,
                    addr_align: 0,
                    entry_size: 0,
                };
                section_headers.push(ElfSectionHeader::Elf64(sh));

                // --- text (code) and data

                // .text
                let offset = main_offset as u64;
                let sh = Elf64SectionHeader {
                    name: 1,
                    section_type: ElfSectionType::ProgBits,
                    flags: (SH_FLAG_ALLOC | SH_FLAG_EXEC) as u64,
                    addr: virtual_base as u64 + entry as u64,
                    offset,
                    size: ts as u64,
                    link: 1,
                    info: 0,
                    addr_align: 64,
                    entry_size: 0,
                };
                section_headers.push(ElfSectionHeader::Elf64(sh));
                // .data
                let offset = offset + ts as u64;
                let sh = Elf64SectionHeader {
                    name: 7,
                    section_type: ElfSectionType::ProgBits,
                    flags: (SH_FLAG_ALLOC | SH_FLAG_WRITE) as u64,
                    addr: virtual_base as u64 + data_load_addr as u64,
                    offset,
                    size: ds as u64,
                    link: 1,
                    info: 0,
                    addr_align: 32,
                    entry_size: 0,
                };
                section_headers.push(ElfSectionHeader::Elf64(sh));

                // --- symbols and strings

                // .symtab
                let elf_sym_tab_count = elf_sym_tab.len();
                let size = (elf_sym_tab_count * elf_sym_tab_entry_size) as u64;
                let offset = main_offset as u64 + data.len() as u64;
                let sh = Elf64SectionHeader {
                    name: 13,
                    section_type: ElfSectionType::SymbolTable,
                    flags: 0,
                    addr: 0,
                    offset,
                    size,
                    link: SYM_STRING_TABLE_INDEX,
                    info: elf_sym_tab_count as u32,
                    addr_align: 8,
                    entry_size: elf_sym_tab_entry_size as u64,
                };
                section_headers.push(ElfSectionHeader::Elf64(sh));

                // .strtab
                let offset = offset + size;
                let size = sym_str_tab.len() as u64;
                let sh = Elf64SectionHeader {
                    name: 21,
                    section_type: ElfSectionType::SymbolStringTable,
                    flags: 0,
                    addr: 0,
                    offset,
                    size,
                    link: 0,
                    info: 0,
                    addr_align: 1,
                    entry_size: 0,
                };
                section_headers.push(ElfSectionHeader::Elf64(sh));
                // .shstrtab
                let offset = offset + size;
                let size = sh_str_tab.len() as u64;
                let sh = Elf64SectionHeader {
                    name: 29,
                    section_type: ElfSectionType::SymbolStringTable,
                    flags: 0,
                    addr: 0,
                    offset,
                    size,
                    link: 0,
                    info: 0,
                    addr_align: 1,
                    entry_size: 0,
                };
                section_headers.push(ElfSectionHeader::Elf64(sh));
            } else {
                // NOTE: empty section, necessary for symbol resolution to work
                let sh = Elf32SectionHeader {
                    name: 0,
                    section_type: ElfSectionType::Null,
                    flags: 0,
                    addr: 0,
                    offset: 0,
                    size: 0,
                    link: 0,
                    info: 0,
                    addr_align: 0,
                    entry_size: 0,
                };
                section_headers.push(ElfSectionHeader::Elf32(sh));

                // --- text (code) and data

                // .text
                let offset = main_offset;
                let sh = Elf32SectionHeader {
                    name: 1,
                    section_type: ElfSectionType::ProgBits,
                    flags: SH_FLAG_ALLOC | SH_FLAG_EXEC,
                    addr: virtual_base as u32 + entry as u32,
                    offset,
                    size: ts,
                    link: 1,
                    info: 0,
                    addr_align: 64,
                    entry_size: 0,
                };
                section_headers.push(ElfSectionHeader::Elf32(sh));
                // .data
                let offset = offset + ts;
                let sh = Elf32SectionHeader {
                    name: 7,
                    section_type: ElfSectionType::ProgBits,
                    flags: SH_FLAG_ALLOC | SH_FLAG_WRITE,
                    addr: virtual_base as u32 + data_load_addr,
                    offset,
                    size: ds,
                    link: 1,
                    info: 0,
                    addr_align: 32,
                    entry_size: 0,
                };
                section_headers.push(ElfSectionHeader::Elf32(sh));

                // --- symbols and strings

                // .symtab
                let elf_sym_tab_count = elf_sym_tab.len() as u32;
                let size = elf_sym_tab_count * elf_sym_tab_entry_size as u32;
                let offset = main_offset + data.len() as u32;
                let sh = Elf32SectionHeader {
                    name: 13,
                    section_type: ElfSectionType::SymbolTable,
                    flags: 0,
                    addr: 0,
                    offset,
                    size,
                    link: SYM_STRING_TABLE_INDEX,
                    info: elf_sym_tab_count,
                    addr_align: 8,
                    entry_size: elf_sym_tab_entry_size as u32,
                };
                section_headers.push(ElfSectionHeader::Elf32(sh));

                // .strtab
                let offset = offset + size;
                let size = sym_str_tab.len() as u32;
                let sh = Elf32SectionHeader {
                    name: 21,
                    section_type: ElfSectionType::SymbolStringTable,
                    flags: 0,
                    addr: 0,
                    offset,
                    size,
                    link: 0,
                    info: 0,
                    addr_align: 1,
                    entry_size: 0,
                };
                section_headers.push(ElfSectionHeader::Elf32(sh));
                // .shstrtab
                let offset = offset + size;
                let size = sh_str_tab.len() as u32;
                let sh = Elf32SectionHeader {
                    name: 29,
                    section_type: ElfSectionType::SymbolStringTable,
                    flags: 0,
                    addr: 0,
                    offset,
                    size,
                    link: 0,
                    info: 0,
                    addr_align: 1,
                    entry_size: 0,
                };
                section_headers.push(ElfSectionHeader::Elf32(sh));
            }

            section_headers
        };

        // -------- assemble final ELF header and data slice

        let eh = ElfHeader::new(
            program_header_entry_count,
            section_header_entry_count,
            entry,
            machine_target,
        );
        let eb = eh.as_bytes();

        let mut phb = vec![0u8; 0];
        for ph in program_headers {
            let b = ph.as_bytes();
            phb.extend_from_slice(b);
        }
        let mut shb = vec![0u8; 0];
        for sh in section_headers {
            let b = sh.as_bytes();
            shb.extend_from_slice(b);
        }
        let pad = vec![0u8; PAD_SIZE];

        let mut stb = vec![0u8; 0];
        for s in elf_sym_tab {
            let b = s.as_bytes();
            stb.extend_from_slice(b);
        }

        Ok([eb, &phb, &shb, &pad, data, &stb, &sym_str_tab, &sh_str_tab].concat())
    } else {
        Err("Could not parse a.out".to_string())
    }
}

impl Display for AoutSymbol<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let t = self.get_type();
        let sym_type = match t {
            AoutSymbolType::Unknown => format!("{:02x?}", self.header.sym_type),
            _ => format!("{t:?}"),
        };
        let sym_name = self.name();
        let v = self.header.value;
        write!(f, "Symbol {v:08x}: {sym_type:20} {sym_name}")
    }
}

impl AoutSymbol<'_> {
    pub fn len(&self) -> usize {
        SYM_HEADER_SIZE + self.name().len() + 1
    }

    pub fn get_type(&self) -> AoutSymbolType {
        aout_symbol_type(self)
    }

    pub fn name(&self) -> String {
        self.name.to_string()
    }
}

const SYM_HEADER_SIZE: usize = 9;
// returns the symbol size
fn parse_sym(st: &[u8]) -> AoutSymbol {
    if let Ok((header, _)) = AoutSymbolHeader::read_from_prefix(st) {
        let max_len = 0x80.min(st.len() - SYM_HEADER_SIZE);
        let s = &st[SYM_HEADER_SIZE..SYM_HEADER_SIZE + max_len];
        let namex = CStr::from_bytes_until_nul(s).unwrap_or(c"");
        let name = namex.to_str().unwrap_or("[noname]");

        AoutSymbol { header, name }
    } else {
        panic!();
    }
}

fn parse_aout_symbols(st: &[u8], dump: bool) -> Vec<AoutSymbol> {
    let mut syms: Vec<AoutSymbol> = vec![];
    let mut offset = 0;

    while offset < st.len() {
        let sym = parse_sym(&st[offset..]);
        if dump {
            match sym.get_type() {
                AoutSymbolType::Unknown => {
                    let t = sym.header.sym_type;
                    let v = sym.header.value;
                    let h = format!("{t:02x?} {v:08x}");
                    println!(" {offset:08x}: Unknown symbol {h}");
                }
                _ => {
                    println!(" {offset:08x}: {sym}");
                }
            }
        }
        offset += sym.len();
        syms.push(sym);
    }

    syms
}

#[derive(Debug, Eq, PartialEq)]
enum MachineArch {
    Amd64,
    Riscv64,
    Unknown,
}

fn main() -> std::io::Result<()> {
    let cmd = Cli::parse().cmd;
    // Default to log level "info". Otherwise, you get no "regular" logs.
    let env = env_logger::Env::default().default_filter_or("info");
    env_logger::Builder::from_env(env).init();

    match cmd {
        Command::Convert { file_name } => {
            println!("File: {file_name}");
            let elf_file_name = format!("{file_name}.elf");

            let d = fs::read(file_name).unwrap();

            if let Ok(image) = aout_to_elf(&d) {
                let mut f = fs::File::create(elf_file_name)?;
                f.write_all(&image);
            }
        }
        Command::Parse {
            file_name,
            debug,
            verbose,
        } => {
            println!("File: {file_name}");
            let d = fs::read(file_name).unwrap();

            // TODO: parse Multiboot header, starting with magic 0x1BAD_B002

            if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&d) {
                println!("This is an ELF: {:#02x?}", &elf);
                return Ok(());
            }

            if let Ok((aout, _)) = Aout::read_from_prefix(&d) {
                let m = aout.magic;
                let arch = match m {
                    0x978a_0000 => MachineArch::Amd64,
                    0x178e_0000 => MachineArch::Riscv64,
                    _ => MachineArch::Unknown,
                };

                if arch == MachineArch::Unknown {
                    println!("a.out not recognized or unsupported architecture: {m:08x}");
                    return Ok(());
                }

                println!("Architecture: {arch:?}");

                let ts: u32 = aout.text_size.into();
                let ds: u32 = aout.data_size.into();
                let sts: u32 = aout.symbol_table_size.into();
                let ep: u32 = aout.entry_point.into();

                println!("Entry point:  {ep:08x}");
                println!();

                // The sections are in a fixed order:
                // - text (code)
                // - data
                // - symbols
                // - bss?
                let t_offset = AOUT_HEADER_SIZE + PAD_EXTRA_SIZE;
                let d_offset = t_offset + ts as usize;
                let st_offset = d_offset + ds as usize;

                let x = if debug {
                    let pd = &d[t_offset..t_offset + 16];
                    format!(" {pd:02x?}")
                } else {
                    "".to_string()
                };
                println!("Code:    {ts:08x} bytes @ {t_offset:08x}{x}");

                let x = if debug {
                    let dd = &d[d_offset..d_offset + 16];
                    format!(" {dd:02x?}")
                } else {
                    "".to_string()
                };
                println!("Data:    {ds:08x} bytes @ {d_offset:08x}{x}");

                let x = if debug {
                    let std = &d[st_offset..st_offset + 16];
                    format!(" {std:02x?}")
                } else {
                    "".to_string()
                };
                println!("Symbols: {sts:08x} bytes @ {st_offset:08x}{x}");

                println!();
                let sym_table_data = &d[st_offset..st_offset + sts as usize];
                let syms = parse_aout_symbols(sym_table_data, verbose);
                println!("{} symbols read", syms.len());
            }
        }
    }

    Ok(())
}
