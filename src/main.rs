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
// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
#[derive(FromBytes, Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct ElfHeader {
    magic: [u8; 4],
    class: u8,
    data: u8,       // endianness
    id_version: u8, //
    os_abi: u8,
    abi_version: u8,
    _res: [u8; 7],
    elf_type: u16,
    machine: u16,
    version: u32,
    entry: u32,
    program_header_offset: u32,
    section_header_offset: u32,
    flags: u32,
    elf_header_size: u16,
    program_header_entry_size: u16,
    program_header_entry_count: u16,
    section_header_entry_size: u16,
    section_header_entry_count: u16,
    section_header_index_entry: u16,
}

impl ElfHeader {
    fn new(
        program_header_entry_count: u32,
        section_header_entry_count: u32,
        entry: u32,
        machine: u16,
    ) -> Self {
        let ph_size = program_header_entry_count * ELF_PROGRAM_HEADER_SIZE as u32;
        let program_header_offset = ELF_HEADER_SIZE as u32;
        let section_header_offset = program_header_offset + ph_size;
        // NOTE: Many things are hardcoded here.
        Self {
            magic: ELF_MAGIC,
            class: 1,      // 32-bit
            data: 1,       // little endian
            id_version: 1, // fixed
            os_abi: 0,
            abi_version: 0,
            _res: [0, 0, 0, 0, 0, 0, 0],
            elf_type: 0x2, // executable
            machine,
            version: 1,
            entry,
            program_header_offset,
            section_header_offset,
            flags: 0x00,
            elf_header_size: ELF_HEADER_SIZE as u16,
            program_header_entry_size: ELF_PROGRAM_HEADER_SIZE as u16,
            program_header_entry_count: program_header_entry_count as u16,
            section_header_entry_size: ELF_SECTION_HEADER_SIZE as u16,
            section_header_entry_count: section_header_entry_count as u16,
            // NOTE: This is just our convention now.
            section_header_index_entry: 1,
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

#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct ElfProgramHeader {
    program_type: ElfProgramType,
    offset: u32,
    virtual_addr: u32,
    physical_addr: u32,
    file_size: u32,
    memory_size: u32,
    flags: u32,
    align: u32,
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
struct ElfSectionHeader {
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

// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.symtab.html
#[derive(Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct ElfSymbolTableEntry {
    name: u32,
    value: u32,
    size: u32,
    info: u8,
    other: u8,
    section_index: u16,
}

// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.symtab.html
struct ElfSymbol {
    // x
}

const AOUT_HEADER_SIZE: usize = std::mem::size_of::<Aout>();

const ELF_HEADER_SIZE: usize = std::mem::size_of::<ElfHeader>();

const ELF_PROGRAM_HEADER_SIZE: usize = std::mem::size_of::<ElfProgramHeader>();

const ELF_SECTION_HEADER_SIZE: usize = std::mem::size_of::<ElfSectionHeader>();

const ELF_SYMBOL_TABLE_ENTRY_SIZE: usize = std::mem::size_of::<ElfSymbolTableEntry>();

// https://www.gnu.org/software/grub/manual/multiboot/multiboot.html
const MULTIBOOT_HEADER_SIZE: usize = 0x48;

// TODO: Multiboot struct

const PAD_BASIC_SIZE: usize = 4;
const PAD_EXTRA_SIZE: usize = 8;
const PAD_SIZE: usize = PAD_BASIC_SIZE + PAD_EXTRA_SIZE;

fn aout_mach_to_elf(aout: &Aout) -> u16 {
    let m = aout.magic;
    match m {
        0x978a_0000 => 0x3e, // AMD x64
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

const VIRTUAL_BASE: u32 = 0x8000_0000;

// TODO: Something with the memory sizes is strange.
fn aout_to_elf(d: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok((aout, _)) = Aout::read_from_prefix(d) {
        let entry: u32 = aout.entry_point.into();

        // TODO: calculate
        let program_header_entry_count = 4;
        // TODO: calculate
        let section_header_entry_count = 4;

        let ts: u32 = aout.text_size.into();
        let ds: u32 = aout.data_size.into();
        let ss: u32 = aout.symbol_table_size.into();

        // ----------- program headers
        let mut program_headers: Vec<ElfProgramHeader> = vec![];

        let ph = ElfProgramHeader {
            program_type: ElfProgramType::Null,
            offset: 0,
            virtual_addr: 0,
            physical_addr: 0,
            file_size: 0,
            memory_size: 0,
            flags: 0,
            align: 0,
        };
        program_headers.push(ph);

        const PH_FLAG_READ: u32 = 1 << 2;
        const PH_FLAG_WRITE: u32 = 1 << 1;
        const PH_FLAG_EXEC: u32 = 1 << 0;

        // text section
        let main_offset = (ELF_HEADER_SIZE
            + program_header_entry_count * ELF_PROGRAM_HEADER_SIZE
            + section_header_entry_count * ELF_SECTION_HEADER_SIZE
            + PAD_SIZE) as u32;

        let ph = ElfProgramHeader {
            program_type: ElfProgramType::Load,
            offset: main_offset,
            virtual_addr: VIRTUAL_BASE,
            physical_addr: 0,
            file_size: ts,
            memory_size: ts,
            flags: PH_FLAG_READ | PH_FLAG_EXEC,
            align: 4 * 1024,
        };
        program_headers.push(ph);

        // data section
        let offset = main_offset + ts;
        let load_offset = align_4k(ts);
        let ph = ElfProgramHeader {
            program_type: ElfProgramType::Load,
            offset,
            virtual_addr: VIRTUAL_BASE + load_offset,
            physical_addr: load_offset,
            file_size: ds,
            // TODO: taken from fixture; why??
            memory_size: ds + 0x0007_47e8,
            flags: PH_FLAG_READ | PH_FLAG_WRITE,
            align: 4 * 1024,
        };
        program_headers.push(ph);

        // symbol table
        let offset = offset + ds;
        let ph = ElfProgramHeader {
            program_type: ElfProgramType::Null,
            offset,
            virtual_addr: 0x0000_0000,  // TODO: ?
            physical_addr: 0x0000_0000, // TODO: ?
            file_size: ss,
            // TODO: ?!
            memory_size: ss - 0x0004_a172,
            flags: PH_FLAG_READ,
            align: 4,
        };
        program_headers.push(ph);

        // TODO: Do we need a .dynamic section?
        if false {
            let offset = offset + ds;
            let ph = ElfProgramHeader {
                program_type: ElfProgramType::Dynamic,
                offset,
                virtual_addr: 0,
                physical_addr: 0,
                file_size: 0,
                memory_size: 0,
                flags: PH_FLAG_READ,
                align: 4,
            };
            program_headers.push(ph);
        }

        let pad = vec![0u8; PAD_SIZE];
        let data = &d[AOUT_HEADER_SIZE + PAD_EXTRA_SIZE..];

        // https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-79797.html
        // > In executable and shared object files, st_value holds a virtual address.

        const SYM_LOCAL: u8 = 0 << 4;
        const SYM_GLOBAL: u8 = 1 << 4;

        // symbol table
        let elf_sym_tab = {
            let mut t: Vec<ElfSymbolTableEntry> = vec![];

            // first is the undefined symbol by convention
            let e = ElfSymbolTableEntry {
                name: 0,
                value: 0,
                size: 0,
                info: 0,
                other: 0,
                section_index: 0,
            };
            t.push(e);

            let e = ElfSymbolTableEntry {
                name: 29,
                value: 0x8011_0000,
                size: 24,
                info: SYM_LOCAL | 2, // global/function
                other: 0,
                section_index: 2,
            };
            t.push(e);

            let e = ElfSymbolTableEntry {
                name: 32,
                value: 0x8011_0018,
                size: 52,
                info: SYM_LOCAL | 2, // global/function
                other: 0,
                section_index: 2,
            };
            t.push(e);

            t
        };
        let est_b = elf_sym_tab.as_bytes();

        // string table
        // TODO
        let str_tab = {
            let f = [0u8].as_bytes();
            let sy = c".symtab".to_bytes_with_nul();
            let st = c".strtab".to_bytes_with_nul();
            let te = c".text".to_bytes_with_nul();
            let da = c".data".to_bytes_with_nul();
            let a = c"AA".to_bytes_with_nul();
            let b = c"B".to_bytes_with_nul();
            [f, sy, st, te, da, a, b].concat()
        };

        // https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.sheader.html#sh_flags
        const SH_FLAG_WRITE: u32 = 1 << 0;
        const SH_FLAG_ALLOC: u32 = 1 << 1;
        const SH_FLAG_EXEC: u32 = 1 << 2;

        // ----------- section headers
        let mut section_headers: Vec<ElfSectionHeader> = vec![];
        // .symtab
        let elf_sym_tab_count = elf_sym_tab.len() as u32;
        let size = elf_sym_tab_count * ELF_SYMBOL_TABLE_ENTRY_SIZE as u32;
        let offset = main_offset + data.len() as u32;
        let sh = ElfSectionHeader {
            name: 1,
            section_type: ElfSectionType::SymbolTable,
            flags: 0,
            addr: 0,
            offset,
            size,
            link: 1,                 // index of string table header
            info: elf_sym_tab_count, // apparently number of symbols
            addr_align: 8,
            entry_size: ELF_SYMBOL_TABLE_ENTRY_SIZE as u32,
        };
        section_headers.push(sh);
        // .strtab
        let offset = offset + size;
        let size = str_tab.len() as u32;
        let sh = ElfSectionHeader {
            name: 9,
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
        section_headers.push(sh);
        // .text
        let offset = main_offset + entry;
        let sh = ElfSectionHeader {
            name: 17,
            section_type: ElfSectionType::ProgBits,
            flags: SH_FLAG_ALLOC | SH_FLAG_EXEC,
            addr: entry,
            offset,
            size: ts - entry,
            link: 1,
            info: 0,
            addr_align: 64,
            entry_size: 0,
        };
        section_headers.push(sh);
        // .data
        let offset = main_offset + ts;
        let sh = ElfSectionHeader {
            name: 23,
            section_type: ElfSectionType::ProgBits,
            flags: SH_FLAG_ALLOC | SH_FLAG_WRITE,
            addr: load_offset,
            offset,
            size: ds,
            link: 1,
            info: 0,
            addr_align: 32,
            entry_size: 0,
        };
        section_headers.push(sh);

        let phb = program_headers.as_bytes();
        let shb = section_headers.as_bytes();

        // TODO: parse Multiboot header, starting with magic 0x1BAD_B002

        let eh = ElfHeader::new(
            program_header_entry_count as u32,
            section_header_entry_count as u32,
            entry,
            aout_mach_to_elf(&aout),
        );
        let eb = eh.as_bytes();

        Ok([eb, phb, shb, &pad, data, est_b, &str_tab].concat())
    } else {
        Err("Could not parse a.out".to_string())
    }
}

impl<'a> Display for AoutSymbol<'a> {
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

impl<'a> AoutSymbol<'a> {
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
        let namex = CStr::from_bytes_until_nul(s).unwrap();
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

            if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&d) {
                println!("This is an ELF: {:#02x?}", &elf);
                return Ok(());
            }

            if let Ok((aout, _)) = Aout::read_from_prefix(&d) {
                let arch = match aout.magic {
                    0x978a_0000 => "amd64",
                    _ => "unknown",
                };

                let ts: u32 = aout.text_size.into();
                let ds: u32 = aout.data_size.into();
                let sts: u32 = aout.symbol_table_size.into();
                let ep: u32 = aout.entry_point.into();

                // The sections are in a fixed order:
                // - text (code)
                // - data
                // - symbols
                // - bss?
                let t_offset = AOUT_HEADER_SIZE + PAD_EXTRA_SIZE;
                let e_offset = t_offset + ep as usize;
                let d_offset = t_offset + ts as usize;
                let st_offset = d_offset + ds as usize;

                let pd = &d[t_offset..t_offset + 16];
                let epd = &d[e_offset..e_offset + 16];
                let dd = &d[d_offset..d_offset + 16];
                let std = &d[st_offset..st_offset + 16];

                println!("Architecture: {arch}");

                println!("Code size: {ts:08x}");
                let x = if debug {
                    format!(" {pd:02x?}")
                } else {
                    "".to_string()
                };
                println!("Code start @ {t_offset:08x}{x}");
                let x = if debug {
                    format!(" {epd:02x?}")
                } else {
                    "".to_string()
                };
                println!("     Entry @ {ep:08x}{x}");

                println!("Data size: {ds:08x}");
                let x = if debug {
                    format!(" {dd:02x?}")
                } else {
                    "".to_string()
                };
                println!("      Data @ {d_offset:08x}{x}");

                println!("Symbol table size: {sts:08x}");
                let x = if debug {
                    format!(" {std:02x?}")
                } else {
                    "".to_string()
                };
                println!("Symbol table @ {st_offset:08x}{x}");

                let sym_table_data = &d[st_offset..st_offset + sts as usize];
                let syms = parse_aout_symbols(sym_table_data, verbose);
                println!("{} symbols found", syms.len());
            }
        }
    }

    Ok(())
}
