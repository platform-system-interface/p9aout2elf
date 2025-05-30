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

#[derive(FromBytes, Immutable, IntoBytes, Clone, Copy, Debug)]
#[repr(C, packed)]
struct ElfProgramHeader {
    program_type: u32,
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

// TODO: Something with the memory sizes is strange.
fn aout_to_elf(d: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok((aout, _)) = Aout::read_from_prefix(d) {
        let entry: u32 = aout.entry_point.into();

        // TODO: calculate
        let program_header_entry_count = 3;
        // TODO: calculate
        let section_header_entry_count = 3;

        let program_header_offset = ELF_HEADER_SIZE as u32;
        let section_header_offset =
            (ELF_HEADER_SIZE + program_header_entry_count * ELF_PROGRAM_HEADER_SIZE) as u32;

        let ts: u32 = aout.text_size.into();
        let ds: u32 = aout.data_size.into();
        let ss: u32 = aout.symbol_table_size.into();

        let virtual_base = 0x8000_0000;
        let text_base = 0x0011_0000;
        let data_base = text_base + align_4k(ts);

        let mut program_headers: Vec<ElfProgramHeader> = vec![];

        // text section
        let main_offset = (ELF_HEADER_SIZE
            + program_header_entry_count * ELF_PROGRAM_HEADER_SIZE
            + section_header_entry_count * ELF_SECTION_HEADER_SIZE
            + PAD_SIZE) as u32;
        let p_text = ElfProgramHeader {
            program_type: 1,
            offset: main_offset,
            virtual_addr: virtual_base + text_base,
            physical_addr: text_base,
            file_size: ts,
            memory_size: ts,
            flags: (1 << 2) | 1,
            align: 4 * 1024,
        };
        program_headers.push(p_text);

        // data section
        let offset = main_offset + ts;
        let p_data = ElfProgramHeader {
            program_type: 1,
            offset,
            virtual_addr: virtual_base + data_base,
            physical_addr: data_base,
            file_size: ds,
            // TODO: taken from fixture; why??
            memory_size: ds + 0x0007_47e8,
            flags: (1 << 2) | (1 << 1),
            align: 4 * 1024,
        };
        program_headers.push(p_data);

        // symbol table
        let offset = offset + ds;
        let p_st = ElfProgramHeader {
            program_type: 0,
            offset,
            virtual_addr: 0x0000_0000,  // TODO: ?
            physical_addr: 0x0000_0000, // TODO: ?
            file_size: ss,
            // TODO: ?!
            memory_size: ss - 0x0004_a172,
            flags: (1 << 2),
            align: 4,
        };
        program_headers.push(p_st);

        let mut section_headers: Vec<ElfSectionHeader> = vec![];

        let pad = vec![0u8; PAD_SIZE];
        let data = &d[AOUT_HEADER_SIZE + PAD_EXTRA_SIZE..];

        // symbol table
        let est = {
            let mut est: Vec<ElfSymbolTableEntry> = vec![];

            let e = ElfSymbolTableEntry {
                name: 23,
                value: 0x8011_0000,
                size: 20,
                info: 0x12, // global function
                other: 0,
                section_index: 2,
            };
            est.push(e);

            let e = ElfSymbolTableEntry {
                name: 26,
                value: 0x8011_000e,
                size: 10,
                info: 0x12, // global function
                other: 0,
                section_index: 2,
            };
            est.push(e);

            est
        };
        let est_b = est.as_bytes();

        let elf_sym_tab_size = (est.len() * ELF_SYMBOL_TABLE_ENTRY_SIZE) as u32;

        // string table
        let f = [0u8].as_bytes();
        let sy = c".symtab".to_bytes_with_nul();
        let st = c".strtab".to_bytes_with_nul();
        let da = c".text".to_bytes_with_nul();
        let a = c"AA".to_bytes_with_nul();
        let b = c"B".to_bytes_with_nul();

        // TODO
        let str_tab = [f, sy, st, da, a, b].concat();
        let elf_str_tab_size = str_tab.len() as u32;

        // section headers
        let offset = main_offset + data.len() as u32;
        let sh = ElfSectionHeader {
            name: 1,
            section_type: ElfSectionType::SymbolTable,
            flags: 0,
            addr: 0,
            offset,
            size: elf_sym_tab_size,
            link: 1,
            info: 0,
            addr_align: 0,
            entry_size: ELF_SYMBOL_TABLE_ENTRY_SIZE as u32,
        };
        section_headers.push(sh);

        let offset = offset + elf_sym_tab_size;
        let sh = ElfSectionHeader {
            name: 9,
            section_type: ElfSectionType::SymbolStringTable,
            flags: 0,
            addr: 0,
            offset,
            size: elf_str_tab_size,
            link: 0,
            info: 0,
            addr_align: 0,
            entry_size: 0,
        };
        section_headers.push(sh);

        let sh = ElfSectionHeader {
            name: 17,
            section_type: ElfSectionType::SymbolStringTable,
            flags: 0,
            addr: 0x8011_0000,
            offset: main_offset + entry,
            size: 0x1000,
            link: 0,
            info: 0,
            addr_align: 0,
            entry_size: 0,
        };
        section_headers.push(sh);

        let phb = program_headers.as_bytes();
        let shb = section_headers.as_bytes();

        // TODO: parse Multiboot header, starting with magic 0x1BAD_B002

        let elf = ElfHeader {
            magic: ELF_MAGIC,
            class: 1,      // 32-bit
            data: 1,       // little endian
            id_version: 1, // fixed
            os_abi: 0,
            abi_version: 0,
            _res: [0, 0, 0, 0, 0, 0, 0],
            elf_type: 0x2, // executable
            machine: aout_mach_to_elf(&aout),
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
            section_header_index_entry: 1,
        };
        let eb = elf.as_bytes();

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
