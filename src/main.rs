#![allow(unused)]
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

// https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
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

const AOUT_HEADER_SIZE: usize = std::mem::size_of::<Aout>();

const ELF_HEADER_SIZE: usize = std::mem::size_of::<ElfHeader>();

const ELF_PROGRAM_HEADER_SIZE: usize = std::mem::size_of::<ElfProgramHeader>();

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

// TODO: Something with the memory sizes is strange.
fn aout_to_elf(d: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok((aout, _)) = Aout::read_from_prefix(d) {
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
            entry: aout.entry_point.into(),
            program_header_offset: ELF_HEADER_SIZE as u32,
            section_header_offset: 0x00,
            flags: 0x00,
            elf_header_size: ELF_HEADER_SIZE as u16,
            program_header_entry_size: ELF_PROGRAM_HEADER_SIZE as u16,
            program_header_entry_count: 3,
            section_header_entry_size: 0,
            section_header_entry_count: 0,
            section_header_index_entry: 0,
        };
        let eb = elf.as_bytes().to_vec();

        let ts: u32 = aout.text_size.into();
        let ds: u32 = aout.data_size.into();
        let ss: u32 = aout.symbol_table_size.into();

        let virtual_base = 0x8000_0000;
        let text_base = 0x0011_0000;
        let data_base = text_base + align_4k(ts);

        // text section
        let offset = (ELF_HEADER_SIZE + 3 * ELF_PROGRAM_HEADER_SIZE + PAD_SIZE) as u32;
        let p_text = ElfProgramHeader {
            program_type: 1,
            offset,
            virtual_addr: virtual_base + text_base,
            physical_addr: text_base,
            file_size: ts,
            memory_size: ts,
            flags: (1 << 2) | 1,
            align: 4 * 1024,
        };
        let p_text_b = p_text.as_bytes().to_vec();

        // data section
        let offset = offset + ts;
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
        let p_data_b = p_data.as_bytes().to_vec();

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
        let p_st_b = p_st.as_bytes().to_vec();

        let pad = vec![0u8; PAD_SIZE];

        let data = &d[AOUT_HEADER_SIZE + PAD_EXTRA_SIZE..];

        // TODO: parse Multiboot header, starting with magic 0x1BAD_B002

        Ok([&eb, &p_text_b, &p_data_b, &p_st_b, &pad, data].concat())
    } else {
        Err("Could not parse a.out".to_string())
    }
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
        Command::Parse { file_name } => {
            println!("File: {file_name}");
            let d = fs::read(file_name).unwrap();

            if let Ok(goblin::Object::Elf(elf)) = goblin::Object::parse(&d) {
                println!("elf: {:#?}", &elf);
                return Ok(());
            }

            if let Ok((aout, _)) = Aout::read_from_prefix(&d) {
                let arch = match aout.magic {
                    0x978a_0000 => "amd64",
                    _ => "unknown",
                };
                println!("Architecture: {arch}");

                let ts = aout.text_size;
                println!("Text size: {ts:08x}");

                println!("{aout:#010x?}");

                let ep: u32 = aout.entry_point.into();
                let ep = ep as usize;

                let epd = &d[ep..ep + 16];
                println!("Entry: {epd:02x?}");
            }
        }
    }

    Ok(())
}
