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
struct Elf {
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

const AOUT_HEADER_SIZE: usize = 32;

const ELF_HEADER_SIZE: u32 = std::mem::size_of::<Elf>() as u32;

fn aout_mach_to_elf(aout: &Aout) -> u16 {
    let m = aout.magic;
    match m {
        0x978a_0000 => 0x3e, // AMD x64
        _ => todo!("Architecture not yet supported: {m:08x}"),
    }
}

fn aout_to_elf(d: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok((aout, _)) = Aout::read_from_prefix(d) {
        let elf = Elf {
            magic: [0x7f, b'E', b'L', b'F'],
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
            program_header_offset: ELF_HEADER_SIZE,
            section_header_offset: 0x00,
            flags: 0x00,
            elf_header_size: ELF_HEADER_SIZE as u16,
            program_header_entry_size: 32,
            program_header_entry_count: 3,
            section_header_entry_size: 0,
            section_header_entry_count: 0,
            section_header_index_entry: 0,
        };
        let b = elf.as_bytes().to_vec();

        let data = &d[AOUT_HEADER_SIZE..];

        Ok([&b, data].concat())
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
