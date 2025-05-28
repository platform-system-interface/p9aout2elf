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

fn aout_to_elf(d: &[u8]) -> Result<Vec<u8>, String> {
    todo!()
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
