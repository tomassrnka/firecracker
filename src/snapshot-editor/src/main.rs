// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};

mod edit_memory;
#[cfg(target_arch = "aarch64")]
mod edit_vmstate;
mod info;
mod tsc;
mod utils;

use edit_memory::{edit_memory_command, EditMemoryError, EditMemorySubCommand};
#[cfg(target_arch = "aarch64")]
use edit_vmstate::{edit_vmstate_command, EditVmStateError, EditVmStateSubCommand};
use info::{info_vmstate_command, InfoVmStateError, InfoVmStateSubCommand};
use tsc::{tsc_command, TscCommandError, TscSubCommand};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum SnapEditorError {
    /// Error during editing memory file: {0}
    EditMemory(#[from] EditMemoryError),
    /// Error during editing vmstate file: {0}
    #[cfg(target_arch = "aarch64")]
    EditVmState(#[from] EditVmStateError),
    /// Error during getting info from a vmstate file: {0}
    InfoVmState(#[from] InfoVmStateError),
    /// Error during updating TSC metadata: {0}
    EditTsc(#[from] TscCommandError),
}

#[derive(Debug, Parser)]
#[command(version = format!("v{}", env!("CARGO_PKG_VERSION")))]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(subcommand)]
    EditMemory(EditMemorySubCommand),
    #[command(subcommand)]
    #[cfg(target_arch = "aarch64")]
    EditVmstate(EditVmStateSubCommand),
    #[command(subcommand)]
    InfoVmstate(InfoVmStateSubCommand),
    #[command(subcommand)]
    Tsc(TscSubCommand),
}

fn main_exec() -> Result<(), SnapEditorError> {
    let cli = Cli::parse();

    match cli.command {
        Command::EditMemory(command) => edit_memory_command(command)?,
        #[cfg(target_arch = "aarch64")]
        Command::EditVmstate(command) => edit_vmstate_command(command)?,
        Command::InfoVmstate(command) => info_vmstate_command(command)?,
        Command::Tsc(command) => tsc_command(command)?,
    }

    Ok(())
}

fn main() -> Result<(), SnapEditorError> {
    let result = main_exec();
    if let Err(e) = result {
        eprintln!("{}", e);
        Err(e)
    } else {
        Ok(())
    }
}
