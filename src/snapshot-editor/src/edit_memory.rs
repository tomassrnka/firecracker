// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
use std::slice;
use vmm::utils::u64_to_usize;
use vmm_sys_util::seek_hole::SeekHole;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EditMemoryError {
    /// Could not open memory file: {0}
    OpenMemoryFile(std::io::Error),
    /// Could not open diff file: {0}
    OpenDiffFile(std::io::Error),
    /// Failed to seek data in diff file: {0}
    SeekDataDiff(std::io::Error),
    /// Failed to seek hole in diff file: {0}
    SeekHoleDiff(std::io::Error),
    /// Failed to get metadata for diff file: {0}
    MetadataDiff(std::io::Error),
    /// Failed to seek in memory file: {0}
    SeekMemory(std::io::Error),
    /// Failed to send the file: {0}
    SendFile(std::io::Error),
    /// Failed to get metadata for memory file: {0}
    MetadataMemory(std::io::Error),
    /// Memory file is too large to map into the current address space
    MemoryFileTooLarge,
    /// Failed to map memory file: {0}
    MapMemory(std::io::Error),
    /// Failed to flush memory file: {0}
    FlushMemory(std::io::Error),
}

#[derive(Debug, Subcommand)]
pub enum EditMemorySubCommand {
    /// Apply a diff snapshot on top of a base one
    Rebase {
        /// Path to the memory file.
        #[arg(short, long)]
        memory_path: PathBuf,
        /// Path to the diff file.
        #[arg(short, long)]
        diff_path: PathBuf,
    },
    /// Sanitize XSAVE headers inside a Firecracker memory snapshot.
    ScrubXsave(ScrubXsaveArgs),
}

#[derive(Debug, Args)]
pub struct ScrubXsaveArgs {
    /// Path to the memory file.
    #[arg(short, long)]
    memory_path: PathBuf,
    /// Keep only the XSAVE features represented by this mask (accepts hex like 0x3).
    #[arg(short = 'k', long, default_value = "0x3", value_parser = parse_mask)]
    keep_mask: u64,
    /// Do not modify the file; only report what would change.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
    /// Print every sanitized header offset.
    #[arg(long, default_value_t = false)]
    verbose: bool,
}

pub fn edit_memory_command(command: EditMemorySubCommand) -> Result<(), EditMemoryError> {
    match command {
        EditMemorySubCommand::Rebase {
            memory_path,
            diff_path,
        } => rebase(memory_path, diff_path)?,
        EditMemorySubCommand::ScrubXsave(args) => scrub_xsave(args)?,
    }
    Ok(())
}

fn parse_mask(arg: &str) -> Result<u64, String> {
    if let Some(stripped) = arg.strip_prefix("0x").or(arg.strip_prefix("0X")) {
        u64::from_str_radix(stripped, 16).map_err(|e| e.to_string())
    } else {
        arg.parse().map_err(|e| e.to_string())
    }
}

fn rebase(memory_path: PathBuf, diff_path: PathBuf) -> Result<(), EditMemoryError> {
    let mut base_file = OpenOptions::new()
        .write(true)
        .open(memory_path)
        .map_err(EditMemoryError::OpenMemoryFile)?;

    let mut diff_file = OpenOptions::new()
        .read(true)
        .open(diff_path)
        .map_err(EditMemoryError::OpenDiffFile)?;

    let mut cursor: u64 = 0;
    while let Some(block_start) = diff_file
        .seek_data(cursor)
        .map_err(EditMemoryError::SeekDataDiff)?
    {
        cursor = block_start;
        let block_end = match diff_file
            .seek_hole(block_start)
            .map_err(EditMemoryError::SeekHoleDiff)?
        {
            Some(hole_start) => hole_start,
            None => diff_file
                .metadata()
                .map_err(EditMemoryError::MetadataDiff)?
                .len(),
        };

        while cursor < block_end {
            base_file
                .seek(SeekFrom::Start(cursor))
                .map_err(EditMemoryError::SeekMemory)?;

            // SAFETY: Safe because the parameters are valid.
            let num_transferred_bytes = unsafe {
                libc::sendfile64(
                    base_file.as_raw_fd(),
                    diff_file.as_raw_fd(),
                    (&mut cursor as *mut u64).cast::<i64>(),
                    u64_to_usize(block_end.saturating_sub(cursor)),
                )
            };
            if num_transferred_bytes < 0 {
                return Err(EditMemoryError::SendFile(std::io::Error::last_os_error()));
            }
        }
    }

    Ok(())
}

const LEGACY_AREA_SIZE: usize = 512;
const XSAVE_HEADER_SIZE: usize = 64;
const XSAVE_STRUCT_SIZE: usize = LEGACY_AREA_SIZE + XSAVE_HEADER_SIZE;
const XSAVE_ALIGNMENT: usize = 64;
const XCOMP_BV_COMPACTED_FORMAT: u64 = 1u64 << 63;

#[derive(Default, Debug)]
struct ScrubStats {
    scanned: usize,
    modified: usize,
}

fn scrub_xsave(args: ScrubXsaveArgs) -> Result<(), EditMemoryError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.memory_path)
        .map_err(EditMemoryError::OpenMemoryFile)?;

    let metadata = file.metadata().map_err(EditMemoryError::MetadataMemory)?;
    let len = metadata.len();
    let len_usize = usize::try_from(len).map_err(|_| EditMemoryError::MemoryFileTooLarge)?;

    if len_usize < XSAVE_STRUCT_SIZE {
        println!(
            "scrub-xsave: memory file {:?} is smaller than an XSAVE record; nothing to sanitize",
            args.memory_path
        );
        return Ok(());
    }

    let mut mapping = FileMapping::new(&file, len_usize)?;

    // SAFETY: The mapping spans the entire file with read/write permissions.
    let data = unsafe { mapping.as_mut_slice() };
    let stats = scrub_xsave_bytes(data, args.keep_mask, args.verbose, args.dry_run);

    println!(
        "scrub-xsave: keep_mask={:#x} scanned_headers={} sanitized={} dry_run={}",
        args.keep_mask, stats.scanned, stats.modified, args.dry_run
    );

    if !args.dry_run {
        mapping.flush()?;
    }

    Ok(())
}

fn scrub_xsave_bytes(
    buffer: &mut [u8],
    keep_mask: u64,
    verbose: bool,
    dry_run: bool,
) -> ScrubStats {
    let mut stats = ScrubStats::default();

    if buffer.len() < XSAVE_STRUCT_SIZE {
        return stats;
    }

    let mut offset = 0usize;
    let last_start = buffer.len() - XSAVE_STRUCT_SIZE;

    while offset <= last_start {
        let header_offset = offset + LEGACY_AREA_SIZE;
        let xfeatures = read_u64_le(&buffer[header_offset..header_offset + 8]);

        if !looks_like_xsave_header(xfeatures, keep_mask) {
            offset += XSAVE_ALIGNMENT;
            continue;
        }

        let xcomp_bv = read_u64_le(&buffer[header_offset + 8..header_offset + 16]);
        if !valid_xcomp(xfeatures, xcomp_bv) {
            offset += XSAVE_ALIGNMENT;
            continue;
        }

        stats.scanned += 1;

        let sanitized = xfeatures & keep_mask;
        if sanitized == xfeatures {
            offset += XSAVE_ALIGNMENT;
            continue;
        }

        if verbose {
            println!(
                "scrub-xsave: header @ 0x{:x} xfeatures={:#x} -> {:#x}",
                offset, xfeatures, sanitized
            );
        }

        if !dry_run {
            buffer[header_offset..header_offset + 8].copy_from_slice(&sanitized.to_le_bytes());
            let new_xcomp = if xcomp_bv & XCOMP_BV_COMPACTED_FORMAT != 0 {
                sanitized | XCOMP_BV_COMPACTED_FORMAT
            } else {
                sanitized
            };
            buffer[header_offset + 8..header_offset + 16].copy_from_slice(&new_xcomp.to_le_bytes());
        }

        stats.modified += 1;
        offset += XSAVE_ALIGNMENT;
    }

    stats
}

fn looks_like_xsave_header(xfeatures: u64, keep_mask: u64) -> bool {
    if xfeatures == 0 {
        return false;
    }

    // XSAVE always stores x87 + SSE.
    if xfeatures & 0x3 != 0x3 {
        return false;
    }

    if xfeatures & !keep_mask == 0 {
        return false;
    }

    // Reserved bits must be zero for the standard format.
    xfeatures & XCOMP_BV_COMPACTED_FORMAT == 0
}

fn valid_xcomp(xfeatures: u64, xcomp_bv: u64) -> bool {
    xcomp_bv == xfeatures || xcomp_bv == (xfeatures | XCOMP_BV_COMPACTED_FORMAT)
}

fn read_u64_le(bytes: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[0..8]);
    u64::from_le_bytes(arr)
}

struct FileMapping {
    ptr: *mut u8,
    len: usize,
}

impl FileMapping {
    fn new(file: &File, len: usize) -> Result<Self, EditMemoryError> {
        if len == 0 {
            return Ok(Self {
                ptr: std::ptr::null_mut(),
                len,
            });
        }

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(EditMemoryError::MapMemory(io::Error::last_os_error()));
        }

        Ok(Self {
            ptr: ptr.cast::<u8>(),
            len,
        })
    }

    unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        if self.len == 0 || self.ptr.is_null() {
            &mut []
        } else {
            slice::from_raw_parts_mut(self.ptr, self.len)
        }
    }

    fn flush(&self) -> Result<(), EditMemoryError> {
        if self.len == 0 || self.ptr.is_null() {
            return Ok(());
        }

        let ret = unsafe { libc::msync(self.ptr.cast(), self.len, libc::MS_SYNC) };
        if ret != 0 {
            return Err(EditMemoryError::FlushMemory(io::Error::last_os_error()));
        }

        Ok(())
    }
}

impl Drop for FileMapping {
    fn drop(&mut self) {
        if self.len == 0 || self.ptr.is_null() {
            return;
        }

        unsafe {
            libc::munmap(self.ptr.cast::<libc::c_void>(), self.len);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;

    use vmm_sys_util::{rand, tempfile};

    use super::*;

    fn check_file_content(file: &File, expected_content: &[u8]) {
        assert_eq!(
            file.metadata().unwrap().len(),
            expected_content.len() as u64
        );
        let mut buf = vec![0u8; expected_content.len()];
        file.read_exact_at(buf.as_mut_slice(), 0).unwrap();
        assert_eq!(&buf, expected_content);
    }

    #[test]
    fn test_scrub_xsave_rewrites_headers() {
        let mut buf = vec![0u8; super::XSAVE_STRUCT_SIZE * 2];
        let first_header = super::LEGACY_AREA_SIZE;
        let second_header = super::XSAVE_ALIGNMENT + super::LEGACY_AREA_SIZE;

        buf[first_header..first_header + 8].copy_from_slice(&0x7u64.to_le_bytes());
        buf[first_header + 8..first_header + 16].copy_from_slice(&0x7u64.to_le_bytes());

        buf[second_header..second_header + 8].copy_from_slice(&0xbu64.to_le_bytes());
        buf[second_header + 8..second_header + 16].copy_from_slice(&0xbu64.to_le_bytes());

        let stats = super::scrub_xsave_bytes(&mut buf, 0x3, false, false);
        assert_eq!(stats.modified, 2);
        assert_eq!(&buf[first_header..first_header + 8], &0x3u64.to_le_bytes());
        assert_eq!(
            &buf[second_header..second_header + 8],
            &0x3u64.to_le_bytes()
        );
    }

    #[test]
    fn test_scrub_xsave_dry_run() {
        let mut buf = vec![0u8; super::XSAVE_STRUCT_SIZE];
        let header = super::LEGACY_AREA_SIZE;
        buf[header..header + 8].copy_from_slice(&0x7u64.to_le_bytes());
        buf[header + 8..header + 16].copy_from_slice(&0x7u64.to_le_bytes());

        let stats = super::scrub_xsave_bytes(&mut buf, 0x3, false, true);
        assert_eq!(stats.modified, 1);
        assert_eq!(
            &buf[header..header + 8],
            &0x7u64.to_le_bytes(),
            "dry-run must not mutate buffer"
        );
    }

    #[test]
    fn test_rebase_empty_files() {
        let base = tempfile::TempFile::new().unwrap();
        let diff = tempfile::TempFile::new().unwrap();

        let base_file = base.as_file();

        let base_path = base.as_path().to_path_buf();
        let diff_path = diff.as_path().to_path_buf();

        // Empty files
        rebase(base_path, diff_path).unwrap();
        assert_eq!(base_file.metadata().unwrap().len(), 0);
    }

    #[test]
    fn test_rebase_empty_diff() {
        let base = tempfile::TempFile::new().unwrap();
        let diff = tempfile::TempFile::new().unwrap();

        let mut base_file = base.as_file();
        let diff_file = diff.as_file();

        let base_path = base.as_path().to_path_buf();
        let diff_path = diff.as_path().to_path_buf();

        let initial_base_file_content = rand::rand_bytes(50000);
        base_file.write_all(&initial_base_file_content).unwrap();

        // Diff file that has only holes
        diff_file
            .set_len(initial_base_file_content.len() as u64)
            .unwrap();
        rebase(base_path, diff_path).unwrap();
        check_file_content(base_file, &initial_base_file_content);
    }

    #[test]
    fn test_rebase_full_diff() {
        let base = tempfile::TempFile::new().unwrap();
        let diff = tempfile::TempFile::new().unwrap();

        let base_file = base.as_file();
        let mut diff_file = diff.as_file();

        let base_path = base.as_path().to_path_buf();
        let diff_path = diff.as_path().to_path_buf();

        // Diff file that has only data
        let diff_data = rand::rand_bytes(50000);
        diff_file.write_all(&diff_data).unwrap();
        rebase(base_path, diff_path).unwrap();
        check_file_content(base_file, &diff_data);
    }

    #[test]
    fn test_rebase() {
        // The filesystem punches holes only for blocks >= 4096.
        // It doesn't make sense to test for smaller ones.
        let block_sizes: &[usize] = &[4096, 8192];
        for &block_size in block_sizes {
            let mut expected_result = vec![];

            let base = tempfile::TempFile::new().unwrap();
            let diff = tempfile::TempFile::new().unwrap();

            let mut base_file = base.as_file();
            let mut diff_file = diff.as_file();

            let base_path = base.as_path().to_path_buf();
            let diff_path = diff.as_path().to_path_buf();

            // 1. Populated block both in base and diff file
            // block:     [ ]
            // diff:      [ ]
            // expected:  [d]
            let base_block = rand::rand_bytes(block_size);
            base_file.write_all(&base_block).unwrap();
            let diff_block = rand::rand_bytes(block_size);
            diff_file.write_all(&diff_block).unwrap();
            expected_result.extend(diff_block);

            // 2. Populated block in base file, hole in diff file
            // block:     [ ] [ ]
            // diff:      [ ] ___
            // expected:  [d] [b]
            let base_block = rand::rand_bytes(block_size);
            base_file.write_all(&base_block).unwrap();
            diff_file
                .seek(SeekFrom::Current(i64::try_from(block_size).unwrap()))
                .unwrap();
            expected_result.extend(base_block);

            // 3. Populated block in base file, zeroes block in diff file
            // block:     [ ] [ ] [ ]
            // diff:      [ ] ___ [0]
            // expected:  [d] [b] [d]
            let base_block = rand::rand_bytes(block_size);
            base_file.write_all(&base_block).unwrap();
            let diff_block = vec![0u8; block_size];
            diff_file.write_all(&diff_block).unwrap();
            expected_result.extend(diff_block);

            // Rebase and check the result
            rebase(base_path.clone(), diff_path.clone()).unwrap();
            check_file_content(base_file, &expected_result);

            // 4. The diff file is bigger
            // block:     [ ] [ ] [ ]
            // diff:      [ ] ___ [0] [ ]
            // expected:  [d] [b] [d] [d]
            let diff_block = rand::rand_bytes(block_size);
            diff_file.write_all(&diff_block).unwrap();
            expected_result.extend(diff_block);
            // Rebase and check the result
            rebase(base_path.clone(), diff_path.clone()).unwrap();
            check_file_content(base_file, &expected_result);

            // 5. The base file is bigger
            // block:     [ ] [ ] [ ] [ ] [ ]
            // diff:      [ ] ___ [0] [ ]
            // expected:  [d] [b] [d] [d] [b]
            let base_block = rand::rand_bytes(block_size);
            // Adding to the base file 2 times because
            // it is 1 block smaller then diff right now.
            base_file.write_all(&base_block).unwrap();
            base_file.write_all(&base_block).unwrap();
            expected_result.extend(base_block);
            // Rebase and check the result
            rebase(base_path, diff_path).unwrap();
            check_file_content(base_file, &expected_result);
        }
    }
}
