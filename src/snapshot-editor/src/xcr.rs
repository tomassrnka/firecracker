// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, convert::TryInto, path::PathBuf};

use clap::{Args, Subcommand};

use crate::utils::{UtilsError, open_vmstate, save_vmstate};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum XcrCommandError {
    /// {0}
    Utils(#[from] UtilsError),
}

#[derive(Debug, Subcommand)]
pub enum XcrSubCommand {
    /// Remove MPX support from the saved extended register state.
    ClearMpx(ClearMpxArgs),
    /// Print the saved MSR indices for each vCPU.
    ListMsrs(ListMsrsArgs),
    /// Remove specific MSR entries from the saved vCPU state.
    RemoveMsrs(RemoveMsrsArgs),
    /// Restrict XSAVE components to the provided mask.
    ClearXsave(ClearXsaveArgs),
}

#[derive(Debug, Args)]
pub struct ClearMpxArgs {
    /// Path to the vmstate file to update.
    #[arg(long)]
    pub vmstate_path: PathBuf,
    /// Optional output path; defaults to overwriting the input file.
    #[arg(long)]
    pub output_path: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ListMsrsArgs {
    /// Path to the vmstate file to inspect.
    #[arg(long)]
    pub vmstate_path: PathBuf,
}

#[derive(Debug, Args)]
pub struct RemoveMsrsArgs {
    /// Path to the vmstate file to update.
    #[arg(long)]
    pub vmstate_path: PathBuf,
    /// Optional output path; defaults to overwriting the input file.
    #[arg(long)]
    pub output_path: Option<PathBuf>,
    /// MSR indices (decimal or 0x-prefixed hex) to remove.
    #[arg(long, value_parser = parse_msr, num_args = 1.., value_delimiter = ',')]
    pub msr: Vec<u32>,
}

#[derive(Debug, Args)]
pub struct ClearXsaveArgs {
    /// Path to the vmstate file to update.
    #[arg(long)]
    pub vmstate_path: PathBuf,
    /// Optional output path; defaults to overwriting the input file.
    #[arg(long)]
    pub output_path: Option<PathBuf>,
    /// Bitmask of XSAVE components to retain (defaults to x87|SSE).
    #[arg(long, value_parser = parse_mask)]
    pub keep_mask: Option<u64>,
}

const MPX_FEATURE_MASK: u64 = (1 << 3) | (1 << 4);
const XSTATE_BV_OFFSET: usize = 512;
const XCOMP_BV_OFFSET: usize = 520;
const BNDREGS_OFFSET: usize = 832;
const BNDREGS_SIZE: usize = 256;
const BNDCSR_OFFSET: usize = 1088;
const BNDCSR_SIZE: usize = 64;
const IA32_BNDCFGS_MSR: u32 = 0x0000_0D90;

pub fn xcr_command(command: XcrSubCommand) -> Result<(), XcrCommandError> {
    match command {
        XcrSubCommand::ClearMpx(args) => clear_mpx(args),
        XcrSubCommand::ListMsrs(args) => list_msrs(args),
        XcrSubCommand::RemoveMsrs(args) => remove_msrs(args),
        XcrSubCommand::ClearXsave(args) => clear_xsave(args),
    }
}

fn clear_mpx(args: ClearMpxArgs) -> Result<(), XcrCommandError> {
    let output_path = args
        .output_path
        .clone()
        .unwrap_or(args.vmstate_path.clone());

    let (mut microvm_state, version) = open_vmstate(&args.vmstate_path)?;
    for vcpu in &mut microvm_state.vcpu_states {
        clear_mpx_for_vcpu(vcpu);
    }
    save_vmstate(microvm_state, &output_path, version)?;
    Ok(())
}

fn remove_msrs(args: RemoveMsrsArgs) -> Result<(), XcrCommandError> {
    use vmm_sys_util::fam::FamStruct;

    let output_path = args
        .output_path
        .clone()
        .unwrap_or(args.vmstate_path.clone());
    let targets: HashSet<u32> = args.msr.iter().copied().collect();

    let (mut microvm_state, version) = open_vmstate(&args.vmstate_path)?;
    for vcpu in &mut microvm_state.vcpu_states {
        for msr_chunk in &mut vcpu.saved_msrs {
            let entries = msr_chunk.as_mut_slice();
            let mut write_idx = 0;
            for idx in 0..entries.len() {
                if !targets.contains(&entries[idx].index) {
                    if write_idx != idx {
                        entries[write_idx] = entries[idx];
                    }
                    write_idx += 1;
                }
            }
            unsafe {
                msr_chunk.as_mut_fam_struct().nmsrs = write_idx as u32;
            }
        }
        vcpu.saved_msrs
            .retain(|chunk| chunk.as_fam_struct_ref().nmsrs != 0);
    }

    save_vmstate(microvm_state, &output_path, version)?;
    Ok(())
}

fn list_msrs(args: ListMsrsArgs) -> Result<(), XcrCommandError> {
    use vmm_sys_util::fam::FamStruct;

    let (microvm_state, _) = open_vmstate(&args.vmstate_path)?;

    for (idx, vcpu) in microvm_state.vcpu_states.iter().enumerate() {
        let mut indices = Vec::new();
        for chunk in &vcpu.saved_msrs {
            indices.extend(chunk.as_slice().iter().map(|entry| entry.index));
        }
        indices.sort_unstable();
        indices.dedup();
        println!("vCPU {idx}: {} MSR entries", indices.len());
        if !indices.is_empty() {
            for entry in indices.iter() {
                println!("  0x{entry:08x}");
            }
        }
    }

    Ok(())
}

fn clear_xsave(args: ClearXsaveArgs) -> Result<(), XcrCommandError> {
    let output_path = args
        .output_path
        .clone()
        .unwrap_or(args.vmstate_path.clone());
    let keep_mask = args.keep_mask.unwrap_or(0x3);

    let (mut microvm_state, version) = open_vmstate(&args.vmstate_path)?;
    for vcpu in &mut microvm_state.vcpu_states {
        restrict_xsave_for_vcpu(vcpu, keep_mask);
    }
    save_vmstate(microvm_state, &output_path, version)?;
    Ok(())
}

fn clear_mpx_for_vcpu(vcpu: &mut vmm::arch::x86_64::vcpu::VcpuState) {
    use vmm_sys_util::fam::FamStruct;

    for xcr in vcpu.xcrs.xcrs.iter_mut().take(vcpu.xcrs.nr_xcrs as usize) {
        if xcr.xcr == 0 {
            xcr.value &= !MPX_FEATURE_MASK;
        }
    }

    let xsave = unsafe { vcpu.xsave.as_mut_fam_struct() };
    let region_u32 = &mut xsave.xsave.region;
    let region_bytes = unsafe {
        std::slice::from_raw_parts_mut(
            region_u32.as_mut_ptr() as *mut u8,
            region_u32.len() * std::mem::size_of::<u32>(),
        )
    };

    mask_header_bits(region_bytes, !MPX_FEATURE_MASK);
    zero_mpx_payload(region_bytes);
    clear_mpx_msrs(vcpu);
}

fn mask_header_bits(region_bytes: &mut [u8], mask: u64) {
    if region_bytes.len() < XCOMP_BV_OFFSET + 8 {
        return;
    }

    let mut xstate_bv = u64::from_le_bytes(
        region_bytes[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    xstate_bv &= mask;
    region_bytes[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8].copy_from_slice(&xstate_bv.to_le_bytes());

    let mut xcomp_bv = u64::from_le_bytes(
        region_bytes[XCOMP_BV_OFFSET..XCOMP_BV_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    xcomp_bv &= mask;
    region_bytes[XCOMP_BV_OFFSET..XCOMP_BV_OFFSET + 8].copy_from_slice(&xcomp_bv.to_le_bytes());
}

fn zero_mpx_payload(region_bytes: &mut [u8]) {
    if region_bytes.len() >= BNDREGS_OFFSET + BNDREGS_SIZE {
        region_bytes[BNDREGS_OFFSET..BNDREGS_OFFSET + BNDREGS_SIZE].fill(0);
    }
    if region_bytes.len() >= BNDCSR_OFFSET + BNDCSR_SIZE {
        region_bytes[BNDCSR_OFFSET..BNDCSR_OFFSET + BNDCSR_SIZE].fill(0);
    }
}

fn clear_mpx_msrs(vcpu: &mut vmm::arch::x86_64::vcpu::VcpuState) {
    use kvm_bindings::kvm_msr_entry;
    use vmm_sys_util::fam::FamStruct;

    for msr_chunk in &mut vcpu.saved_msrs {
        let entries: &mut [kvm_msr_entry] = msr_chunk.as_mut_slice();
        let mut write_idx = 0;
        for idx in 0..entries.len() {
            if entries[idx].index != IA32_BNDCFGS_MSR {
                if write_idx != idx {
                    entries[write_idx] = entries[idx];
                }
                write_idx += 1;
            }
        }
        unsafe {
            msr_chunk.as_mut_fam_struct().nmsrs = write_idx as u32;
        }
    }

    vcpu.saved_msrs
        .retain(|chunk| chunk.as_fam_struct_ref().nmsrs != 0);
}

fn restrict_xsave_for_vcpu(vcpu: &mut vmm::arch::x86_64::vcpu::VcpuState, keep_mask: u64) {
    use vmm_sys_util::fam::FamStruct;

    for xcr in vcpu.xcrs.xcrs.iter_mut().take(vcpu.xcrs.nr_xcrs as usize) {
        if xcr.xcr == 0 {
            xcr.value &= keep_mask;
        }
    }

    let xsave = unsafe { vcpu.xsave.as_mut_fam_struct() };
    let region_u32 = &mut xsave.xsave.region;
    let region_bytes = unsafe {
        std::slice::from_raw_parts_mut(
            region_u32.as_mut_ptr() as *mut u8,
            region_u32.len() * std::mem::size_of::<u32>(),
        )
    };

    mask_header_bits(region_bytes, keep_mask);
    zero_extended_xsave(region_bytes);
}

fn zero_extended_xsave(region_bytes: &mut [u8]) {
    const LEGACY_AREA: usize = 512;
    if region_bytes.len() > LEGACY_AREA {
        region_bytes[LEGACY_AREA..].fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_bindings::{Msrs, kvm_msr_entry};
    use vmm::arch::x86_64::vcpu::VcpuState;

    fn build_test_vcpu() -> VcpuState {
        let mut vcpu = VcpuState::default();
        vcpu.xcrs.nr_xcrs = 1;
        vcpu.xcrs.xcrs[0].xcr = 0;
        vcpu.xcrs.xcrs[0].value = MPX_FEATURE_MASK | 0b11;

        let mut xsave = vcpu.xsave.as_mut_fam_struct();
        xsave.xsave.region[XSTATE_BV_OFFSET / 4] = MPX_FEATURE_MASK as u32 | 0b11;
        xsave.xsave.region[XSTATE_BV_OFFSET / 4 + 1] = (MPX_FEATURE_MASK >> 32) as u32;
        xsave.xsave.region[XCOMP_BV_OFFSET / 4] = MPX_FEATURE_MASK as u32;
        xsave.xsave.region[XCOMP_BV_OFFSET / 4 + 1] = (MPX_FEATURE_MASK >> 32) as u32;

        drop(xsave);

        let mut msrs = Msrs::new(1).unwrap();
        msrs.as_mut_slice()[0] = kvm_msr_entry {
            index: IA32_BNDCFGS_MSR,
            ..Default::default()
        };
        vcpu.saved_msrs.push(msrs);

        vcpu
    }

    #[test]
    fn test_clear_mpx_for_vcpu() {
        let mut vcpu = build_test_vcpu();

        clear_mpx_for_vcpu(&mut vcpu);

        assert_eq!(vcpu.xcrs.xcrs[0].value & MPX_FEATURE_MASK, 0);

        let xsave = vcpu.xsave.as_fam_struct_ref();
        let xstate_bv_lo = xsave.xsave.region[XSTATE_BV_OFFSET / 4];
        let xcomp_bv_lo = xsave.xsave.region[XCOMP_BV_OFFSET / 4];
        assert_eq!(xstate_bv_lo & MPX_FEATURE_MASK as u32, 0);
        assert_eq!(xcomp_bv_lo & MPX_FEATURE_MASK as u32, 0);

        let bytes = unsafe {
            std::slice::from_raw_parts(
                xsave.xsave.region.as_ptr() as *const u8,
                xsave.xsave.region.len() * std::mem::size_of::<u32>(),
            )
        };
        assert!(
            bytes[BNDREGS_OFFSET..BNDREGS_OFFSET + BNDREGS_SIZE]
                .iter()
                .all(|&b| b == 0)
        );
        assert!(
            bytes[BNDCSR_OFFSET..BNDCSR_OFFSET + BNDCSR_SIZE]
                .iter()
                .all(|&b| b == 0)
        );

        assert!(vcpu.saved_msrs.is_empty());
    }

    #[test]
    fn test_restrict_xsave_for_vcpu() {
        let mut vcpu = VcpuState::default();
        vcpu.xcrs.nr_xcrs = 1;
        vcpu.xcrs.xcrs[0].xcr = 0;
        vcpu.xcrs.xcrs[0].value = 0xff;

        {
            let mut xsave = vcpu.xsave.as_mut_fam_struct();
            xsave.xsave.region[XSTATE_BV_OFFSET / 4] = 0xff;
            xsave.xsave.region[XCOMP_BV_OFFSET / 4] = 0xff;
        }

        restrict_xsave_for_vcpu(&mut vcpu, 0x3);

        assert_eq!(vcpu.xcrs.xcrs[0].value, 0x3);
        let xsave = vcpu.xsave.as_fam_struct_ref();
        assert_eq!(xsave.xsave.region[XSTATE_BV_OFFSET / 4] & !0x3, 0);
        assert_eq!(xsave.xsave.region[XCOMP_BV_OFFSET / 4] & !0x3, 0);
    }
}

fn parse_msr(value: &str) -> Result<u32, String> {
    let trimmed = value.trim();
    if let Some(rest) = trimmed.strip_prefix("0x") {
        u32::from_str_radix(rest, 16).map_err(|e| e.to_string())
    } else if let Some(rest) = trimmed.strip_prefix("0X") {
        u32::from_str_radix(rest, 16).map_err(|e| e.to_string())
    } else {
        trimmed.parse::<u32>().map_err(|e| e.to_string())
    }
}

fn parse_mask(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    if let Some(rest) = trimmed.strip_prefix("0x") {
        u64::from_str_radix(rest, 16).map_err(|e| e.to_string())
    } else if let Some(rest) = trimmed.strip_prefix("0X") {
        u64::from_str_radix(rest, 16).map_err(|e| e.to_string())
    } else {
        trimmed.parse::<u64>().map_err(|e| e.to_string())
    }
}
