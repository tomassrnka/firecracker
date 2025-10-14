// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{convert::TryInto, path::PathBuf};

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

const MPX_FEATURE_MASK: u64 = (1 << 3) | (1 << 4);
const XSTATE_BV_OFFSET: usize = 512;
const XCOMP_BV_OFFSET: usize = 520;
const BNDREGS_OFFSET: usize = 832;
const BNDREGS_SIZE: usize = 256;
const BNDCSR_OFFSET: usize = 1088;
const BNDCSR_SIZE: usize = 64;

pub fn xcr_command(command: XcrSubCommand) -> Result<(), XcrCommandError> {
    match command {
        XcrSubCommand::ClearMpx(args) => clear_mpx(args),
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

fn clear_mpx_for_vcpu(vcpu: &mut vmm::arch::x86_64::vcpu::VcpuState) {
    use vmm_sys_util::fam::FamStruct;

    for xcr in vcpu.xcrs.xcrs.iter_mut().take(vcpu.xcrs.nr_xcrs as usize) {
        if xcr.xcr == 0 {
            xcr.value &= !MPX_FEATURE_MASK;
        }
    }

    let xsave = vcpu.xsave.as_mut_fam_struct();
    let region_u32 = &mut xsave.xsave.region;
    let region_bytes = unsafe {
        std::slice::from_raw_parts_mut(
            region_u32.as_mut_ptr() as *mut u8,
            region_u32.len() * std::mem::size_of::<u32>(),
        )
    };

    clear_header_bits(region_bytes);
    zero_mpx_payload(region_bytes);
}

fn clear_header_bits(region_bytes: &mut [u8]) {
    if region_bytes.len() < XCOMP_BV_OFFSET + 8 {
        return;
    }

    let mut xstate_bv = u64::from_le_bytes(
        region_bytes[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    xstate_bv &= !MPX_FEATURE_MASK;
    region_bytes[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8].copy_from_slice(&xstate_bv.to_le_bytes());

    let mut xcomp_bv = u64::from_le_bytes(
        region_bytes[XCOMP_BV_OFFSET..XCOMP_BV_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    xcomp_bv &= !MPX_FEATURE_MASK;
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

#[cfg(test)]
mod tests {
    use super::*;
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
    }
}
