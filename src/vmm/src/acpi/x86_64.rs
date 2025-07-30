// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use acpi_tables::fadt::{
    IAPC_BOOT_ARG_FLAGS_MSI_NOT_PRESENT, IAPC_BOOT_ARG_FLAGS_PCI_ASPM,
    IAPC_BOOT_ARG_FLAGS_VGA_NOT_PRESENT,
};
use acpi_tables::madt::{IoAPIC, LocalAPIC};
use acpi_tables::{Fadt, aml};
use vm_memory::GuestAddress;
use zerocopy::IntoBytes;

use crate::arch::x86_64::layout;
use crate::device_manager::legacy::PortIODeviceManager;
use crate::vmm_config::machine_config::get_max_supported_vcpus;

#[inline(always)]
pub(crate) fn setup_interrupt_controllers(nr_vcpus: u8) -> Vec<u8> {
    let mut ic =
        Vec::with_capacity(size_of::<IoAPIC>() + (nr_vcpus as usize) * size_of::<LocalAPIC>());

    ic.extend_from_slice(IoAPIC::new(0, layout::IOAPIC_ADDR).as_bytes());
    for i in 0..nr_vcpus {
        ic.extend_from_slice(LocalAPIC::new(i).as_bytes());
    }
    ic
}

/// Setup interrupt controllers for CPU hotplug support
/// 
/// This function creates LocalAPIC entries for all possible CPUs (MAX_SUPPORTED_VCPUS)
/// and marks only the initially present ones as enabled. This allows the guest OS
/// to discover and hotplug additional CPUs dynamically.
#[inline(always)]
pub(crate) fn setup_interrupt_controllers_for_hotplug(nr_vcpus: u8) -> Vec<u8> {
    let max_vcpus = get_max_supported_vcpus();
    let mut ic = Vec::with_capacity(
        size_of::<IoAPIC>() + (max_vcpus as usize) * size_of::<LocalAPIC>()
    );

    // Add the I/O APIC
    ic.extend_from_slice(IoAPIC::new(0, layout::IOAPIC_ADDR).as_bytes());
    
    // Add LocalAPIC entries for all possible CPUs based on host CPU count
    let max_vcpus = get_max_supported_vcpus();
    for i in 0..max_vcpus {
        let enabled = i < nr_vcpus;
        ic.extend_from_slice(LocalAPIC::new_with_flags(i, enabled).as_bytes());
    }
    ic
}

#[inline(always)]
pub(crate) fn setup_arch_fadt(fadt: &mut Fadt) {
    // Let the guest kernel know that there is not VGA hardware present
    // neither do we support ASPM, or MSI type of interrupts.
    // More info here:
    // https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html?highlight=0a06#ia-pc-boot-architecture-flags
    fadt.setup_iapc_flags(
        (1 << IAPC_BOOT_ARG_FLAGS_VGA_NOT_PRESENT)
            | (1 << IAPC_BOOT_ARG_FLAGS_PCI_ASPM)
            | (1 << IAPC_BOOT_ARG_FLAGS_MSI_NOT_PRESENT),
    );
}

#[inline(always)]
pub(crate) fn setup_arch_dsdt(dsdt_data: &mut Vec<u8>, cpu_hotplug_enabled: bool) -> Result<(), aml::AmlError> {
    PortIODeviceManager::append_aml_bytes(dsdt_data)?;
    
    // Add CPU hotplug support only if enabled
    if cpu_hotplug_enabled {
        setup_cpu_hotplug_dsdt(dsdt_data)?;
    }
    
    Ok(())
}

/// Add CPU hotplug ACPI devices to the DSDT
fn setup_cpu_hotplug_dsdt(dsdt_data: &mut Vec<u8>) -> Result<(), aml::AmlError> {
    use aml::*;
    
    // First, create a CPU container device (required by Linux)
    Device::new(
        "_SB_.CPUS".try_into()?, // CPU container
        vec![
            &Name::new("_HID".try_into()?, &"ACPI0010")?, // CPU Container Device
            &Name::new("_CID".try_into()?, &"ACPI0010")?,
            &Name::new("_UID".try_into()?, &0u8)?,
            
            // Status - always present
            &Method::new(
                "_STA".try_into()?,
                0,
                false,
                vec![&Return::new(&0x0Fu8)],
            ),
        ],
    ).append_aml_bytes(dsdt_data)?;
    
    // Create individual processor devices for all possible CPUs based on host
    let max_vcpus = get_max_supported_vcpus();
    for cpu_id in 0..max_vcpus {
        // Create bindings for AML objects to ensure proper lifetimes
        let hid_name = Name::new("_HID".try_into()?, &"ACPI0007")?;
        let uid_name = Name::new("_UID".try_into()?, &(cpu_id as u32))?;
        let pxm_name = Name::new("_PXM".try_into()?, &0u8)?;
        
        let mat_buffer = create_cpu_mat_buffer(cpu_id);
        let mat_return = Return::new(&mat_buffer);
        let mat_method = Method::new(
            "_MAT".try_into()?,
            0,
            false,
            vec![&mat_return]
        );
        
        let sta_return = Return::new(&0x0Fu8);
        let sta_method = Method::new(
            "_STA".try_into()?,
            0,
            false,
            vec![&sta_return]
        );
        
        let ej0_return = Return::new(&0u8);
        let ej0_method = Method::new(
            "_EJ0".try_into()?,
            1,
            false,
            vec![&ej0_return]
        );
        
        // Create processor device
        Device::new(
            format!("_SB_.CPUS.C{:03}", cpu_id).as_str().try_into()?,
            vec![
                &hid_name,
                &uid_name,
                &mat_method,
                &sta_method,
                &pxm_name,
                &ej0_method,
            ],
        ).append_aml_bytes(dsdt_data)?;
    }
    
    Ok(())
}

/// Create MADT buffer for _MAT method
/// This returns a buffer containing a Local APIC MADT entry for the specified CPU
fn create_cpu_mat_buffer(cpu_id: u8) -> aml::Buffer {
    // Create a Local APIC MADT entry (8 bytes)
    // Format: [type, length, processor_id, apic_id, flags]
    let apic_entry = vec![
        0x00, // Type: Local APIC
        0x08, // Length: 8 bytes
        cpu_id, // Processor UID
        cpu_id, // APIC ID
        0x01, 0x00, 0x00, 0x00, // Flags: Enabled (bit 0 = 1)
    ];
    
    aml::Buffer::new(apic_entry)
}


pub(crate) const fn apic_addr() -> u32 {
    layout::APIC_ADDR
}

pub(crate) const fn rsdp_addr() -> GuestAddress {
    GuestAddress(layout::RSDP_ADDR)
}
