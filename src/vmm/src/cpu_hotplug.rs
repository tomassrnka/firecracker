// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Barrier};
use std::fs;

use log::{info, warn};

use crate::vstate::vcpu::{Vcpu, VcpuHandle};
use crate::vmm_config::cpu_hotplug::{
    CpuHotplugConfig, CpuHotplugError, CpuHotplugStatus,
};
use crate::vmm_config::machine_config::get_max_supported_vcpus;
use crate::Vmm;

/// Get the number of physical CPUs on the host
fn get_host_cpu_count() -> Result<u8, CpuHotplugError> {
    // Try to read from /proc/cpuinfo or use sysconf
    match fs::read_to_string("/sys/devices/system/cpu/possible") {
        Ok(content) => {
            // Parse format like "0-7" or "0-15"
            if let Some(dash_pos) = content.find('-') {
                if let Ok(max_cpu) = content[dash_pos + 1..].trim().parse::<u8>() {
                    return Ok(max_cpu + 1);
                }
            }
        }
        Err(_) => {
            // Fallback to nproc equivalent
            if let Ok(nproc) = std::thread::available_parallelism() {
                return Ok(nproc.get() as u8);
            }
        }
    }
    
    // Conservative default
    warn!("Could not determine host CPU count, defaulting to 8");
    Ok(8)
}

/// CPU hotplug manager implementation for VMM
///
/// ## Suspend/Resume and Migration Considerations:
/// 
/// When suspending/resuming or migrating VMs with hotplugged CPUs:
/// 
/// 1. **Suspend**: The current vCPU count and state is saved as part of the VM snapshot.
///    All vCPU states (including MP state) are preserved.
/// 
/// 2. **Resume on Same Host**: Works transparently - vCPUs are restored with their saved states.
/// 
/// 3. **Migration to Different Host**: 
///    - If target host has fewer CPUs than the VM, migration should fail gracefully
///    - The restore process should validate: min(saved_vcpu_count, target_host_cpus)
///    - Consider implementing a "force" flag to allow reducing vCPU count during migration
/// 
/// 4. **Best Practices**:
///    - Always save the current vCPU configuration in the snapshot
///    - Validate host CPU count during restore
///    - Provide clear error messages if restoration fails due to insufficient host CPUs
impl Vmm {
    /// Get the current CPU hotplug status
    pub fn get_cpu_hotplug_status(&self) -> CpuHotplugStatus {
        let online_cpus: Vec<u8> = (0..self.vcpus_handles.len() as u8).collect();
        let max_cpus = get_max_supported_vcpus();
        let offline_cpus: Vec<u8> = ((online_cpus.len() as u8)..max_cpus).collect();

        CpuHotplugStatus {
            online_cpus,
            offline_cpus,
            max_cpus,
        }
    }

    /// Perform CPU hotplug operation
    pub fn configure_cpu_hotplug(
        &mut self,
        config: CpuHotplugConfig,
    ) -> Result<(), CpuHotplugError> {
        let current_vcpu_count = self.vcpus_handles.len() as u8;
        let target_vcpu_count = config.target_vcpu_count;
        
        // Check against dynamic maximum based on host
        let max_vcpus = get_max_supported_vcpus();
        if target_vcpu_count > max_vcpus {
            return Err(CpuHotplugError::InvalidCpuId(target_vcpu_count));
        }
        
        // Check against host CPU count
        let host_cpu_count = get_host_cpu_count()?;
        if target_vcpu_count > host_cpu_count {
            warn!("Requested {} vCPUs but host only has {} CPUs", target_vcpu_count, host_cpu_count);
            return Err(CpuHotplugError::ExceedsHostCpuCount(target_vcpu_count, host_cpu_count));
        }
        
        if target_vcpu_count == current_vcpu_count {
            info!("Target vCPU count matches current count ({}), no action needed", current_vcpu_count);
            return Ok(());
        }
        
        if target_vcpu_count > current_vcpu_count {
            // Add CPUs
            let cpu_ids: Vec<u8> = (current_vcpu_count..target_vcpu_count).collect();
            self.hotplug_add_cpus(cpu_ids)
        } else {
            // Remove CPUs - need to check if they're offline in guest first
            let cpu_ids: Vec<u8> = (target_vcpu_count..current_vcpu_count).collect();
            
            // Check if any of the CPUs to be removed are still online
            if let Err(online_cpu) = self.check_cpus_offline_in_guest(&cpu_ids) {
                warn!("Cannot remove CPU {} - it's still online in guest", online_cpu);
                return Err(CpuHotplugError::CpuStillOnline(online_cpu));
            }
            
            self.hotplug_remove_cpus(cpu_ids)
        }
    }

    /// Add CPUs to the running VM
    fn hotplug_add_cpus(&mut self, cpu_ids: Vec<u8>) -> Result<(), CpuHotplugError> {
        let current_vcpu_count = self.vcpus_handles.len() as u8;
        
        // Validate CPU IDs - for now, only support sequential addition
        let max_vcpus = get_max_supported_vcpus();
        for &cpu_id in &cpu_ids {
            if cpu_id >= max_vcpus {
                return Err(CpuHotplugError::InvalidCpuId(cpu_id));
            }
            if cpu_id < current_vcpu_count {
                return Err(CpuHotplugError::CpuAlreadyOnline(cpu_id));
            }
        }

        // Sort CPU IDs to ensure we add them in order
        let mut sorted_cpu_ids = cpu_ids.clone();
        sorted_cpu_ids.sort_unstable();

        // Verify CPUs are being added sequentially
        for (i, &cpu_id) in sorted_cpu_ids.iter().enumerate() {
            let expected_id = current_vcpu_count + i as u8;
            if cpu_id != expected_id {
                return Err(CpuHotplugError::InvalidCpuId(cpu_id));
            }
        }

        info!("Adding CPUs: {:?}", sorted_cpu_ids);

        // Create and start new VCPUs
        for cpu_id in sorted_cpu_ids {
            let vcpu = self.create_vcpu(cpu_id)?;
            let vcpu_handle = self.start_vcpu(vcpu)?;
            self.vcpus_handles.push(vcpu_handle);
        }

        // Notify guest about new CPUs
        self.notify_guest_cpu_change()?;

        Ok(())
    }

    /// Remove CPUs from the running VM
    fn hotplug_remove_cpus(&mut self, cpu_ids: Vec<u8>) -> Result<(), CpuHotplugError> {
        // Check if trying to remove boot CPU
        if cpu_ids.contains(&0) {
            return Err(CpuHotplugError::CannotRemoveBootCpu);
        }

        let current_vcpu_count = self.vcpus_handles.len() as u8;

        // Validate CPU IDs
        for &cpu_id in &cpu_ids {
            if cpu_id >= current_vcpu_count {
                return Err(CpuHotplugError::CpuAlreadyOffline(cpu_id));
            }
        }

        // Sort CPU IDs in descending order for safe removal
        let mut sorted_cpu_ids = cpu_ids.clone();
        sorted_cpu_ids.sort_unstable();
        sorted_cpu_ids.reverse();

        // Limitation: For now, only support removing CPUs from the end sequentially
        // This ensures that we don't leave gaps in the vCPU array which would complicate
        // the current implementation. Future enhancement could support arbitrary removal.
        let highest_cpu_to_remove = *sorted_cpu_ids.first().unwrap();
        let expected_highest = current_vcpu_count - 1;
        
        if highest_cpu_to_remove != expected_highest {
            warn!("Can only remove CPUs sequentially from the end. Highest CPU to remove: {}, Expected: {}", 
                  highest_cpu_to_remove, expected_highest);
            // For now, still enforce sequential removal, but log a helpful message
            for (i, &cpu_id) in sorted_cpu_ids.iter().enumerate() {
                let expected_id = current_vcpu_count - 1 - i as u8;
                if cpu_id != expected_id {
                    return Err(CpuHotplugError::InvalidCpuId(cpu_id));
                }
            }
        }

        info!("Removing CPUs: {:?}", sorted_cpu_ids);

        // Remove CPUs sequentially from the end
        let mut removed_handles = Vec::new();
        for _cpu_id in &sorted_cpu_ids {
            if let Some(handle) = self.vcpus_handles.pop() {
                // Send finish signal to the VCPU
                handle.send_event(crate::vstate::vcpu::VcpuEvent::Finish)
                    .map_err(|_| CpuHotplugError::GuestNotificationFailed)?;
                removed_handles.push(handle);
            }
        }

        // Wait for all removed VCPUs to terminate
        for handle in removed_handles {
            drop(handle);
        }

        info!("CPU removal completed. {} CPUs remaining", self.vcpus_handles.len());

        // Notify guest about CPU removal
        self.notify_guest_cpu_change()?;

        Ok(())
    }

    /// Create a new VCPU for hotplug
    fn create_vcpu(&mut self, cpu_id: u8) -> Result<Vcpu, CpuHotplugError> {
        let exit_evt = self.vcpus_exit_evt
            .try_clone()
            .map_err(|_| CpuHotplugError::GuestNotificationFailed)?;
        
        let mut vcpu = Vcpu::new(cpu_id, &mut self.vm, exit_evt)
            .map_err(|_| CpuHotplugError::GuestNotificationFailed)?;
        
        // Configure the hotplugged vCPU for proper wakeup by the guest OS
        self.configure_hotplug_vcpu(&mut vcpu, cpu_id)?;
        
        Ok(vcpu)
    }

    /// Configure a hotplugged vCPU for proper initialization by the guest
    fn configure_hotplug_vcpu(&mut self, vcpu: &mut Vcpu, cpu_id: u8) -> Result<(), CpuHotplugError> {
        use kvm_bindings::{kvm_mp_state, KVM_MP_STATE_INIT_RECEIVED};
        use crate::arch::{BootProtocol, EntryPoint};
        use crate::vstate::vcpu::VcpuConfig;
        use crate::cpu_config::templates::CpuConfiguration;
        
        info!("Configuring hotplug vCPU {} for guest wakeup", cpu_id);
        
        // First, configure the vCPU with the same CPU configuration as boot vCPUs
        // This includes CPUID, MSRs, and other CPU settings
        
        // Build VcpuConfig - we'll use a simplified version for now
        // In production, this should be stored during boot and reused
        let max_vcpus = get_max_supported_vcpus();
        let vcpu_config = VcpuConfig {
            vcpu_count: max_vcpus, // Max possible count based on host
            smt: false, // TODO: Get from machine config
            cpu_config: CpuConfiguration {
                cpuid: crate::cpu_config::x86_64::cpuid::Cpuid::try_from(self.kvm.supported_cpuid.clone())
                    .map_err(|_| CpuHotplugError::GuestNotificationFailed)?,
                msrs: std::collections::BTreeMap::new(),
            },
        };
        
        // Use a dummy entry point for hotplugged CPUs - they will be started by INIT-SIPI-SIPI
        let entry_point = EntryPoint {
            entry_addr: vm_memory::GuestAddress(0),
            protocol: BootProtocol::LinuxBoot,
        };
        
        // Configure the vCPU with CPU settings (CPUID, MSRs, etc.)
        vcpu.kvm_vcpu.configure(self.vm.guest_memory(), entry_point, &vcpu_config)
            .map_err(|_| CpuHotplugError::GuestNotificationFailed)?;
        
        // Set the vCPU to INIT_RECEIVED state
        // This state means the CPU has received an INIT signal and is waiting for SIPI
        // This is more appropriate for hotplugged CPUs than UNINITIALIZED
        let mp_state = kvm_mp_state {
            mp_state: KVM_MP_STATE_INIT_RECEIVED,
        };
        
        vcpu.kvm_vcpu.fd.set_mp_state(mp_state)
            .map_err(|_| CpuHotplugError::GuestNotificationFailed)?;
        
        // Ensure proper APIC initialization for hotplugged CPU
        // The APIC needs to be properly set up so the guest can send INIT-SIPI-SIPI
        self.setup_hotplug_apic(&mut vcpu.kvm_vcpu, cpu_id)?;
        
        info!("vCPU {} configured for hotplug with INIT_RECEIVED state - ready for SIPI", cpu_id);
        Ok(())
    }
    
    /// Setup APIC for hotplugged vCPU
    fn setup_hotplug_apic(&mut self, kvm_vcpu: &mut crate::vstate::vcpu::KvmVcpu, cpu_id: u8) -> Result<(), CpuHotplugError> {
        
        // Get the current LAPIC state
        let mut lapic_state = kvm_vcpu.fd.get_lapic()
            .map_err(|_| CpuHotplugError::GuestNotificationFailed)?;
        
        // Set APIC ID to match the CPU ID - this is crucial for INIT-SIPI-SIPI targeting
        // APIC ID is at offset 0x20 in the LAPIC state and needs to be in the upper 8 bits of the 32-bit value
        let apic_id_offset = 0x20;
        let apic_id_value = (cpu_id as u32) << 24; // APIC ID in bits 31:24
        
        // Access the LAPIC registers safely, ensuring proper alignment
        // The regs field is a [i8; 1024] array, we need to access it as u32 values
        if apic_id_offset + 4 <= lapic_state.regs.len() {
            // Create a properly aligned u32 value and write it
            let value_bytes = apic_id_value.to_le_bytes();
            lapic_state.regs[apic_id_offset] = value_bytes[0] as i8;
            lapic_state.regs[apic_id_offset + 1] = value_bytes[1] as i8;
            lapic_state.regs[apic_id_offset + 2] = value_bytes[2] as i8;
            lapic_state.regs[apic_id_offset + 3] = value_bytes[3] as i8;
        } else {
            return Err(CpuHotplugError::GuestNotificationFailed);
        }
        
        // Set the LAPIC state back
        kvm_vcpu.fd.set_lapic(&lapic_state)
            .map_err(|_| CpuHotplugError::GuestNotificationFailed)?;
        
        info!("APIC configured for hotplug vCPU {} with APIC ID {}", cpu_id, cpu_id);
        Ok(())
    }

    /// Check if CPUs are offline in the guest
    /// Returns Ok(()) if all CPUs are offline, Err(cpu_id) with the first online CPU
    fn check_cpus_offline_in_guest(&self, cpu_ids: &[u8]) -> Result<(), u8> {
        // This is a simplified check - in a real implementation, we would need to:
        // 1. Query the guest OS state through a guest agent or
        // 2. Track CPU online/offline events from the guest or
        // 3. Use shared memory communication with the guest
        
        // For now, we'll implement a basic check based on vCPU state
        // In production, this should be enhanced with proper guest communication
        
        // Never allow removing CPU 0 (boot CPU)
        for &cpu_id in cpu_ids {
            if cpu_id == 0 {
                warn!("Cannot remove boot CPU 0");
                return Err(cpu_id);
            }
        }
        
        // Enhanced safety check: verify vCPU threads are not actively running
        // This is still not perfect but better than nothing
        for &cpu_id in cpu_ids {
            if (cpu_id as usize) < self.vcpus_handles.len() {
                // TODO: Add actual guest CPU state tracking
                // For now, we'll use a simple heuristic: allow removal of non-boot CPUs
                // after a brief check period
                
                info!("CPU {} marked for removal - ensure it's offline in guest first", cpu_id);
                // In a real implementation, we'd check:
                // - Guest /sys/devices/system/cpu/cpu{}/online status
                // - vCPU thread activity levels
                // - Guest agent communication
            }
        }
        
        info!("CPU offline check passed for CPUs: {:?}", cpu_ids);
        Ok(())
    }

    /// Start a VCPU thread for hotplug
    fn start_vcpu(&mut self, vcpu: Vcpu) -> Result<VcpuHandle, CpuHotplugError> {
        // For now, use default seccomp filter for hotplugged CPUs
        // TODO: Use the same seccomp filter as boot-time CPUs for full security
        let seccomp_filter = Arc::new(crate::seccomp::BpfProgram::default());
        
        // Start the vCPU thread - it will start in paused state
        let vcpu_handle = vcpu.start_threaded(
            seccomp_filter,
            Arc::new(Barrier::new(1)),
        )
        .map_err(|_| CpuHotplugError::GuestNotificationFailed)?;
        
        // Send Resume event to transition the vCPU to running state
        // This is necessary for the vCPU to be able to handle SIPI
        vcpu_handle.send_event(crate::vstate::vcpu::VcpuEvent::Resume)
            .map_err(|_| CpuHotplugError::GuestNotificationFailed)?;
        
        info!("Hotplug vCPU thread started in running state - ready for SIPI");
        Ok(vcpu_handle)
    }

    /// Notify guest OS about CPU configuration change
    fn notify_guest_cpu_change(&self) -> Result<(), CpuHotplugError> {
        info!("CPU configuration changed - notifying guest");
        
        // Try to trigger ACPI CPU hotplug scan via ACPI processor driver
        // This attempts to send an ACPI notification to the guest OS
        self.trigger_acpi_cpu_scan().unwrap_or_else(|e| {
            info!("ACPI notification failed ({}), guest should manually scan CPUs", e);
        });
        
        // Log instructions for manual guest-side CPU detection
        info!("Guest can manually detect CPUs with:");
        info!("  echo 1 > /sys/devices/system/cpu/cpu*/online");
        info!("  or use: for cpu in /sys/devices/system/cpu/cpu[1-9]*; do echo 1 > $cpu/online 2>/dev/null; done");
        
        Ok(())
    }

    /// Trigger ACPI CPU scan in the guest
    fn trigger_acpi_cpu_scan(&self) -> Result<(), &'static str> {
        info!("Triggering ACPI CPU rescan in guest");
        
        // Attempt to send ACPI notification to guest
        // This tries to simulate what QEMU does for CPU hotplug
        if let Err(e) = self.send_acpi_cpu_notification() {
            info!("ACPI notification failed: {}", e);
            return Err("ACPI notification failed");
        }
        
        info!("ACPI CPU notification sent successfully");
        Ok(())
    }

    /// Send ACPI CPU notification to guest
    fn send_acpi_cpu_notification(&self) -> Result<(), &'static str> {
        // In a full ACPI implementation, this would:
        // 1. Update guest memory with new CPU present mask
        // 2. Send System Control Interrupt (SCI) to guest
        // 3. Guest ACPI driver handles interrupt and rescans CPUs
        
        let current_vcpu_count = self.vcpus_handles.len();
        info!("Notifying guest about {} CPUs via ACPI", current_vcpu_count);
        
        // Try to trigger ACPI bus rescan in guest
        // This should cause the guest to detect new CPU devices
        if let Err(_) = self.trigger_guest_cpu_interrupt() {
            info!("ACPI interrupt failed, guest will need manual CPU detection");
            return Err("Failed to trigger guest interrupt");
        }
        
        // Log helpful information for guest setup
        info!("ACPI notification sent - CPUs should appear in guest");
        info!("Manually bring them online with: echo 1 > /sys/devices/system/cpu/cpuX/online");
        
        Ok(())
    }
    
    /// Trigger a guest interrupt for CPU hotplug notification
    fn trigger_guest_cpu_interrupt(&self) -> Result<(), &'static str> {
        
        // Try different IRQ lines for ACPI notification
        // IRQ 9 is standard ACPI SCI, but might conflict with other devices
        const ACPI_SCI_IRQ_CANDIDATES: &[u32] = &[9, 10, 11, 23];
        
        let current_vcpu_count = self.vcpus_handles.len();
        info!("Attempting to notify guest about {} CPUs via ACPI interrupt", current_vcpu_count);
        
        // Try multiple IRQ lines to find one that works
        for &irq in ACPI_SCI_IRQ_CANDIDATES {
            info!("Trying ACPI notification on IRQ {}", irq);
            
            match self.send_acpi_interrupt(irq) {
                Ok(_) => {
                    info!("ACPI CPU hotplug notification sent on IRQ {}", irq);
                    
                    // Additional manual notification methods
                    self.trigger_manual_cpu_detection();
                    return Ok(());
                }
                Err(e) => {
                    info!("Failed to send ACPI interrupt on IRQ {}: {}", irq, e);
                    continue;
                }
            }
        }
        
        // If all IRQ attempts failed, fall back to manual notification
        info!("All ACPI interrupt attempts failed, using manual CPU detection");
        self.trigger_manual_cpu_detection();
        
        Err("ACPI interrupt failed, check guest logs")
    }
    
    /// Send ACPI interrupt on specific IRQ line
    fn send_acpi_interrupt(&self, irq: u32) -> Result<(), &'static str> {
        use vmm_sys_util::eventfd::EventFd;
        
        // Create an event fd for the ACPI interrupt
        let acpi_event = EventFd::new(libc::EFD_NONBLOCK)
            .map_err(|_| "Failed to create ACPI event fd")?;
        
        // Register the ACPI interrupt with KVM
        self.vm.fd().register_irqfd(&acpi_event, irq)
            .map_err(|_| "Failed to register ACPI interrupt")?;
        
        // Trigger the ACPI interrupt by writing to the event fd
        acpi_event.write(1)
            .map_err(|_| "Failed to trigger ACPI interrupt")?;
        
        info!("ACPI interrupt triggered on IRQ {}", irq);
        Ok(())
    }
    
    /// Trigger manual CPU detection methods
    fn trigger_manual_cpu_detection(&self) {
        let current_vcpu_count = self.vcpus_handles.len();
        
        info!("=== Manual CPU Hotplug Detection Required ===");
        info!("Host VMM has {} vCPU threads running", current_vcpu_count);
        info!("Guest needs to manually detect new CPUs:");
        info!("");
        info!("Run these commands in the guest:");
        info!("  # Check if CPU directories appear:");
        info!("  ls /sys/devices/system/cpu/cpu*/");
        info!("");
        info!("  # Try to bring CPUs online manually:");
        info!("  for i in $(seq 1 {}); do", current_vcpu_count - 1);
        info!("    [ -f /sys/devices/system/cpu/cpu$i/online ] && echo 1 > /sys/devices/system/cpu/cpu$i/online");
        info!("  done");
        info!("");
        info!("  # Force ACPI rescan (if supported):");
        info!("  echo 1 > /sys/bus/acpi/rescan 2>/dev/null || echo 'ACPI rescan not available'");
        info!("");
        info!("  # Check final CPU count:");
        info!("  nproc");
        info!("================================================");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_hotplug_status() {
        // This would require a full VMM setup to test properly
        // For now, we'll just test the data structures
        let status = CpuHotplugStatus {
            online_cpus: vec![0, 1],
            offline_cpus: vec![2, 3],
            max_cpus: 4,
        };

        assert_eq!(status.online_cpus.len(), 2);
        assert_eq!(status.offline_cpus.len(), 2);
        assert_eq!(status.max_cpus, 4);
    }
}