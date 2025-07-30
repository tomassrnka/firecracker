# True CPU Hotplug Design for Firecracker

## Current State: Pseudo-Hotplug
```bash
# Boot with pre-allocated structures
maxcpus=8 possible_cpus=8
# CPUs 1-7 exist but are offline
echo 1 > /sys/devices/system/cpu/cpu1/online  # "Hotplug"
```

## True Hotplug Design

### Architecture Overview
```
Host: Available CPU pool (e.g., 24 cores)
↓
Firecracker: Dynamic vCPU allocation
↓  
Guest: CPUs appear/disappear dynamically (no pre-allocation)
```

### Implementation Plan

#### Phase 1: Dynamic ACPI Table Updates
```rust
impl Vmm {
    fn true_hotplug_add_cpu(&mut self) -> Result<u8, CpuHotplugError> {
        // 1. Find next available CPU ID
        let cpu_id = self.find_next_cpu_id();
        
        // 2. Create vCPU thread  
        let vcpu = self.create_vcpu_dynamic(cpu_id)?;
        
        // 3. Update guest ACPI tables in memory
        self.inject_new_processor_device(cpu_id)?;
        
        // 4. Send ACPI _BUS_CHECK notification
        self.acpi_notify_cpu_added(cpu_id)?;
        
        // 5. Guest kernel handles device discovery
        Ok(cpu_id)
    }
}
```

#### Phase 2: Guest Memory ACPI Updates
```rust
fn inject_new_processor_device(&mut self, cpu_id: u8) -> Result<(), AcpiError> {
    // Find ACPI DSDT table in guest memory
    let dsdt_addr = self.find_guest_acpi_table("DSDT")?;
    
    // Create new processor device AML
    let processor_device = create_processor_device_aml(cpu_id);
    
    // Inject into guest memory
    self.guest_memory()
        .write_obj(processor_device, dsdt_addr + offset)?;
        
    // Update ACPI table checksums
    self.update_acpi_checksums()?;
    
    Ok(())
}
```

#### Phase 3: ACPI Event System
```rust
fn acpi_notify_cpu_added(&self, cpu_id: u8) -> Result<(), AcpiError> {
    // Send ACPI _BUS_CHECK event
    let gpe_event = AcpiEvent::BusCheck { 
        device_path: format!("_SB.CPU{:X}", cpu_id),
        event_type: BusCheckType::DeviceAdded 
    };
    
    // Trigger ACPI SCI interrupt
    self.trigger_acpi_interrupt(gpe_event)?;
    
    Ok(())
}
```

### Kernel Requirements

#### Guest Kernel Config
```bash
CONFIG_HOTPLUG_CPU=y
CONFIG_ACPI_HOTPLUG_CPU=y  
CONFIG_ACPI_PROCESSOR=y
# No maxcpus= parameter needed!
```

#### Host CPU Pool Management
```rust
struct HostCpuPool {
    available_cpus: BTreeSet<u8>,
    assigned_cpus: HashMap<VmId, Vec<u8>>,
}

impl HostCpuPool {
    fn allocate_cpu_for_vm(&mut self, vm_id: VmId) -> Option<u8> {
        self.available_cpus.pop_first().map(|cpu| {
            self.assigned_cpus.entry(vm_id).or_default().push(cpu);
            cpu
        })
    }
}
```

### API Design
```json
// True hotplug API (no pre-allocation needed)
POST /cpu-config/hotplug-add
{
  "count": 2,  // Add 2 CPUs from host pool
  "numa_node": 0  // Optional NUMA preference
}

Response:
{
  "added_cpus": [1, 2],
  "host_cpus": [14, 15],  // Which host CPUs were assigned
  "total_vcpus": 3
}
```

### Advantages of True Hotplug

1. **No Boot Parameters**: Guest boots normally, no maxcpus needed
2. **Dynamic Scaling**: Can exceed initial expectations
3. **Resource Efficiency**: Only allocate what's used
4. **Host Pool Sharing**: Multiple VMs share dynamic CPU pool

### Challenges

#### 1. ACPI Complexity
- Dynamic ACPI table updates are complex
- Guest ACPI interpreters vary in capability
- Checksum recalculation required

#### 2. Guest OS Support
```bash
# Not all guests support this
echo "Some Linux distros disable ACPI CPU hotplug"
echo "Windows has different requirements"
echo "Embedded systems may not support it"
```

#### 3. Performance Impact
- Dynamic allocation has runtime overhead
- ACPI event processing takes time
- More complex error handling

#### 4. State Management
```rust
// Complex state tracking required
struct CpuState {
    cpu_id: u8,
    host_cpu: u8,
    acpi_injected: bool,
    guest_discovered: bool,
    guest_online: bool,
}
```

### Comparison: Current vs True Hotplug

| Aspect | Current (Pseudo) | True Hotplug |
|--------|------------------|--------------|
| Boot params | `maxcpus=N` required | None needed |
| Memory usage | Pre-allocate for N CPUs | Dynamic allocation |
| CPU limit | Fixed at boot | Dynamic based on host |
| Guest support | Widely supported | Limited support |
| Implementation | Simpler | Much more complex |
| Performance | Better (pre-allocated) | Slower (dynamic) |

### Recommendation

**For Firecracker's use case** (microVMs, serverless), the current pseudo-hotplug approach is actually better:

1. **Predictable**: Known CPU count at boot
2. **Fast**: No dynamic ACPI complexity  
3. **Compatible**: Works with all Linux guests
4. **Simple**: Easier to debug and maintain

**True hotplug would be valuable for**:
- Long-running VMs
- Enterprise virtualization
- Scenarios where initial CPU count is unknown

### Implementation Priority: LOW

The engineering effort for true hotplug would be enormous for marginal benefit in Firecracker's target use cases.