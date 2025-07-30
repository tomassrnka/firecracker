# CPU Hotplug Scaling Down - Current State and Limitations

## ✅ What Works

### Host-Side Removal
- vCPU threads are properly terminated using `VcpuEvent::Finish`
- Memory cleanup is handled correctly
- ACPI notifications are sent to guest
- API correctly updates `online_cpus` and `offline_cpus` lists

### Safety Features
- Cannot remove boot CPU (CPU 0)
- Validates CPU IDs before removal
- Checks that CPUs exist before trying to remove them
- Prevents double-removal of already offline CPUs

## ❌ Current Limitations

### 1. Sequential-Only Removal
**Issue**: You can only remove CPUs in strict reverse order (highest to lowest)

**Example**:
```bash
# ✅ Works: Scale from 8 CPUs to 4 CPUs
curl -X PUT --unix-socket /path/to/socket http://localhost/cpu-config/hotplug \
     -d '{"target_vcpu_count": 4}'  # Removes CPUs 7,6,5,4

# ❌ Doesn't work: Remove CPU 2 while keeping CPU 7
# No API to remove specific non-sequential CPUs
```

**Why**: The current implementation uses a simple `Vec<VcpuHandle>` where removing arbitrary elements would leave gaps.

### 2. Incomplete Guest State Coordination
**Issue**: Host doesn't properly verify CPUs are offline in guest before removal

**Current Behavior**:
```rust
// Simplified check - only prevents removing CPU 0
fn check_cpus_offline_in_guest(&self, cpu_ids: &[u8]) -> Result<(), u8> {
    // TODO: Implement proper guest CPU state tracking
}
```

**What's Missing**:
- No communication with guest OS
- No verification that `echo 0 > /sys/devices/system/cpu/cpuX/online` was done
- Could remove CPUs that are still running guest processes

### 3. No Guest Agent Integration
**Issue**: No mechanism to coordinate CPU removal with guest OS

**What Should Happen**:
```bash
# 1. Host requests CPU offline
# 2. Guest agent offlines CPU gracefully
# 3. Guest confirms CPU is offline  
# 4. Host removes vCPU thread
```

**Current Reality**:
- Host removes CPU immediately
- Guest might not be ready
- Could cause guest instability

## 🔧 Recommended Usage Pattern

### Safe CPU Scaling Down Process

1. **Reduce Target via API**:
   ```bash
   curl -X PUT --unix-socket /path/to/socket http://localhost/cpu-config/hotplug \
        -d '{"target_vcpu_count": 2}'  # Scale from 4 to 2 CPUs
   ```

2. **In Guest: Manually Offline CPUs First** (Recommended):
   ```bash
   # Before scaling down, manually offline CPUs in guest
   echo 0 > /sys/devices/system/cpu/cpu3/online
   echo 0 > /sys/devices/system/cpu/cpu2/online
   
   # Verify they're offline
   cat /sys/devices/system/cpu/cpu*/online
   ```

3. **Check Host Logs**:
   ```bash
   # Host will log what it's doing
   journalctl -f | grep -i "cpu.*remov"
   ```

## 🚀 Future Improvements Needed

### 1. Guest Agent Communication
```rust
// Future: Proper guest coordination
async fn offline_cpu_in_guest(cpu_id: u8) -> Result<(), CpuHotplugError> {
    // Send request to guest agent
    // Wait for confirmation
    // Then remove host vCPU thread
}
```

### 2. Arbitrary CPU Removal
```rust
// Future: Support removing any CPU (not just sequential)
impl Vmm {
    fn remove_specific_cpus(&mut self, cpu_ids: Vec<u8>) -> Result<(), CpuHotplugError> {
        // Handle gaps in vCPU array
        // Remap CPU IDs as needed
    }
}
```

### 3. Migration-Safe CPU State
```rust
// Future: Track which CPUs can be safely removed during migration
struct CpuState {
    cpu_id: u8,
    guest_online: bool,
    removable: bool,
    last_activity: Timestamp,
}
```

## ⚠️ Current Risks

1. **Guest Instability**: Removing CPUs that are still running guest processes
2. **Sequential Limitation**: Cannot optimize CPU placement by removing specific CPUs
3. **No Rollback**: If removal fails, no automatic recovery mechanism

## 📊 Testing Status

### ✅ Tested Scenarios
- Scale down from 4 → 2 CPUs (sequential removal)
- Attempt to remove boot CPU (correctly blocked)
- Remove already offline CPUs (correctly blocked)

### ❌ Not Yet Tested
- Guest process migration during CPU removal
- High load scenarios during scaling down
- NUMA-aware CPU removal
- Migration with different CPU counts

## Summary

**CPU scaling down partially works** but has significant limitations:
- ✅ Host-side mechanics work
- ❌ Guest coordination is incomplete  
- ❌ Only sequential removal supported
- ⚠️ Risk of guest instability

For production use, always manually offline CPUs in guest before scaling down.