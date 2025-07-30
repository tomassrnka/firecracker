# CPU Hotplug Usage Guide

## Overview

Firecracker now supports **conditional CPU hotplug** - you can enable CPU hotplug support only when needed, eliminating the need for hardcoded kernel parameters.

## Key Benefits

✅ **Clean Control**: Enable CPU hotplug only when needed via `cpu_hotplug_enabled` flag  
✅ **No Pre-Setup Required**: Kernel parameters added automatically when enabled  
✅ **Dynamic Host Adaptation**: Max CPUs automatically set to host CPU count  
✅ **Production Safe**: Comprehensive safety checks and validation  

## Usage Examples

### 1. **Standard VM (No CPU Hotplug)**

```bash
# Machine config - regular VM setup
curl -X PUT --unix-socket /path/to/socket http://localhost/machine-config \
     -H 'Content-Type: application/json' \
     -d '{
       "vcpu_count": 2,
       "mem_size_mib": 1024,
       "cpu_hotplug_enabled": false
     }'
```

**Result**: VM starts with exactly 2 CPUs, no hotplug infrastructure, clean kernel cmdline.

### 2. **CPU Hotplug Enabled VM**

```bash
# Machine config - enable CPU hotplug
curl -X PUT --unix-socket /path/to/socket http://localhost/machine-config \
     -H 'Content-Type: application/json' \
     -d '{
       "vcpu_count": 1,
       "mem_size_mib": 1024,
       "cpu_hotplug_enabled": true
     }'
```

**Result**: 
- VM starts with 1 CPU
- Kernel automatically gets: `maxcpus=8 nr_cpus=8 possible_cpus=8` (on 8-core host)
- ACPI tables configured for all 8 possible CPUs
- Guest sees `/sys/devices/system/cpu/cpu0-cpu7/` directories

### 3. **Dynamic CPU Scaling**

```bash
# Scale up to 4 CPUs
curl -X PUT --unix-socket /path/to/socket http://localhost/cpu-config/hotplug \
     -H 'Content-Type: application/json' \
     -d '{"target_vcpu_count": 4}'

# In guest: Bring CPUs online
for cpu in /sys/devices/system/cpu/cpu{1,2,3}/online; do
    echo 1 > "$cpu"
done

# Check result
nproc  # Should show 4
```

### 4. **Host-Adaptive Scaling**

**8-core host**:
```json
{"max_cpus": 8}  # Can scale from 1 to 8 CPUs
```

**16-core host**:
```json
{"max_cpus": 16}  # Can scale from 1 to 16 CPUs
```

**64-core host**:
```json
{"max_cpus": 64}  # Can scale from 1 to 64 CPUs
```

## Comparison: Before vs After

### Before (Always Required Kernel Params)
```bash
# VM always got CPU hotplug params regardless of need
# Kernel cmdline: "reboot=k panic=1 ... maxcpus=32 nr_cpus=32 possible_cpus=32"
# Guest always had /sys/devices/system/cpu/cpu0-cpu31/ (even on 8-core host!)
```

### After (Conditional & Dynamic)
```bash
# Without cpu_hotplug_enabled=true:
# Kernel cmdline: "reboot=k panic=1 pci=off ..." (clean, no hotplug params)
# Guest has only actual CPUs

# With cpu_hotplug_enabled=true on 8-core host:
# Kernel cmdline: "reboot=k panic=1 ... maxcpus=8 nr_cpus=8 possible_cpus=8"
# Guest has /sys/devices/system/cpu/cpu0-cpu7/ (matches host!)
```

## Real-World Scenarios

### Scenario 1: Static Workloads
```bash
# Web server with fixed CPU requirements
curl -X PUT ... -d '{
  "vcpu_count": 4,
  "mem_size_mib": 2048,
  "cpu_hotplug_enabled": false  # No overhead, clean setup
}'
```

### Scenario 2: Auto-Scaling Applications
```bash
# Kubernetes pods that need dynamic scaling
curl -X PUT ... -d '{
  "vcpu_count": 1,
  "mem_size_mib": 1024,
  "cpu_hotplug_enabled": true   # Enable dynamic scaling
}'

# Later, scale based on load
curl -X PUT ... -d '{"target_vcpu_count": 6}'
```

### Scenario 3: Development/Testing
```bash
# Start small, scale up for testing
curl -X PUT ... -d '{
  "vcpu_count": 1,
  "cpu_hotplug_enabled": true
}'

# Test with different CPU counts
for cpus in 2 4 8; do
  curl -X PUT ... -d "{\"target_vcpu_count\": $cpus}"
  # Run benchmarks...
done
```

## Safety Features

1. **Host CPU Limit**: Cannot exceed actual host CPU count
2. **Boot CPU Protection**: Cannot remove CPU 0
3. **Online CPU Protection**: Cannot remove CPUs still online in guest
4. **Input Validation**: Comprehensive error checking
5. **Graceful Fallbacks**: Clean error handling

## Migration Notes

### Existing Scripts
Old scripts continue to work - `cpu_hotplug_enabled` defaults to `false`.

### New Development
Use `cpu_hotplug_enabled: true` only when you need dynamic CPU scaling.

## Performance Impact

- **Disabled**: Zero overhead, standard VM performance
- **Enabled**: Minimal overhead, only when actively scaling CPUs

This approach gives you the best of both worlds: clean, simple VMs when you don't need hotplug, and powerful dynamic scaling when you do!