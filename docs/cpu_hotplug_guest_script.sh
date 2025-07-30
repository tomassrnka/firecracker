#!/bin/sh
# CPU Hotplug Guest Integration Script for Firecracker
# This script helps the guest detect and online hotplugged CPUs

echo "=== Firecracker CPU Hotplug Detection ==="

# Function to detect new CPUs
detect_cpus() {
    echo "Current CPU status:"
    echo "  Possible: $(cat /sys/devices/system/cpu/possible 2>/dev/null || echo 'unknown')"
    echo "  Present:  $(cat /sys/devices/system/cpu/present 2>/dev/null || echo 'unknown')"
    echo "  Online:   $(cat /sys/devices/system/cpu/online 2>/dev/null || echo 'unknown')"
    echo "  nproc:    $(nproc)"
    echo ""
}

# Function to try to bring CPUs online
online_cpus() {
    echo "Attempting to bring CPUs online..."
    
    # Method 1: Try to online CPUs based on possible range
    possible=$(cat /sys/devices/system/cpu/possible 2>/dev/null)
    if [ "$possible" != "" ] && [ "$possible" != "0" ]; then
        echo "Possible CPUs: $possible"
        
        # Extract max CPU number
        max_cpu=$(echo $possible | sed 's/.*-//' | tr -d '\n')
        if [ "$max_cpu" -gt 0 ] 2>/dev/null; then
            echo "Trying to online CPUs 1-$max_cpu..."
            
            for i in $(seq 1 $max_cpu); do
                cpu_dir="/sys/devices/system/cpu/cpu$i"
                online_file="$cpu_dir/online"
                
                if [ -d "$cpu_dir" ]; then
                    if [ -f "$online_file" ]; then
                        echo "Bringing CPU $i online..."
                        echo 1 > "$online_file" 2>/dev/null && echo "  CPU $i: success" || echo "  CPU $i: failed"
                    else
                        echo "  CPU $i: no online file (may be already online or not hotpluggable)"
                    fi
                else
                    echo "  CPU $i: directory does not exist"
                fi
            done
        fi
    fi
    
    echo ""
}

# Function to try ACPI rescan methods
try_acpi_rescan() {
    echo "Attempting ACPI CPU rescan..."
    
    # Try various ACPI rescan methods
    if [ -f /sys/bus/acpi/rescan ]; then
        echo "Triggering ACPI bus rescan..."
        echo 1 > /sys/bus/acpi/rescan 2>/dev/null && echo "  ACPI rescan: success" || echo "  ACPI rescan: failed"
    else
        echo "  ACPI rescan not available"
    fi
    
    if [ -f /sys/devices/system/cpu/probe ]; then
        echo "Triggering CPU probe..."
        echo 1 > /sys/devices/system/cpu/probe 2>/dev/null && echo "  CPU probe: success" || echo "  CPU probe: failed"
    else
        echo "  CPU probe not available"
    fi
    
    echo ""
}

# Main execution
echo "Starting CPU hotplug detection..."
echo ""

detect_cpus
try_acpi_rescan
detect_cpus
online_cpus
detect_cpus

echo "=== CPU Hotplug Detection Complete ==="
echo ""
echo "If CPUs are still not detected, the ACPI notification system"
echo "needs to be implemented in the Firecracker VMM."
echo ""
echo "Manual commands you can try:"
echo "  # Check for new CPU directories:"
echo "  ls /sys/devices/system/cpu/cpu*/"
echo ""
echo "  # Manually online specific CPUs:"
echo "  echo 1 > /sys/devices/system/cpu/cpu1/online"
echo "  echo 1 > /sys/devices/system/cpu/cpu2/online"
echo "  echo 1 > /sys/devices/system/cpu/cpu3/online"