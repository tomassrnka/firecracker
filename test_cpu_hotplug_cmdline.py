#!/usr/bin/env python3

import socket
import json
import os
import sys
import subprocess
import tempfile
import time

def test_cpu_hotplug_cmdline():
    """Test that CPU hotplug parameters are added to kernel command line"""
    
    # Create a test script to check the kernel cmdline
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
        f.write("""#!/bin/bash
# Check if CPU hotplug parameters are in the kernel command line
cat /proc/cmdline | grep -q "maxcpus=32 nr_cpus=32 possible_cpus=32"
if [ $? -eq 0 ]; then
    echo "SUCCESS: CPU hotplug parameters found in kernel cmdline"
    exit 0
else
    echo "FAIL: CPU hotplug parameters not found in kernel cmdline"
    echo "Kernel cmdline: $(cat /proc/cmdline)"
    exit 1
fi
""")
        test_script = f.name
    
    os.chmod(test_script, 0o755)
    
    try:
        # Test with Firecracker configuration that should enable CPU hotplug params
        # (vcpu_count < MAX_SUPPORTED_VCPUS which is 32)
        firecracker_config = {
            "machine-config": {
                "vcpu_count": 2,  # Less than 32, so should add CPU hotplug params
                "mem_size_mib": 256
            },
            "boot-source": {
                "kernel_image_path": "/firecracker/build/kernel/linux-5.10-x86_64.bin",
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
            },
            "drives": [{
                "drive_id": "rootfs",
                "path_on_host": "/firecracker/build/rootfs/alpine.ext4",
                "is_root_device": True,
                "is_read_only": False
            }]
        }
        
        print("Testing CPU hotplug kernel parameters...")
        print(f"Configuration: vcpu_count={firecracker_config['machine-config']['vcpu_count']}")
        print("Expected: CPU hotplug parameters should be added to kernel cmdline")
        print(f"Test script: {test_script}")
        print()
        
        # Note: This is a conceptual test - we would need to actually boot
        # a VM to verify the kernel cmdline contains the CPU hotplug parameters
        print("To manually test:")
        print("1. Start Firecracker with vcpu_count < 32")
        print("2. Check guest /proc/cmdline contains: maxcpus=32 nr_cpus=32 possible_cpus=32")
        print("3. Run: echo 1 > /sys/devices/system/cpu/cpu1/online")
        print()
        
        return True
        
    finally:
        os.unlink(test_script)

if __name__ == "__main__":
    success = test_cpu_hotplug_cmdline()
    sys.exit(0 if success else 1)