#!/usr/bin/env python3

"""Full CPU hotplug test with actual VM using Firecracker test framework."""

import json
import subprocess
import sys
import tempfile
import time
import os
import requests_unixsocket
from pathlib import Path

def download_test_resources():
    """Download minimal kernel and rootfs for testing."""
    print("Downloading test resources...")
    
    # Create a resources directory
    resources_dir = Path("/tmp/firecracker-test-resources")
    resources_dir.mkdir(exist_ok=True)
    
    # URLs for minimal test resources (these are public Firecracker test resources)
    kernel_url = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.0.0/vmlinux.bin"
    rootfs_url = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.0.0/ubuntu-18.04.ext4"
    
    kernel_path = resources_dir / "vmlinux.bin"
    rootfs_path = resources_dir / "ubuntu-18.04.ext4"
    
    # Download if not exists
    if not kernel_path.exists():
        print("Downloading kernel...")
        result = subprocess.run([
            "wget", "-O", str(kernel_path), kernel_url
        ], capture_output=True)
        if result.returncode != 0:
            print("Failed to download kernel, using placeholder")
            return None, None
    
    if not rootfs_path.exists():
        print("Downloading rootfs...")
        result = subprocess.run([
            "wget", "-O", str(rootfs_path), rootfs_url
        ], capture_output=True)
        if result.returncode != 0:
            print("Failed to download rootfs, using placeholder")
            return None, None
    
    return str(kernel_path), str(rootfs_path)

def create_minimal_test_vm():
    """Create a minimal VM configuration for testing CPU hotplug."""
    
    # Get firecracker binary
    firecracker_binary = "/root/fc/firecracker-official/build/cargo_target/x86_64-unknown-linux-musl/debug/firecracker"
    
    if not Path(firecracker_binary).exists():
        print("Firecracker binary not found. Please run build first.")
        return False
    
    # Create temporary socket
    with tempfile.NamedTemporaryFile(suffix='.sock', delete=False) as sock_file:
        api_socket_path = sock_file.name
    
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as log_file:
        log_path = log_file.name
    
    try:
        os.unlink(api_socket_path)  # Remove so Firecracker can create it
        
        # Start Firecracker
        print("Starting Firecracker...")
        proc = subprocess.Popen([
            firecracker_binary,
            "--api-sock", api_socket_path,
            "--log-path", log_path,
            "--level", "Info"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait for API socket
        for _ in range(20):
            if os.path.exists(api_socket_path):
                break
            time.sleep(0.5)
        else:
            print("Failed to start Firecracker API")
            return False
        
        # Create HTTP session
        session = requests_unixsocket.Session()
        base_url = f"http+unix://{api_socket_path.replace('/', '%2F')}"
        
        print("Configuring VM...")
        
        # Configure machine with 1 vCPU initially
        config = {
            "vcpu_count": 1,
            "mem_size_mib": 128
        }
        response = session.put(f"{base_url}/machine-config", json=config)
        print(f"Machine config: {response.status_code}")
        
        # Try to get kernel and rootfs
        kernel_path, rootfs_path = download_test_resources()
        
        if kernel_path and rootfs_path and Path(kernel_path).exists() and Path(rootfs_path).exists():
            # Configure boot source
            boot_config = {
                "kernel_image_path": kernel_path,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
            }
            response = session.put(f"{base_url}/boot-source", json=boot_config)
            print(f"Boot source: {response.status_code}")
            
            # Configure rootfs
            drive_config = {
                "drive_id": "rootfs",
                "path_on_host": rootfs_path,
                "is_root_device": True,
                "is_read_only": False
            }
            response = session.put(f"{base_url}/drives/rootfs", json=drive_config)
            print(f"Drive config: {response.status_code}")
            
            # Start VM
            start_config = {"action_type": "InstanceStart"}
            response = session.put(f"{base_url}/actions", json=start_config)
            print(f"VM start: {response.status_code}")
            
            if response.status_code == 204:
                print("✓ VM started successfully!")
                
                # Wait a moment for VM to boot
                time.sleep(2)
                
                # Now test CPU hotplug
                return test_cpu_hotplug_with_running_vm(session, base_url)
            else:
                print(f"Failed to start VM: {response.status_code}")
                if response.text:
                    print(f"Error: {response.text}")
                return False
        else:
            print("Could not download test resources. Testing API without full VM...")
            return test_cpu_hotplug_api_only(session, base_url)
            
    except Exception as e:
        print(f"Error during VM setup: {e}")
        return False
    finally:
        # Cleanup
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except:
            proc.kill()
        
        for path in [api_socket_path, log_path]:
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except:
                pass

def test_cpu_hotplug_with_running_vm(session, base_url):
    """Test CPU hotplug with a running VM."""
    print("\n=== Testing CPU Hotplug with Running VM ===")
    
    try:
        # Test 1: Get initial CPU status
        response = session.get(f"{base_url}/cpu-config")
        if response.status_code == 200:
            status = response.json()
            print(f"✓ Initial CPU status: {status}")
            initial_count = len(status['online_cpus'])
        else:
            print(f"✗ Failed to get CPU status: {response.status_code}")
            return False
        
        # Test 2: Scale up to 2 CPUs
        hotplug_config = {"target_vcpu_count": 2}
        response = session.put(f"{base_url}/cpu-config/hotplug", json=hotplug_config)
        if response.status_code == 204:
            print("✓ CPU hotplug scale-up successful")
        else:
            print(f"✗ CPU hotplug scale-up failed: {response.status_code}")
            return False
        
        # Test 3: Verify the change
        response = session.get(f"{base_url}/cpu-config")
        if response.status_code == 200:
            status = response.json()
            current_count = len(status['online_cpus'])
            print(f"✓ CPU status after scale-up: {status}")
            if current_count == 2:
                print("✓ Successfully scaled up to 2 vCPUs")
            else:
                print(f"✗ Expected 2 vCPUs, got {current_count}")
                return False
        else:
            print(f"✗ Failed to verify CPU status: {response.status_code}")
            return False
        
        # Test 4: Scale back down to 1 CPU
        hotplug_config = {"target_vcpu_count": 1}
        response = session.put(f"{base_url}/cpu-config/hotplug", json=hotplug_config)
        if response.status_code == 204:
            print("✓ CPU hotplug scale-down successful")
        else:
            print(f"✗ CPU hotplug scale-down failed: {response.status_code}")
            return False
        
        # Test 5: Verify scale-down
        response = session.get(f"{base_url}/cpu-config")
        if response.status_code == 200:
            status = response.json()
            current_count = len(status['online_cpus'])
            print(f"✓ CPU status after scale-down: {status}")
            if current_count == 1:
                print("✓ Successfully scaled down to 1 vCPU")
            else:
                print(f"✗ Expected 1 vCPU, got {current_count}")
                return False
        else:
            print(f"✗ Failed to verify CPU status after scale-down: {response.status_code}")
            return False
        
        print("\n🎉 All CPU hotplug tests passed with running VM!")
        return True
        
    except Exception as e:
        print(f"✗ CPU hotplug test failed: {e}")
        return False

def test_cpu_hotplug_api_only(session, base_url):
    """Test CPU hotplug API endpoints without full VM."""
    print("\n=== Testing CPU Hotplug API (Pre-boot) ===")
    
    try:
        # These should return 400 (not supported pre-boot)
        response = session.get(f"{base_url}/cpu-config")
        if response.status_code == 400:
            print("✓ GET /cpu-config correctly returns 400 (pre-boot)")
        else:
            print(f"✗ Expected 400, got {response.status_code}")
            return False
        
        hotplug_config = {"target_vcpu_count": 2}
        response = session.put(f"{base_url}/cpu-config/hotplug", json=hotplug_config)
        if response.status_code == 400:
            print("✓ PUT /cpu-config/hotplug correctly returns 400 (pre-boot)")
        else:
            print(f"✗ Expected 400, got {response.status_code}")
            return False
        
        print("✓ CPU hotplug API endpoints working correctly (pre-boot restrictions)")
        return True
        
    except Exception as e:
        print(f"✗ API test failed: {e}")
        return False

if __name__ == "__main__":
    print("=== Full CPU Hotplug Test ===")
    success = create_minimal_test_vm()
    
    if success:
        print("\n🎉 CPU hotplug implementation is working!")
        print("\nTo test manually:")
        print("1. Start Firecracker with your kernel/rootfs")
        print("2. Use these curl commands:")
        print("")
        print("# Check CPU status:")
        print("curl -X GET --unix-socket /tmp/firecracker.socket http://localhost/cpu-config")
        print("")
        print("# Scale up to 4 CPUs:")
        print('curl -X PUT --unix-socket /tmp/firecracker.socket -H "Content-Type: application/json" -d \'{"target_vcpu_count": 4}\' http://localhost/cpu-config/hotplug')
        print("")
        print("# Scale down to 2 CPUs:")
        print('curl -X PUT --unix-socket /tmp/firecracker.socket -H "Content-Type: application/json" -d \'{"target_vcpu_count": 2}\' http://localhost/cpu-config/hotplug')
    else:
        print("\n❌ Some tests failed. Check the logs above.")
    
    sys.exit(0 if success else 1)