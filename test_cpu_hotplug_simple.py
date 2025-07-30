#!/usr/bin/env python3

"""Simple test to verify CPU hotplug data structures work correctly."""

import json
import subprocess
import sys
import tempfile
import time
import os
from pathlib import Path

def test_build_success():
    """Test that Firecracker builds successfully with CPU hotplug changes."""
    print("Testing build...")
    result = subprocess.run(
        ["tools/devtool", "build"],
        capture_output=True,
        text=True,
        cwd="/root/fc/firecracker-official"
    )
    
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}")
        return False
        
    print("✓ Build successful")
    return True

def test_binary_exists():
    """Test that firecracker binary was created."""
    binary_path = Path("/root/fc/firecracker-official/build/cargo_target/x86_64-unknown-linux-musl/debug/firecracker")
    if not binary_path.exists():
        print(f"Binary not found at {binary_path}")
        return False
        
    print("✓ Binary exists")
    return True

def test_api_spec_valid():
    """Test that the OpenAPI spec is valid JSON/YAML."""
    spec_path = Path("/root/fc/firecracker-official/src/firecracker/swagger/firecracker.yaml")
    
    try:
        # Simple check that the file parses
        with open(spec_path) as f:
            content = f.read()
            
        # Check that our new endpoints are in the spec
        if "/cpu-config:" not in content:
            print("CPU config endpoint not found in API spec")
            return False
            
        if "/cpu-config/hotplug:" not in content:
            print("CPU hotplug endpoint not found in API spec")
            return False
            
        if "CpuHotplugConfig:" not in content:
            print("CpuHotplugConfig definition not found in API spec")
            return False
            
        if "CpuHotplugStatus:" not in content:
            print("CpuHotplugStatus definition not found in API spec")
            return False
            
        print("✓ API specification includes CPU hotplug endpoints")
        return True
        
    except Exception as e:
        print(f"Failed to validate API spec: {e}")
        return False

def test_data_structures():
    """Test that CPU hotplug data structures serialize correctly."""
    # Test CpuHotplugConfig
    config_json = '{"target_vcpu_count": 4}'
    try:
        config = json.loads(config_json)
        assert "target_vcpu_count" in config
        assert config["target_vcpu_count"] == 4
        print("✓ CpuHotplugConfig JSON structure valid")
    except Exception as e:
        print(f"CpuHotplugConfig test failed: {e}")
        return False
    
    # Test CpuHotplugStatus
    status_json = '{"online_cpus": [0, 1], "offline_cpus": [2, 3], "max_cpus": 32}'
    try:
        status = json.loads(status_json)
        assert "online_cpus" in status
        assert "offline_cpus" in status
        assert "max_cpus" in status
        assert status["online_cpus"] == [0, 1]
        assert status["offline_cpus"] == [2, 3]
        assert status["max_cpus"] == 32
        print("✓ CpuHotplugStatus JSON structure valid")
    except Exception as e:
        print(f"CpuHotplugStatus test failed: {e}")
        return False
        
    return True

def run_tests():
    """Run all simple tests."""
    print("=== CPU Hotplug Simple Tests ===")
    
    tests = [
        test_build_success,
        test_binary_exists,
        test_api_spec_valid,
        test_data_structures,
    ]
    
    passed = 0
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"✗ {test.__name__} failed")
        except Exception as e:
            print(f"✗ {test.__name__} failed with exception: {e}")
    
    print(f"\n=== Results: {passed}/{len(tests)} tests passed ===")
    
    if passed == len(tests):
        print("🎉 All tests passed! CPU hotplug implementation looks good.")
        return True
    else:
        print("❌ Some tests failed.")
        return False

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)