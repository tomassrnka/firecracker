# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for CPU hotplug functionality."""

import json
import pytest

from framework.microvm_helpers import MICROVM_KERNEL_RELPATH
from framework.utils import wait_process_termination


def test_cpu_hotplug_api_get(uvm_plain):
    """Test GET /cpu-config API endpoint."""
    vm = uvm_plain
    vm.basic_config(vcpu_count=1, mem_size_mib=128)
    vm.start()

    # Test GET /cpu-config after boot
    response = vm.api.cpu_config.get()
    assert response.status_code == 200
    
    config = response.json()
    assert "online_cpus" in config
    assert "offline_cpus" in config  
    assert "max_cpus" in config
    assert config["online_cpus"] == [0]  # Only CPU 0 should be online
    assert len(config["offline_cpus"]) > 0  # There should be offline CPUs
    assert config["max_cpus"] == 32  # Max supported CPUs


def test_cpu_hotplug_api_put_add(uvm_plain):
    """Test PUT /cpu-config/hotplug API endpoint for adding CPUs."""
    vm = uvm_plain
    vm.basic_config(vcpu_count=1, mem_size_mib=128)
    vm.start()

    # Get initial CPU status
    response = vm.api.cpu_config.get()
    initial_config = response.json()
    assert len(initial_config["online_cpus"]) == 1

    # Add one more CPU (target = 2)
    hotplug_config = {"target_vcpu_count": 2}
    response = vm.api.cpu_config_hotplug.put(body=json.dumps(hotplug_config))
    assert response.status_code == 204

    # Verify CPU was added
    response = vm.api.cpu_config.get()
    updated_config = response.json()
    assert len(updated_config["online_cpus"]) == 2
    assert updated_config["online_cpus"] == [0, 1]


def test_cpu_hotplug_api_put_remove(uvm_plain):
    """Test PUT /cpu-config/hotplug API endpoint for removing CPUs."""
    vm = uvm_plain
    vm.basic_config(vcpu_count=2, mem_size_mib=128)
    vm.start()

    # Get initial CPU status
    response = vm.api.cpu_config.get()
    initial_config = response.json()
    assert len(initial_config["online_cpus"]) == 2

    # Remove one CPU (target = 1)
    hotplug_config = {"target_vcpu_count": 1}
    response = vm.api.cpu_config_hotplug.put(body=json.dumps(hotplug_config))
    assert response.status_code == 204

    # Verify CPU was removed
    response = vm.api.cpu_config.get()
    updated_config = response.json()
    assert len(updated_config["online_cpus"]) == 1
    assert updated_config["online_cpus"] == [0]


def test_cpu_hotplug_api_errors(uvm_plain):
    """Test CPU hotplug API error conditions."""
    vm = uvm_plain
    vm.basic_config(vcpu_count=1, mem_size_mib=128)
    vm.start()

    # Test invalid target CPU count (too high)
    hotplug_config = {"target_vcpu_count": 64}  # Above MAX_SUPPORTED_VCPUS (32)
    response = vm.api.cpu_config_hotplug.put(body=json.dumps(hotplug_config))
    assert response.status_code == 400

    # Test invalid target CPU count (zero)
    hotplug_config = {"target_vcpu_count": 0}
    response = vm.api.cpu_config_hotplug.put(body=json.dumps(hotplug_config))
    assert response.status_code == 400

    # Test malformed JSON
    response = vm.api.cpu_config_hotplug.put(body="{invalid json}")
    assert response.status_code == 400


def test_cpu_hotplug_pre_boot_error(uvm_plain):
    """Test that CPU hotplug APIs return error before boot."""
    vm = uvm_plain
    vm.basic_config(vcpu_count=1, mem_size_mib=128)
    # Don't start the VM

    # Test GET /cpu-config before boot should fail
    response = vm.api.cpu_config.get()
    assert response.status_code == 400

    # Test PUT /cpu-config/hotplug before boot should fail
    hotplug_config = {"target_vcpu_count": 2}
    response = vm.api.cpu_config_hotplug.put(body=json.dumps(hotplug_config))
    assert response.status_code == 400


def test_cpu_hotplug_scale_up_down(uvm_plain):
    """Test scaling CPU count up and down multiple times."""
    vm = uvm_plain
    vm.basic_config(vcpu_count=1, mem_size_mib=128)
    vm.start()

    # Scale up to 4 CPUs
    for target_count in [2, 3, 4]:
        hotplug_config = {"target_vcpu_count": target_count}
        response = vm.api.cpu_config_hotplug.put(body=json.dumps(hotplug_config))
        assert response.status_code == 204

        # Verify CPU count
        response = vm.api.cpu_config.get()
        config = response.json()
        assert len(config["online_cpus"]) == target_count

    # Scale down to 1 CPU
    for target_count in [3, 2, 1]:
        hotplug_config = {"target_vcpu_count": target_count}
        response = vm.api.cpu_config_hotplug.put(body=json.dumps(hotplug_config))
        assert response.status_code == 204

        # Verify CPU count
        response = vm.api.cpu_config.get()
        config = response.json()
        assert len(config["online_cpus"]) == target_count


def test_cpu_hotplug_no_change(uvm_plain):
    """Test CPU hotplug when target equals current count."""
    vm = uvm_plain
    vm.basic_config(vcpu_count=2, mem_size_mib=128)
    vm.start()

    # Set target to same as current (should be no-op)
    hotplug_config = {"target_vcpu_count": 2}
    response = vm.api.cpu_config_hotplug.put(body=json.dumps(hotplug_config))
    assert response.status_code == 204

    # Verify CPU count unchanged
    response = vm.api.cpu_config.get()
    config = response.json()
    assert len(config["online_cpus"]) == 2
    assert config["online_cpus"] == [0, 1]