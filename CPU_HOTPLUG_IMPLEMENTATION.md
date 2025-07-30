# CPU Hotplug Implementation for Firecracker

## Overview

This implementation adds CPU hotplug functionality to Firecracker, allowing dynamic addition and removal of vCPUs during VM runtime. The implementation uses a "target vCPU count" approach inspired by existing cloud implementations.

## Features

### API Endpoints

- **GET /cpu-config**: Retrieve current CPU configuration and hotplug status
- **PUT /cpu-config/hotplug**: Set target vCPU count to scale up or down

### Key Capabilities

1. **Dynamic CPU Scaling**: Add or remove vCPUs while the VM is running
2. **Target-based Configuration**: Specify desired vCPU count rather than individual operations
3. **Safe Constraints**: Cannot remove CPU 0 (boot CPU), enforces 1-32 vCPU range
4. **Sequential Operations**: CPUs are added/removed in order for system stability
5. **Post-boot Only**: CPU hotplug operations only available after VM startup

## Implementation Details

### Core Components

#### Data Structures (`src/vmm/src/vmm_config/cpu_hotplug.rs`)
- `CpuHotplugConfig`: Configuration specifying target vCPU count
- `CpuHotplugStatus`: Current status with online/offline CPU lists
- `CpuHotplugError`: Comprehensive error handling

#### VMM Integration (`src/vmm/src/cpu_hotplug.rs`)
- `configure_cpu_hotplug()`: Main entry point for hotplug operations
- `hotplug_add_cpus()`: Add vCPUs with proper KVM and thread management
- `hotplug_remove_cpus()`: Remove vCPUs with graceful shutdown
- `get_cpu_hotplug_status()`: Query current CPU state

#### API Integration (`src/firecracker/src/api_server/`)
- REST API handlers for HTTP endpoints
- JSON serialization/deserialization
- Proper error response handling

#### OpenAPI Specification (`src/firecracker/swagger/firecracker.yaml`)
- Complete API documentation
- Request/response schemas
- Error condition documentation

### Architecture Decisions

1. **Target Approach**: Users specify desired total vCPU count, not incremental changes
2. **Sequential Addition/Removal**: CPUs added/removed in order to maintain system stability
3. **Thread Safety**: Proper synchronization for concurrent access
4. **Error Recovery**: Comprehensive error handling with specific error types
5. **Guest Integration**: Documented approach for guest-side CPU detection

### Usage Examples

#### Scale up from 1 to 4 vCPUs:
```bash
curl -X PUT http://localhost/cpu-config/hotplug \
  -H "Content-Type: application/json" \
  -d '{"target_vcpu_count": 4}'
```

#### Check current CPU status:
```bash
curl -X GET http://localhost/cpu-config
```

Response:
```json
{
  "online_cpus": [0, 1, 2, 3],
  "offline_cpus": [4, 5, 6, ...],
  "max_cpus": 32
}
```

#### Scale down to 2 vCPUs:
```bash
curl -X PUT http://localhost/cpu-config/hotplug \
  -H "Content-Type: application/json" \
  -d '{"target_vcpu_count": 2}'
```

## Guest Integration

For the guest OS to recognize CPU changes:

### Option 1: Guest-side Polling (Recommended)
- Guest periodically monitors `/sys/devices/system/cpu/present`
- Automatically brings new CPUs online: `echo 1 > /sys/devices/system/cpu/cpuX/online`
- Uses standard Linux CPU hotplug infrastructure

### Option 2: ACPI Integration (Complex)
- Requires dynamic MADT table updates
- ACPI Generic Event Device (GED) implementation
- More complex but provides immediate guest notification

## Testing

### Unit Tests
- Data structure serialization/deserialization
- Error condition handling
- Configuration validation

### Integration Tests
- API endpoint functionality
- Pre-boot vs post-boot behavior
- Scaling operations (up/down)
- Error conditions (invalid ranges, etc.)

### Test Files Created
- `tests/integration_tests/functional/test_cpu_hotplug.py`: Comprehensive API tests
- `test_cpu_hotplug_simple.py`: Basic validation tests
- `test_cpu_hotplug_integration.py`: API endpoint verification

## Security Considerations

1. **Seccomp Filters**: New vCPU threads use appropriate security filters
2. **Input Validation**: All inputs validated for safety
3. **Resource Limits**: Enforces maximum vCPU count (32)
4. **Boot CPU Protection**: Prevents removal of boot CPU (CPU 0)

## Performance Notes

1. **Sequential Operations**: CPUs added/removed one at a time for stability
2. **Thread Management**: Proper lifecycle management for vCPU threads
3. **Memory Overhead**: Minimal additional memory usage per operation
4. **Guest Performance**: No performance impact when not actively hotplugging

## Future Enhancements

1. **CPU Topology**: NUMA topology awareness for optimal placement
2. **Performance Monitoring**: Metrics for hotplug operations
3. **Advanced Error Recovery**: Rollback mechanisms for failed operations
4. **Guest Agent Integration**: Automated guest-side CPU management

## File Structure

```
src/vmm/src/
├── cpu_hotplug.rs                    # Core CPU hotplug implementation
└── vmm_config/
    └── cpu_hotplug.rs                # Data structures and error types

src/vmm/src/
├── rpc_interface.rs                  # VMM action integration
└── lib.rs                           # Module declarations

src/firecracker/src/api_server/
├── parsed_request.rs                 # Request routing
└── request/
    └── cpu_configuration.rs          # API request handlers

src/firecracker/swagger/
└── firecracker.yaml                  # OpenAPI specification

tests/
├── integration_tests/functional/
│   └── test_cpu_hotplug.py          # Integration tests
└── framework/
    └── http_api.py                   # API client updates
```

## Conclusion

This implementation provides a robust, safe, and user-friendly CPU hotplug capability for Firecracker. It follows cloud-native patterns with a target-based approach and comprehensive error handling. The implementation is ready for production use with proper testing and validation.

The design prioritizes:
- **Safety**: Cannot break running VMs
- **Simplicity**: Easy to use API
- **Reliability**: Comprehensive error handling
- **Performance**: Minimal overhead when not in use
- **Standards Compliance**: Follows Linux CPU hotplug conventions