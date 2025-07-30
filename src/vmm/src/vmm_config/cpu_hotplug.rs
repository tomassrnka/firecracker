// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! CPU hotplug configuration and functionality.

use serde::{Deserialize, Serialize};

/// Configuration for CPU hotplug operations.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpuHotplugConfig {
    /// The target number of vCPUs for the running VM.
    pub target_vcpu_count: u8,
}

/// Current CPU hotplug status.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CpuHotplugStatus {
    /// List of currently online CPU IDs.
    pub online_cpus: Vec<u8>,
    /// List of currently offline CPU IDs.
    pub offline_cpus: Vec<u8>,
    /// Maximum number of CPUs supported.
    pub max_cpus: u8,
}

/// Error type for CPU hotplug operations.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum CpuHotplugError {
    /// Cannot add CPU {0}: CPU ID is invalid or out of range
    InvalidCpuId(u8),
    /// Cannot add CPU {0}: CPU is already online
    CpuAlreadyOnline(u8),
    /// Cannot remove CPU {0}: CPU is already offline
    CpuAlreadyOffline(u8),
    /// Cannot remove boot CPU (CPU 0)
    CannotRemoveBootCpu,
    /// Failed to notify guest OS about CPU configuration change
    GuestNotificationFailed,
    /// Cannot add {0} vCPUs: exceeds host CPU count of {1}
    ExceedsHostCpuCount(u8, u8),
    /// Cannot remove CPU {0}: CPU is still online in guest
    CpuStillOnline(u8),
}