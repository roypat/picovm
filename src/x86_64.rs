// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::KVMIO;
use kvm_bindings::KVM_CAP_EXIT_HYPERCALL;
use kvm_bindings::{kvm_enable_cap, KVM_X86_SW_PROTECTED_VM};
use kvm_ioctls::{VcpuFd, VmFd};
use vmm_sys_util::ioctl::ioctl_with_val;
use vmm_sys_util::{ioctl_io_nr, ioctl_ioc_nr};

pub const VM_TYPE: u64 = KVM_X86_SW_PROTECTED_VM as u64;

// VM ioctl for checking support for a specific capability
ioctl_io_nr!(KVM_CHECK_EXTENSION, KVMIO, 0x03);

pub const ARCH_BOOTSTRAP_CODE: &[u8; 58] = include_bytes!("../code");

/// Hypercall number
pub const KVM_HC_MAP_GPA_RANGE: u64 = 12;

pub fn arch_setup_vm(vm_fd: &VmFd) {
    // To be able to dynamically map memory in response to a [`KVM_HC_MAP_GPA_RANGE`], we need
    // to tell KVM that it should exit to host userspace when it receives one of these.
    // For simplicity, make it exit to host userspace on any hypercall that supports this.
    let exitable_hypercalls =
        unsafe { ioctl_with_val(vm_fd, KVM_CHECK_EXTENSION(), KVM_CAP_EXIT_HYPERCALL as u64) };
    assert!(exitable_hypercalls > 0);
    vm_fd
        .enable_cap(&kvm_enable_cap {
            cap: KVM_CAP_EXIT_HYPERCALL,
            args: [exitable_hypercalls as u64, 0, 0, 0],
            ..Default::default()
        })
        .unwrap();
}

pub fn arch_setup_vcpu_state(_vm_fd: &VmFd, vcpu_fd: &VcpuFd) {
    let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

    let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
    // Set the Instruction Pointer to the guest address where we loaded the code.
    vcpu_regs.rip = crate::BOOTSTRAP_INSTRUCTIONS;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 3;
    vcpu_regs.rflags = 2;
    vcpu_fd.set_regs(&vcpu_regs).unwrap();
}

pub fn arch_get_program_counter(vcpu_fd: &VcpuFd) -> u64 {
    vcpu_fd.get_regs().unwrap().rip
}
