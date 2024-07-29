// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::kvm_enable_cap;
use kvm_bindings::KVMIO;
use kvm_bindings::KVM_CAP_EXIT_HYPERCALL;
use kvm_ioctls::{VcpuFd, VmFd};
use vmm_sys_util::ioctl::ioctl_with_val;
use vmm_sys_util::{ioctl_io_nr, ioctl_ioc_nr};

// VM ioctl for checking support for a specific capability
ioctl_io_nr!(KVM_CHECK_EXTENSION, KVMIO, 0x03);

/**
Do a KVM_HC_MAP_GPA_RANGE hypercall (ax = 12) to mark the second page (bx = page aligned address,
cx = number of pages) as private (4th bit of dx = 1) from the guest's side
    mov ax, 12
    mov bx, 0x2000
    mov cx, 0x1
    mov dx, 0x8
    vmcall
Write a 'HLT' instruction (0xf4) to address 0x2000 (start of the second page), and jump to it.
    mov di, 0x2000
    mov bx, 0xf4
    mov [cs:di], bx
    jmp di
Hex values below are a hexdump of the output of "nasm code.asm"
 */
pub const ARCH_BOOTSTRAP_CODE: [u8; 26] = [
    0xb8, 0x0c, 0x00, // mov ax, 12
    0xbb, 0x00, 0x20, // mov bx, 0x2000
    0xb9, 0x01, 0x00, // mov cx, 0x1
    0xba, 0x08, 0x00, // mov dx, 0x8
    0x0f, 0x01, 0xc1, // vmcall
    0xbf, 0x00, 0x20, // mov di, 0x2000
    0xbb, 0xf4, 0x00, // mov bx, 0xf4
    0x2e, 0x89, 0x1d, // mov [cs:di], bx
    0xff, 0xe7, // jmp di
];

/// The length (in bytes) of the hlt instruction we use to force a KVM_EXIT
pub const ARCH_INSTR_LEN: u64 = 1;

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
