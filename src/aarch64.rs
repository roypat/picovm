// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::BOOTSTRAP_INSTRUCTIONS;
use kvm_bindings::{
    kvm_regs, kvm_vcpu_init, user_pt_regs, KVM_ARM_VCPU_PSCI_0_2, KVM_REG_ARM64, KVM_REG_ARM_CORE,
    KVM_REG_SIZE_U64,
};
use kvm_ioctls::{VcpuFd, VmFd};
use std::mem::offset_of;

#[rustfmt::skip]
pub const ARCH_BOOTSTRAP_CODE: [u8; 28] = [
    0x01, 0x00, 0x84, 0xD2,  // mov x1, #0x2000            ; address to which we write the HVC #0x0 instruction
    0x42, 0x00, 0x80, 0x52,  // mov w2, #0x0002            ; Load lower 16 bits of hvc #0x0 instruction into x1
    0x02, 0x80, 0xBA, 0x72,  // movk w2, #0xd400, lsl #16  ; Load upper 16 bits of hvc #0x0 instruction (closest equivalent to HLT on x86) into x2 reg, leaving lower bits untouched
    0x22, 0x00, 0x00, 0xF9,  // str x2, [x1]               ; store value of x1 register (hvc #0x0 instruction opcode) to address stored in x1 register
    0x00, 0x80, 0xB0, 0x52,  // mov w0, #0x84000000        ; Prepare x0 register with hypercall code for preparing a system exit
    0x00, 0x00, 0x1D, 0x32,  // orr w0, w0, #8
    0x20, 0x00, 0x1F, 0xD6,  // br x1                      ; unconditional jump to address stored in x1 register
];

/// The length (in bytes) of the hvc #0x0 instruction we use to force a KVM_EXIT
pub const ARCH_INSTR_LEN: u64 = 4;

/// Gets a core id.
macro_rules! arm64_core_reg_id {
    ($size: ident, $offset: expr) => {
        // The core registers of an arm64 machine are represented
        // in kernel by the `kvm_regs` structure. This structure is a
        // mix of 32, 64 and 128 bit fields:
        // struct kvm_regs {
        //     struct user_pt_regs      regs;
        //
        //     __u64                    sp_el1;
        //     __u64                    elr_el1;
        //
        //     __u64                    spsr[KVM_NR_SPSR];
        //
        //     struct user_fpsimd_state fp_regs;
        // };
        // struct user_pt_regs {
        //     __u64 regs[31];
        //     __u64 sp;
        //     __u64 pc;
        //     __u64 pstate;
        // };
        // The id of a core register can be obtained like this:
        // offset = id & ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_ARM_CORE). Thus,
        // id = KVM_REG_ARM64 | KVM_REG_SIZE_U64/KVM_REG_SIZE_U32/KVM_REG_SIZE_U128 |
        // KVM_REG_ARM_CORE | offset
        KVM_REG_ARM64 as u64
            | KVM_REG_ARM_CORE as u64
            | $size
            | ($offset / std::mem::size_of::<u32>()) as u64
    };
}

pub const PC: u64 = {
    let kreg_off = offset_of!(kvm_regs, regs);
    let pc_off = offset_of!(user_pt_regs, pc);
    arm64_core_reg_id!(KVM_REG_SIZE_U64, kreg_off + pc_off)
};

pub fn arch_setup_vm(_vm_fd: &VmFd) {}

pub fn arch_setup_vcpu_state(vm_fd: &VmFd, vcpu_fd: &VcpuFd) {
    let mut kvi = kvm_vcpu_init::default();
    vm_fd.get_preferred_target(&mut kvi).unwrap();
    kvi.features[0] |= 1 << KVM_ARM_VCPU_PSCI_0_2;
    vcpu_fd.vcpu_init(&kvi).unwrap();

    let kreg_off = offset_of!(kvm_regs, regs);
    let pc = offset_of!(user_pt_regs, pc) + kreg_off;
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, pc);
    vcpu_fd
        .set_one_reg(id, &BOOTSTRAP_INSTRUCTIONS.to_ne_bytes())
        .unwrap();
}

pub fn arch_get_program_counter(vcpu_fd: &VcpuFd) -> u64 {
    let mut buf = [0u8; 8];
    vcpu_fd.get_one_reg(PC, buf.as_mut_slice()).unwrap();
    u64::from_ne_bytes(buf)
}
