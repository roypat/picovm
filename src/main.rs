// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::{kvm_enable_cap, kvm_userspace_memory_region, KVMIO};
use kvm_ioctls::{Kvm, VcpuExit};
use vm_memory::{ReadVolatile, VolatileSlice};
use vmm_sys_util::ioctl::{ioctl_with_ref, ioctl_with_val};
use vmm_sys_util::syscall::SyscallReturnCode;
use vmm_sys_util::{ioctl_io_nr, ioctl_ioc_nr, ioctl_iow_nr, ioctl_iowr_nr};

const KVM_EXIT_MEMORY_FAULT: u32 = 38;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct kvm_memory_attributes {
    address: u64,
    size: u64,
    attributes: u64,
    flags: u64,
}

/// Hypercall uses to mark guest page frames as shared/private
ioctl_iow_nr!(
    KVM_SET_MEMORY_ATTRIBUTES,
    KVMIO,
    0xd2,
    kvm_memory_attributes
);

///
const KVM_MEM_PRIVATE: u32 = 1 << 2;
const KVM_MEMORY_ATTRIBUTE_PRIVATE: u64 = 1u64 << 3;

const KVM_CAP_EXIT_HYPERCALL: u32 = 201;
// only needed in Firecracker context
#[allow(unused)]
const KVM_CAP_MEMORY_ATTRIBUTES: u32 = 232;
#[allow(unused)]
const KVM_CAP_GUEST_MEMFD: u32 = 234;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct kvm_create_guest_memfd {
    size: u64,
    flags: u64,
    reserved: [u64; 6],
}

ioctl_iowr_nr!(KVM_CREATE_GUEST_MEMFD, KVMIO, 0xd4, kvm_create_guest_memfd);

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct kvm_userspace_memory_region2 {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    guest_memfd_offset: u64,
    guest_memfd: u32,
    pad1: u32,
    pad2: [u64; 14],
}

ioctl_iow_nr!(
    KVM_SET_USER_MEMORY_REGION2,
    KVMIO,
    0x49,
    kvm_userspace_memory_region2
);

ioctl_io_nr!(KVM_CHECK_EXTENSION, KVMIO, 0x03);

const KVM_MEMORY_EXIT_FLAG_PRIVATE: u64 = 1 << 3;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct memory {
    flags: u64,
    gpa: u64,
    size: u64,
}

const KVM_HC_MAP_GPA_RANGE: u64 = 12;

const KVM_X86_SW_PROTECTED_VM: u64 = 1;

// Adapted from https://github.com/rust-vmm/kvm-ioctls/blob/main/src/ioctls/vcpu.rs#L2176
fn main() {
    const GUEST_MEM_SIZE: u64 = 0x4000; // 4 pages
    const BOOTSTRAP_INSTRUCTIONS: u64 = 0x1000;

    const HALT_INSTRUCTION: u64 = 0x2000;

    let kvm = Kvm::new().unwrap();
    let mut vm = kvm.create_vm_with_type(KVM_X86_SW_PROTECTED_VM).unwrap()

    let exitable_hypercalls =
        unsafe { ioctl_with_val(&vm, KVM_CHECK_EXTENSION(), KVM_CAP_EXIT_HYPERCALL as u64) };
    assert!(exitable_hypercalls > 0);
    vm.enable_cap(&kvm_enable_cap {
        cap: KVM_CAP_EXIT_HYPERCALL,
        args: [exitable_hypercalls as u64, 0, 0, 0],
        ..Default::default()
    })
    .unwrap();

    /*
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
    let bootstrap_code = [
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

    let shared_memory = mmap_anonymous(GUEST_MEM_SIZE as usize);

    unsafe {
        let guest_memory = VolatileSlice::new(shared_memory, GUEST_MEM_SIZE as usize);
        bootstrap_code
            .as_ref()
            .read_exact_volatile(
                &mut guest_memory
                    .subslice(BOOTSTRAP_INSTRUCTIONS as usize, bootstrap_code.len())
                    .unwrap(),
            )
            .unwrap();
    }

    let guest_memfd = SyscallReturnCode(unsafe {
        ioctl_with_ref(
            &vm,
            KVM_CREATE_GUEST_MEMFD(),
            &kvm_create_guest_memfd {
                size: GUEST_MEM_SIZE,
                flags: 0,
                ..Default::default()
            },
        )
    })
    .into_result()
    .unwrap();

    let memory_region = kvm_userspace_memory_region2 {
        slot: 0,
        flags: KVM_MEM_PRIVATE,
        guest_phys_addr: 0,
        memory_size: GUEST_MEM_SIZE,
        userspace_addr: shared_memory as u64,
        guest_memfd_offset: 0,
        guest_memfd: guest_memfd as u32,
        ..Default::default()
    };

    SyscallReturnCode(unsafe {
        ioctl_with_ref(&vm, KVM_SET_USER_MEMORY_REGION2(), &memory_region)
    })
    .into_empty_result()
    .unwrap();

    let mut vcpu_fd = vm.create_vcpu(0).unwrap();
    let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

    let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
    // Set the Instruction Pointer to the guest address where we loaded the code.
    vcpu_regs.rip = BOOTSTRAP_INSTRUCTIONS;
    vcpu_regs.rax = 2;
    vcpu_regs.rbx = 3;
    vcpu_regs.rflags = 2;
    vcpu_fd.set_regs(&vcpu_regs).unwrap();

    // Give it a handful of tries
    for _ in 0..5 {
        match vcpu_fd.run() {
            Ok(VcpuExit::Hlt) => {
                // we expect it to immediately HLT
                println!("Halted!");

                // Check we actually halted at the expected location
                let vcpu_regs = vcpu_fd.get_regs().unwrap();
                assert_eq!(vcpu_regs.rip, HALT_INSTRUCTION + 1);

                return;
            }
            Ok(VcpuExit::Hypercall) => {
                let run = vcpu_fd.get_kvm_run();
                let hypercall = unsafe { run.__bindgen_anon_1.hypercall };

                println!("Hypercall #{}!", hypercall.nr);

                if hypercall.nr == KVM_HC_MAP_GPA_RANGE {
                    let [addr, num_pages, attributes, ..] = hypercall.args;
                    let attrs = kvm_memory_attributes {
                        address: addr,
                        size: 0x1000 * num_pages,
                        attributes: attributes & KVM_MEMORY_ATTRIBUTE_PRIVATE,
                        ..Default::default()
                    };

                    unsafe {
                        SyscallReturnCode(ioctl_with_ref(&vm, KVM_SET_MEMORY_ATTRIBUTES(), &attrs))
                            .into_result()
                            .unwrap();
                    }
                }
            }
            Err(error) if error.errno() == libc::EFAULT => {
                let vcpu_regs = vcpu_fd.get_regs().unwrap();
                let run = vcpu_fd.get_kvm_run();
                if run.exit_reason == KVM_EXIT_MEMORY_FAULT {
                    let payload =
                        unsafe { std::mem::transmute_copy::<_, memory>(&run.__bindgen_anon_1) };
                    match payload.flags {
                        KVM_MEMORY_EXIT_FLAG_PRIVATE => panic!(
                            "Got private memory fault at {:#x} of length {:#x} while executing instruction at {:#x}",
                            payload.gpa, payload.size, vcpu_regs.rip
                        ),
                        _ => panic!(
                            "Got shared memory fault at {:#x} of length {:#x}",
                            payload.gpa, payload.size
                        ),
                    }
                }
            }
            r => {
                let vcpu_regs = vcpu_fd.get_regs().unwrap();
                panic!("unexpected exit reason: {:?} at {}", r, vcpu_regs.rip);
            }
        }
    }

    panic!("Did not manage to halt within 5 KVM_RUN calls :(");
}

fn mmap_anonymous(size: usize) -> *mut u8 {
    use std::ptr::null_mut;

    let addr = unsafe {
        libc::mmap(
            null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        panic!("mmap failed.");
    }

    addr as *mut u8
}
