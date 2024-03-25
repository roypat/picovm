// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::{kvm_enable_cap, kvm_userspace_memory_region, KVMIO};
use kvm_ioctls::{Kvm, VcpuExit};
use std::ptr::null_mut;
use std::time::Duration;
use vm_memory::{ReadVolatile, VolatileSlice};
use vmm_sys_util::ioctl::{ioctl_with_ref, ioctl_with_val};
use vmm_sys_util::syscall::SyscallReturnCode;
use vmm_sys_util::{ioctl_io_nr, ioctl_ioc_nr, ioctl_iow_nr, ioctl_iowr_nr};

/// KVM_EXIT reason if a memory fault was detected that KVM could not resolve,
/// e.g. if a private fault happened, but the memory region does not support private
/// page frames.
const KVM_EXIT_MEMORY_FAULT: u32 = 38;

/// KVM_EXIT_MEMORY_FAULT bit flag that indicates the fault happened on a private memory access
const KVM_MEMORY_EXIT_FLAG_PRIVATE: u64 = 1 << 3;

/// structure describing the shape of a memory access that caused a KVM_EXIT_MEMORY_FAULT
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct memory {
    flags: u64,
    gpa: u64,
    size: u64,
}

/// Bitflag to mark a specific (range of) page frame(s) as private
const KVM_MEMORY_ATTRIBUTE_PRIVATE: u64 = 1u64 << 3;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct kvm_memory_attributes {
    address: u64,
    size: u64,
    attributes: u64,
    flags: u64,
}

/// VM ioctl used to mark guest page frames as shared/private
ioctl_iow_nr!(
    KVM_SET_MEMORY_ATTRIBUTES,
    KVMIO,
    0xd2,
    kvm_memory_attributes
);

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct kvm_create_guest_memfd {
    size: u64,
    flags: u64,
    reserved: [u64; 6],
}

/// ioctl to create a guest_memfd. Has to be executed on a vm fd, to which
/// the returned guest_memfd will be bound (e.g. it can only be used to back
/// memory in that specific VM).
ioctl_iowr_nr!(KVM_CREATE_GUEST_MEMFD, KVMIO, 0xd4, kvm_create_guest_memfd);

/// Flag passed to [`KVM_SET_USER_MEMORY_REGION2`] to indicate that a region supports
/// private memory.
const KVM_MEM_PRIVATE: u32 = 1 << 2;

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

/// VM ioctl for registering memory regions that have a guest_memfd associated with them
ioctl_iow_nr!(
    KVM_SET_USER_MEMORY_REGION2,
    KVMIO,
    0x49,
    kvm_userspace_memory_region2
);

/// Hypercall number
const KVM_HC_MAP_GPA_RANGE: u64 = 12;

/// KVM capability gatekeeping the ability to have specific hypercalls
/// exit to host userspace to be handled.
const KVM_CAP_EXIT_HYPERCALL: u32 = 201;

// only needed in Firecracker context
/// KVM capability enumerated if the host support private memory
#[allow(unused)]
const KVM_CAP_MEMORY_ATTRIBUTES: u32 = 232;

/// KVM capability enumerated if the host supports guest_memfd
#[allow(unused)]
const KVM_CAP_GUEST_MEMFD: u32 = 234;

// VM ioctl for checking support for a specific capability
ioctl_io_nr!(KVM_CHECK_EXTENSION, KVMIO, 0x03);

/// VM type that supports guest private memory
const KVM_X86_SW_PROTECTED_VM: u64 = 1;

// Adapted from https://github.com/rust-vmm/kvm-ioctls/blob/main/src/ioctls/vcpu.rs#L2176
fn main() {
    const GUEST_MEM_SIZE: u64 = 0x4000; // 4 pages
    /// Guest physical address at which to write the bootstrap instructions (e.g. the code that causes a
    /// Hlt instruction to be written to [`HALT_INSTRUCTION`])
    const BOOTSTRAP_INSTRUCTIONS: u64 = 0x1000;

    /// Guest physical address at which the Hlt instruction will be written.
    const HALT_INSTRUCTION: u64 = 0x2000;

    let kvm = Kvm::new().unwrap();
    let mut vm = kvm.create_vm_with_type(KVM_X86_SW_PROTECTED_VM).unwrap();

    // To be able to dynamically map memory in response to a [`KVM_HC_MAP_GPA_RANGE`], we need
    // to tell KVM that it should exit to host userspace when it receives one of these.
    // For simplicity, make it exit to host userspace on any hypercall that supports this.
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
        //0xbb, 0xf4, 0x00, // mov bx, 0xf4
        //0x2e, 0x89, 0x1d, // mov [cs:di], bx
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

    println!("guest_memfd: {}", guest_memfd);
    let mapped_guest_memfd = unsafe {
        libc::mmap(
            null_mut(),
            0x1000,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            guest_memfd,
            0x2000,
        )
    };

    if mapped_guest_memfd == libc::MAP_FAILED {
        panic!("Failed to mmap guest_memfd: {:?}", std::io::Error::last_os_error());
    }
    println!("Mapped guest_memfd into userspace at address {0:p}", mapped_guest_memfd);

    // Write HLT instruction to start of third page (the guest will jump to the start of the third page after the hypercall).
    unsafe {
        std::ptr::write_volatile(mapped_guest_memfd as _, 0xf4u8);
    }
    println!("Wrote HLT instruction to start of third page");

    // Need to unmap the memory from userspace again, otherwise setting the attribute of the
    // mapped pages to private will result in EPERM.
    unsafe {
        assert_eq!(libc::munmap(mapped_guest_memfd, 0x1000), 0);
    }
    println!("Unmapped guest_memfd again!");

    println!("Press enter to continue");
    std::io::stdin().read_line(&mut String::new()).unwrap();

    // Give it a handful of tries
    for _ in 0..5 {
        match vcpu_fd.run() {
            Ok(VcpuExit::Hlt) => {
                // we expect it to immediately HLT
                println!("Halted!");

                // Check we actually halted at the expected location
                let vcpu_regs = vcpu_fd.get_regs().unwrap();
                assert_eq!(vcpu_regs.rip, HALT_INSTRUCTION + 1);

                // Yeet the private page (to test that we can punch holes with guest_memfd removed
                // from the direct map).
                unsafe {
                    let ret = libc::fallocate(
                        guest_memfd,
                        libc::FALLOC_FL_KEEP_SIZE | libc::FALLOC_FL_PUNCH_HOLE,
                        0x2000,
                        0x1000,
                    );
                    assert_eq!(ret, 0);
                }
                println!("Yeeted private memory!");

                std::thread::sleep(Duration::from_secs(2));

                println!("Goodbye!");

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
