// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::{
    kvm_create_guest_memfd, kvm_memory_attributes, kvm_userspace_memory_region2,kvm_userspace_memory_region,
    KVM_EXIT_MEMORY_FAULT, KVM_MEMORY_ATTRIBUTE_PRIVATE, KVM_MEMORY_EXIT_FLAG_PRIVATE,
    KVM_MEM_GUEST_MEMFD,
};
#[cfg(target_arch = "x86_64")]
use kvm_ioctls::HypercallExit;
use kvm_ioctls::{Kvm, VcpuExit};
use std::ptr::null_mut;
use std::time::Duration;
use vm_memory::{ReadVolatile, VolatileSlice};

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_arch = "x86_64")]
use x86_64::*;

#[cfg(target_arch = "aarch64")]
use aarch64::*;

// only needed in Firecracker context
/// KVM capability enumerated if the host support private memory
#[allow(unused)]
const KVM_CAP_MEMORY_ATTRIBUTES: u32 = 232;

/// KVM capability enumerated if the host supports guest_memfd
#[allow(unused)]
const KVM_CAP_GUEST_MEMFD: u32 = 234;

/// Guest physical address at which to write the bootstrap instructions (e.g. the code that causes a
/// Hlt instruction to be written to [`crate::HALT_INSTRUCTION`])
const BOOTSTRAP_INSTRUCTIONS: u64 = 0x1000;
// Adapted from https://github.com/rust-vmm/kvm-ioctls/blob/main/src/ioctls/vcpu.rs#L2176
fn main() {
    unsafe {
        const GUEST_MEM_SIZE: u64 = 0x4000; // 4 pages

        /// Guest physical address at which the Hlt instruction will be written.
        const HALT_INSTRUCTION: u64 = 0x2000;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm_with_type(0).unwrap();

        arch_setup_vm(&vm);

        let shared_memory = mmap_anonymous(GUEST_MEM_SIZE as usize);

        let guest_memory = VolatileSlice::new(shared_memory, GUEST_MEM_SIZE as usize);
        ARCH_BOOTSTRAP_CODE
            .as_ref()
            .read_exact_volatile(
                &mut guest_memory
                    .subslice(BOOTSTRAP_INSTRUCTIONS as usize, ARCH_BOOTSTRAP_CODE.len())
                    .unwrap(),
            )
            .unwrap();

        let guest_memfd = if cfg!(feature = "guest_memfd") {
            let guest_memfd = vm
                .create_guest_memfd(kvm_create_guest_memfd {
                    size: GUEST_MEM_SIZE,
                    flags: 0,
                    ..Default::default()
                })
                .unwrap();

            let memory_region = kvm_userspace_memory_region2 {
                slot: 0,
                flags: KVM_MEM_GUEST_MEMFD,
                guest_phys_addr: 0,
                memory_size: GUEST_MEM_SIZE,
                userspace_addr: shared_memory as u64,
                guest_memfd_offset: 0,
                guest_memfd: guest_memfd as u32,
                ..Default::default()
            };

            vm.set_user_memory_region2(memory_region).unwrap();

            guest_memfd
        } else {
            vm.set_user_memory_region(kvm_userspace_memory_region {
                slot: 0,
                flags: 0,
                guest_phys_addr: 0,
                memory_size: GUEST_MEM_SIZE,
                userspace_addr: shared_memory as u64,
            })
            .unwrap();

            0
        };

        let mut vcpu_fd = vm.create_vcpu(0).unwrap();

        arch_setup_vcpu_state(&vm, &vcpu_fd);

        if cfg!(feature = "mmap") {
            println!("guest_memfd: {}", guest_memfd);
            let mapped_guest_memfd = libc::mmap(
                null_mut(),
                0x1000,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                guest_memfd,
                0x2000,
            );

            if mapped_guest_memfd == libc::MAP_FAILED {
                panic!(
                    "Failed to mmap guest_memfd: {:?}",
                    std::io::Error::last_os_error()
                );
            }
            println!(
                "Mapped guest_memfd into userspace at address {0:p}",
                mapped_guest_memfd
            );

            // Need to unmap the memory from userspace again, otherwise setting the attribute of the
            // mapped pages to private will result in EPERM.
            assert_eq!(libc::munmap(mapped_guest_memfd, 0x1000), 0);
            println!("Unmapped guest_memfd again!");
        }

        if cfg!(target_arch = "aarch64") && cfg!(feature = "guest_memfd") {
            vm.set_memory_attributes(kvm_memory_attributes {
                address: 0x2000,
                size: 0x1000,
                attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE as u64,
                ..Default::default()
            })
            .unwrap();
        }

        println!("Press enter to continue");
        std::io::stdin().read_line(&mut String::new()).unwrap();

        // Give it a handful of tries
        for _ in 0..5 {
            match vcpu_fd.run() {
                // Hlt on x86_64, SystemEvent on aarch64
                Ok(VcpuExit::Hlt) | Ok(VcpuExit::SystemEvent(1, [0])) => {
                    // we expect it to immediately HLT
                    println!("Halted!");

                    // Check we actually halted at the expected location
                    assert_eq!(
                        arch_get_program_counter(&vcpu_fd),
                        HALT_INSTRUCTION + ARCH_INSTR_LEN
                    );

                    if cfg!(feature = "guest_memfd") {
                        // Yeet the private page (to test that we can punch holes with guest_memfd removed
                        // from the direct map).
                        let ret = libc::fallocate(
                            guest_memfd,
                            libc::FALLOC_FL_KEEP_SIZE | libc::FALLOC_FL_PUNCH_HOLE,
                            0x2000,
                            0x1000,
                        );
                        assert_eq!(ret, 0);
                        println!("Yeeted private memory!");
                    }

                    std::thread::sleep(Duration::from_secs(2));

                    println!("Goodbye!");

                    return;
                }
                #[cfg(target_arch = "x86_64")]
                Ok(VcpuExit::Hypercall(HypercallExit { nr, args, .. })) => {
                    println!("Hypercall #{}!", nr);

                    if nr == KVM_HC_MAP_GPA_RANGE && cfg!(feature = "guest_memfd") {
                        let [addr, num_pages, attributes, ..] = args;
                        let attrs = kvm_memory_attributes {
                            address: addr,
                            size: 0x1000 * num_pages,
                            attributes: attributes & KVM_MEMORY_ATTRIBUTE_PRIVATE as u64,
                            ..Default::default()
                        };

                        vm.set_memory_attributes(attrs).unwrap();
                    }
                }
                Err(error) if error.errno() == libc::EFAULT => {
                    let run = vcpu_fd.get_kvm_run();
                    if run.exit_reason == KVM_EXIT_MEMORY_FAULT {
                        let payload = run.__bindgen_anon_1.memory_fault;
                        if payload.flags == KVM_MEMORY_EXIT_FLAG_PRIVATE as u64 {
                            panic!(
                                "Got private memory fault at {:#x} of length {:#x} while executing instruction at {:#x}",
                                payload.gpa, payload.size, arch_get_program_counter(&vcpu_fd)
                            )
                        } else {
                            panic!(
                                "Got shared memory fault at {:#x} of length {:#x}",
                                payload.gpa, payload.size
                            )
                        }
                    }
                }
                r => {
                    let fmt = format!("{:?}", r); /* borrowchk */
                    panic!(
                        "unexpected exit reason: {} at {:x}",
                        fmt,
                        arch_get_program_counter(&vcpu_fd)
                    );
                }
            }
        }

        panic!("Did not manage to halt within 5 KVM_RUN calls :(");
    }
}

fn mmap_anonymous(size: usize) -> *mut u8 {
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
