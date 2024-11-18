[bits 16]
[section .text]

; do a hypercall to make the third page as private

mov ax, 12
mov bx, 0x2000
mov cx, 0x2
mov dx, 0x8
vmcall

; copy all code that is past the jmp di instruction to address 0x2000, which
; the above hypercall will have set up to be private memory.

mov bx, 0x0000
mov ds, bx
mov es, bx

; world's worst memcpy

mov di, 0x2000
mov si, .to_copy

mov cx, .end
sub cx, .to_copy

rep movsb

; jump to the code we just moved to private memory

mov di, 0x2000
jmp di

; code that should be moved to private memory and executed from there

.to_copy:
    ; trigger a MMIO write by writing to physical address 0x4000,
    ; which is not backed by any memory on the host (we only allocate 4 pages,
    ; and 0x4000 is the first byte of the fifth page)
    mov di, 0x4000
    mov [cs:di], di

    ; try to enable kvm-clock, and put its control data structure at address 0x3000
    ; we write 0x3001 to the MSR as the lowest bit of the address is interpreted as the
    ; "enable" bit.
    mov ecx, 0x4b564d01
    mov ax, 0x3001
    wrmsr

    ; halt the guest
    hlt
.end: