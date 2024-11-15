[bits 16]
[section .text]

; do a hypercall to make the third page as private

mov ax, 12
mov bx, 0x2000
mov cx, 0x1
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

.loop:
    movsb

    cmp si, .end
    jne .loop

; jump to the code we just moved to private memory

mov di, 0x2000
jmp di

; code that should be moved to private memory and executed from there
; first, trigger mmio write by accessing physical address 0x4000, which
; is not backed by any guest memory (we only allocate 3 pages).
; then, halt.

.to_copy:
    mov di, 0x4000
    mov [cs:di], di

    hlt
.end: