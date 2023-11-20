[bits 16]
[section .text]
mov ax, 12
mov bx, 0x2000
mov cx, 0x1
mov dx, 0x8
vmcall
mov di, 0x2000
mov bx, 0xf4
mov [cs:di], bx
jmp di
