; 
; Compile .bin 
; nasm -f win64 cal.asm -o calc_basic.obj
; objcopy -O binary --only-section=.text calc64.obj calc64.bin
; Compile .exe 
; x86_64-w64-mingw32-gcc calc_basic.obj -o calc_basic.exe
; Check shellcode xxd -i calc64_fixed.bin
; 

[BITS 64]
global main
extern system

section .data
    cmd db "calc.exe", 0

section .text
main:
    sub     rsp, 0x28           ; shadow space
    lea     rcx, [rel cmd]      ; arg1 = "calc.exe"
    call    system
    add     rsp, 0x28
    xor     eax, eax
    ret