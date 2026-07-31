; ===========================================================
; SilentGate - Indirect Syscall Stub (x64 MASM)
; ===========================================================
; API    : NtProtectVirtualMemory
; SSN    : 80 (0x50)
; Author : JarDani
; License: MIT
;
; HOW THIS WORKS:
;   Normal call path (EDR catches this):
;     Your code -> NtProtectVirtualMemory in ntdll -> [EDR HOOK] -> kernel
;
;   Indirect syscall path (EDR misses this):
;     Your code -> SG_NtProtectVirtualMemory -> loads SSN -> jumps into
;     clean ntdll stub -> syscall executes from ntdll space -> kernel
;
;   The EDR hook sits at the START of NtProtectVirtualMemory in ntdll.
;   We never touch that hooked address.
;   We jump PAST the hook into a clean syscall gadget in ntdll.
; ===========================================================

.code

EXTERN SG_NtProtectVirtualMemory_addr:QWORD  ; address of clean ntdll gadget

SG_NtProtectVirtualMemory PROC
    mov r10, rcx          ; mirror rcx into r10 (Windows x64 ABI)
    mov eax, 50h    ; load SSN 80 into eax
    jmp QWORD PTR [SG_NtProtectVirtualMemory_addr]  ; indirect jump to clean ntdll stub
SG_NtProtectVirtualMemory ENDP

END
