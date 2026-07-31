# Custom MessageBox shellcode generator
# Not from msfvenom - no known signatures
# Hand crafted x64 Windows shellcode

shellcode = bytearray([
    # Load kernel32 via PEB walk
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,  # mov rax, gs:[0x60]
    0x48, 0x8B, 0x40, 0x18,                                  # mov rax, [rax+0x18]
    0x48, 0x8B, 0x40, 0x20,                                  # mov rax, [rax+0x20]
    0x48, 0x8B, 0x00,                                        # mov rax, [rax]
    0x48, 0x8B, 0x00,                                        # mov rax, [rax]
    0x48, 0x8B, 0x40, 0x20,                                  # mov rax, [rax+0x20]
    # For lab purposes - just execute a clean INT3 + RET
    # This proves execution without triggering signatures
    0x90, 0x90, 0x90, 0x90, 0x90,                           # NOP sled
    0xCC,                                                     # INT3 (breakpoint)
    0xC3                                                      # RET
])

# Output as C array
print("unsigned char buf[] = {")
hex_bytes = ", ".join([f"0x{b:02X}" for b in shellcode])
print(f"    {hex_bytes}")
print("};")
print(f"// Size: {len(shellcode)} bytes")
