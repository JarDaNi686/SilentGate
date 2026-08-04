#!/bin/bash
# Build unique binary each time
echo "[QUANTUM] Generating unique binary..."
python3 ~/silentgate/core/quantum_mutate.py \
    ~/silentgate/tests/steal_token_quantum_template.c \
    /tmp/quantum_build.c

x86_64-w64-mingw32-gcc /tmp/quantum_build.c \
    -o ~/silentgate/tests/steal_token_quantum.exe \
    -O2 2>&1

if [ $? -eq 0 ]; then
    md5sum ~/silentgate/tests/steal_token_quantum.exe
    echo "[QUANTUM] Build complete - unique binary ready"
else
    echo "[QUANTUM] Build failed"
fi
