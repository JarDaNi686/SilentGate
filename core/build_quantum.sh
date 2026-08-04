#!/bin/bash
# SilentGate - Quantum Pattern Mutator Build Script
# Author: JarDani
# Generates unique binary signature every build

TEMPLATE="$HOME/silentgate/tests/steal_token.c"
OUTPUT="$HOME/silentgate/tests/steal_token_quantum.exe"

echo "[QUANTUM] Generating unique binary..."
python3 "$HOME/silentgate/core/quantum_mutate.py" \
    "$TEMPLATE" \
    /tmp/quantum_build.c

x86_64-w64-mingw32-gcc /tmp/quantum_build.c \
    -o "$OUTPUT" -O2 -mwindows 2>&1

if [ $? -eq 0 ]; then
    md5sum "$OUTPUT"
    echo "[QUANTUM] Build complete - unique binary ready"
else
    echo "[QUANTUM] Build failed"
fi
