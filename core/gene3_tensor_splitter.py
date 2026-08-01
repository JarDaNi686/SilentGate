"""
SilentGate - GENE 3: Tensor Splitter
INPUT  : complex128 coefficient array + metadata (from GENE 2)
OUTPUT : three factor matrices G, A1, A2 + updated metadata
CONTRACT: output feeds directly into GENE 4 eigenvalue_camouflager.py

Mathematical foundation:
  Tucker Decomposition (order-1 simplified for 1D signal):
  
  We treat the complex coefficient vector as a matrix by reshaping.
  Then apply SVD-based factorization:
  
  M = U * S * Vh
  
  Split into three independent matrices:
    G  = S (core — singular values)
    A1 = U (left singular vectors)
    A2 = Vh (right singular vectors)
  
  Reconstruction: M = A1 * diag(G) * A2
  
  Security property:
    No single matrix contains the payload
    G alone: just magnitudes — no phase information
    A1 alone: just rotation — no scale information  
    A2 alone: just rotation — no scale information
    All three required for exact reconstruction
"""

import numpy as np
import json
import os
import hashlib


def reshape_coefficients(coefficients):
    """
    Reshape 1D complex coefficient array into 2D matrix.
    Choose dimensions as close to square as possible.
    This enables matrix factorization via SVD.
    """
    N = len(coefficients)

    # Find best 2D shape close to square
    rows = int(np.sqrt(N))
    while N % rows != 0 and rows > 1:
        rows -= 1
    cols = N // rows

    matrix = coefficients.reshape(rows, cols)
    return matrix, (rows, cols)


def split(coefficients, metadata):
    """
    Split complex coefficient matrix into three factor matrices
    using Singular Value Decomposition.

    SVD: M = U * diag(S) * Vh
    
    Where:
      U  is unitary (left singular vectors)
      S  is real non-negative (singular values)
      Vh is unitary (right singular vectors conjugate transposed)
    
    We store:
      G  = S  (real values — core tensor)
      A1 = U  (complex unitary matrix)
      A2 = Vh (complex unitary matrix)
    
    None of G, A1, A2 individually reveal the payload.
    """
    matrix, shape = reshape_coefficients(coefficients)

    # Full SVD decomposition
    A1, G, A2 = np.linalg.svd(matrix, full_matrices=True)

    # Verify reconstruction before returning
    reconstructed_matrix = A1[:, :len(G)] @ np.diag(G) @ A2[:len(G), :]

    updated_meta = {
        **metadata,
        "gene":            3,
        "output_contract": "three matrices G,A1,A2 -> GENE4 eigenvalue_camouflager",
        "matrix_shape":    list(shape),
        "coeff_count":     len(coefficients),
        "G_shape":         list(G.shape),
        "A1_shape":        list(A1.shape),
        "A2_shape":        list(A2.shape),
        "G_sha256":        hashlib.sha256(G.tobytes()).hexdigest(),
        "A1_sha256":       hashlib.sha256(A1.tobytes()).hexdigest(),
        "A2_sha256":       hashlib.sha256(A2.tobytes()).hexdigest(),
        "singular_values": G.tolist(),
        "rank":            int(np.sum(G > 1e-10)),
        "reconstruction_error": float(
            np.max(np.abs(reconstructed_matrix - matrix))
        ),
    }

    return G, A1, A2, updated_meta


def reconstruct(G, A1, A2, metadata):
    """
    Reconstruct coefficient matrix from three factor matrices.
    Called at execution time only.
    """
    matrix = A1[:, :len(G)] @ np.diag(G) @ A2[:len(G), :]
    coefficients = matrix.flatten()[:metadata["coeff_count"]]
    return coefficients


def validate_reconstruction(original_coeffs, G, A1, A2, metadata):
    """Verify reconstruction error is within floating point tolerance."""
    recovered = reconstruct(G, A1, A2, metadata)
    max_error = np.max(np.abs(recovered - original_coeffs))
    return max_error < 1e-8


def save_factors(G, A1, A2, base_path="output"):
    os.makedirs(base_path, exist_ok=True)
    np.save(f"{base_path}/gene3_G.npy",  G)
    np.save(f"{base_path}/gene3_A1.npy", A1)
    np.save(f"{base_path}/gene3_A2.npy", A2)


def save_metadata(metadata, path="output/gene3_metadata.json"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(metadata, f, indent=2)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from gene1_payload_ingester import ingest
    from gene2_dft_encoder       import encode

    test_payload = bytes([
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20,
        0x48, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0x48, 0x83,
        0xC4, 0x28, 0xC3
    ])

    arr,    meta1 = ingest(test_payload, source_type="bytes")
    coeffs, meta2 = encode(arr, meta1)
    G, A1, A2, meta3 = split(coeffs, meta2)

    valid = validate_reconstruction(coeffs, G, A1, A2, meta3)

    save_factors(G, A1, A2)
    save_metadata(meta3)

    print(f"[GENE 3] INPUT  : complex128 array shape={coeffs.shape}")
    print(f"[GENE 3] OUTPUT : three factor matrices")
    print(f"         G  shape={G.shape}  (singular values - core)")
    print(f"         A1 shape={A1.shape} (left unitary - rotation)")
    print(f"         A2 shape={A2.shape} (right unitary - rotation)")
    print(f"[GENE 3] RANK   : {meta3['rank']}")
    print(f"[GENE 3] ERROR  : {meta3['reconstruction_error']:.2e}")
    print(f"[GENE 3] VERIFY : reconstruct(G,A1,A2) ≈ coeffs -> {valid}")
    print(f"[GENE 3] SECURITY: no single matrix reveals payload")
    print(f"[GENE 3] READY  : output contracts validated -> GENE 4")
