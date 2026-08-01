"""
SilentGate - GENE 1: Payload Ingester
INPUT  : raw payload (file path, hex string, or bytes)
OUTPUT : numpy uint8 array + metadata dict
CONTRACT: output feeds directly into GENE 2 dft_encoder.py
"""

import numpy as np
import json
import os
import hashlib


def ingest(source, source_type="file"):
    """
    Ingest payload from multiple sources.
    
    source_type options:
      "file"   : path to binary file
      "hex"    : hex string e.g. "4c8bd1b818000000"
      "bytes"  : raw Python bytes object
    
    Returns:
      payload_array : np.ndarray of dtype uint8
      metadata      : dict with integrity + provenance info
    """

    if source_type == "file":
        if not os.path.exists(source):
            raise FileNotFoundError(f"Payload file not found: {source}")
        with open(source, "rb") as f:
            raw = f.read()

    elif source_type == "hex":
        raw = bytes.fromhex(source.replace(" ", "").replace("\\x", ""))

    elif source_type == "bytes":
        raw = source if isinstance(source, bytes) else bytes(source)

    else:
        raise ValueError(f"Unknown source_type: {source_type}")

    if len(raw) == 0:
        raise ValueError("Payload is empty")

    payload_array = np.frombuffer(raw, dtype=np.uint8).copy()

    metadata = {
        "gene":          1,
        "output_contract": "np.ndarray uint8 -> GENE2 dft_encoder",
        "size_bytes":    len(raw),
        "size_elements": len(payload_array),
        "sha256":        hashlib.sha256(raw).hexdigest(),
        "dtype":         str(payload_array.dtype),
        "min_byte":      int(payload_array.min()),
        "max_byte":      int(payload_array.max()),
        "mean_byte":     float(payload_array.mean()),
        "source_type":   source_type,
    }

    return payload_array, metadata


def validate_output(payload_array, metadata):
    """Validate GENE 1 output before passing to GENE 2."""
    assert isinstance(payload_array, np.ndarray), "Must be numpy array"
    assert payload_array.dtype == np.uint8,        "Must be uint8"
    assert len(payload_array) > 0,                 "Must not be empty"
    assert metadata["sha256"] is not None,          "Must have integrity hash"
    return True


def save_metadata(metadata, path="output/gene1_metadata.json"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(metadata, f, indent=2)


if __name__ == "__main__":
    # Test with our existing custom shellcode
    test_payload = bytes([
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20,
        0x48, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0x48, 0x83,
        0xC4, 0x28, 0xC3
    ])

    arr, meta = ingest(test_payload, source_type="bytes")
    validate_output(arr, meta)
    save_metadata(meta, "output/gene1_metadata.json")

    print(f"[GENE 1] INPUT  : {len(test_payload)} raw bytes")
    print(f"[GENE 1] OUTPUT : numpy uint8 array shape={arr.shape}")
    print(f"[GENE 1] SHA256 : {meta['sha256'][:32]}...")
    print(f"[GENE 1] READY  : output contracts validated -> GENE 2")
