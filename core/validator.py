"""
SilentGate - core/validator.py
Author  : JarDan
License : MIT
"""

import json
import os
import sys

SUPPORTED_APIS = [
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtOpenProcess"
]

DATA_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "edr_hooks.json"
)

def load_edr_intelligence():
    if not os.path.exists(DATA_PATH):
        print(f"\n[ERROR] Intelligence file not found: {DATA_PATH}")
        sys.exit(1)
    try:
        with open(DATA_PATH, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"\n[ERROR] Failed to parse edr_hooks.json: {e}")
        sys.exit(1)

def validate_api(api_name):
    if not api_name or not api_name.strip():
        print("\n[ERROR] No API name provided.")
        sys.exit(1)
    api_name = api_name.strip()
    if api_name not in SUPPORTED_APIS:
        print(f"\n[ERROR] {api_name} is not a supported API.")
        print("\n[INFO]  Supported APIs:")
        for api in SUPPORTED_APIS:
            print(f"          - {api}")
        sys.exit(1)
    intelligence_db = load_edr_intelligence()
    if api_name not in intelligence_db:
        print(f"\n[ERROR] {api_name} missing from intelligence database.")
        sys.exit(1)
    return {
        "api_name": api_name,
        "intelligence": intelligence_db[api_name]
    }

def list_supported_apis():
    intelligence_db = load_edr_intelligence()
    print("\n  Supported APIs - SilentGate v1.0")
    print("  " + "-" * 60)
    for api in SUPPORTED_APIS:
        data = intelligence_db.get(api, {})
        print(f"\n  [{api}]")
        print(f"  Description : {data.get('description', 'N/A')}")
        print(f"  MITRE       : {data.get('mitre_id', 'N/A')} - {data.get('mitre_name', 'N/A')}")
        print(f"  EDR Hooks   : {data.get('why_edr_hooks', 'N/A')}")
        confidence = data.get("evasion_confidence", {})
        if confidence:
            print(f"  Confidence  : Defender {confidence.get('windows_defender')}%  |  CrowdStrike {confidence.get('crowdstrike_falcon')}%  |  SentinelOne {confidence.get('sentinelone')}%")
    print("\n  " + "-" * 60)

def print_validation_result(validated):
    api = validated["api_name"]
    data = validated["intelligence"]
    print(f"\n  [VALIDATOR] API confirmed : {api}")
    print(f"  [VALIDATOR] Description   : {data['description']}")
    print(f"  [VALIDATOR] Hook location : {data['hook_location']}")
    print(f"\n  [VALIDATOR] Why EDR targets this API:")
    print(f"              {data['why_edr_hooks']}")
    print(f"\n  [VALIDATOR] What EDR checks:")
    for check in data["what_edr_checks"]:
        print(f"              - {check}")
    print(f"\n  [VALIDATOR] Event IDs : {', '.join(data['defender_event_ids'])}")
    print(f"  [VALIDATOR] MITRE     : {data['mitre_id']} - {data['mitre_name']}")
