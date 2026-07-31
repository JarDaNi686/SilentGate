"""
SilentGate - core/intelligence.py
Step 5 of the pipeline: Confidence Rating + Defender Perspective

Author  : JarDani
License : MIT
Purpose : Analyses the generated stub and produces:
          1. Evasion confidence rating per EDR product
          2. What would still catch this technique
          3. Defender perspective - what to monitor
          4. MITRE ATT&CK mapping
          5. Suggested improvements
"""

import json
import os

MITRE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "mitre_mapping.json"
)

EDR_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "edr_hooks.json"
)


def load_mitre_data():
    if not os.path.exists(MITRE_PATH):
        return {}
    try:
        with open(MITRE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def load_edr_data():
    if not os.path.exists(EDR_PATH):
        return {}
    try:
        with open(EDR_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def get_confidence_label(score):
    """Convert numeric score to human readable label."""
    if score >= 80:
        return "HIGH"
    elif score >= 60:
        return "MEDIUM"
    elif score >= 40:
        return "LOW"
    else:
        return "VERY LOW"


def get_confidence_bar(score, width=20):
    """Generate ASCII progress bar for confidence score."""
    filled = int((score / 100) * width)
    empty  = width - filled
    bar    = "█" * filled + "░" * empty
    return bar


def analyse_confidence(api_name, edr_data):
    """
    Analyse evasion confidence for the given API
    against known EDR products.
    Returns structured confidence data.
    """
    api_intel   = edr_data.get(api_name, {})
    confidence  = api_intel.get("evasion_confidence", {})

    defender    = confidence.get("windows_defender", 0)
    crowdstrike = confidence.get("crowdstrike_falcon", 0)
    sentinelone = confidence.get("sentinelone", 0)
    explanation = confidence.get("explanation", "")

    # Calculate overall average
    overall = int((defender + crowdstrike + sentinelone) / 3)

    return {
        "windows_defender":  defender,
        "crowdstrike_falcon": crowdstrike,
        "sentinelone":       sentinelone,
        "overall":           overall,
        "explanation":       explanation
    }


def get_remaining_risks(api_name, edr_data):
    """
    Identify what would still catch this technique
    even with indirect syscalls applied.
    These are the honest limitations of the approach.
    """
    risks = [
        {
            "risk": "Kernel ETW callbacks",
            "detail": "Windows kernel registers callbacks for process and thread operations. These fire at kernel level regardless of how the syscall was invoked. Indirect syscalls bypass user-mode hooks but do not silence kernel callbacks.",
            "severity": "HIGH"
        },
        {
            "risk": "Behavioural correlation",
            "detail": f"Advanced EDRs track sequences of API calls. If {api_name} is called as part of a known injection chain (Allocate -> Write -> Protect -> CreateThread), the pattern itself triggers detection even when each individual call bypasses hooks.",
            "severity": "HIGH"
        },
        {
            "risk": "Call stack analysis",
            "detail": "Some EDRs inspect the return address on the call stack after a syscall. If the return address points outside a known module, it flags as suspicious. Our stub mitigates this but does not fully solve call stack spoofing.",
            "severity": "MEDIUM"
        },
        {
            "risk": "Memory scanning",
            "detail": "EDR products periodically scan process memory for shellcode signatures, high entropy regions, and RWX memory pages. Indirect syscalls do not affect what is written into memory.",
            "severity": "MEDIUM"
        },
        {
            "risk": "Syscall instruction location",
            "detail": "Newer EDRs monitor WHERE the syscall instruction executes from. If it executes from outside ntdll address range, it is flagged. Our gadget finder ensures execution from ntdll, but this must be verified per target.",
            "severity": "LOW"
        }
    ]
    return risks


def get_defender_perspective(api_name, edr_data):
    """
    What a blue teamer needs to detect this technique.
    This is the defender perspective — JarDani thinks in
    both directions.
    """
    api_intel = edr_data.get(api_name, {})
    event_ids = api_intel.get("defender_event_ids", [])

    detections = [
        {
            "method": "Sysmon Event ID 10",
            "detail": "ProcessAccess events log when one process opens a handle to another. Monitor for PROCESS_ALL_ACCESS or VM_OPERATION access rights from unexpected processes.",
            "tool": "Sysmon"
        },
        {
            "method": "ETW Microsoft-Windows-Threat-Intelligence",
            "detail": "The ETW TI provider fires kernel callbacks for memory allocation, write, and thread creation operations. This fires regardless of user-mode hook bypass. Subscribe to this provider in your EDR.",
            "tool": "ETW"
        },
        {
            "method": "Syscall origin monitoring",
            "detail": "Monitor for syscall instructions executing from memory regions outside known loaded modules. Legitimate code syscalls should always originate from ntdll.dll address range.",
            "tool": "EDR kernel driver"
        },
        {
            "method": f"Windows Event IDs: {', '.join(event_ids)}",
            "detail": "Enable advanced audit logging for object access and process creation. These Event IDs capture the operations our APIs perform at the Windows audit layer.",
            "tool": "Windows Event Log"
        },
        {
            "method": "Behavioural sequence detection",
            "detail": f"Build detection rules for the injection sequence: NtAllocateVirtualMemory -> NtWriteVirtualMemory -> NtProtectVirtualMemory -> NtCreateThreadEx targeting the same remote process within a short time window.",
            "tool": "SIEM / EDR rules"
        },
        {
            "method": "Memory integrity scanning",
            "detail": "Periodically scan process memory for RWX regions, high entropy content, and shellcode byte patterns. Indirect syscalls do not prevent payload detection in memory.",
            "tool": "EDR memory scanner"
        }
    ]
    return detections


def get_mitre_mappings(api_name, mitre_data):
    """Get all MITRE ATT&CK techniques relevant to this API."""
    api_map    = mitre_data.get("api_to_mitre", {})
    techniques = mitre_data.get("techniques", {})
    tech_ids   = api_map.get(api_name, [])

    mappings = []
    for tid in tech_ids:
        if tid in techniques:
            mappings.append({
                "id":   tid,
                "name": techniques[tid]["name"],
                "url":  techniques[tid]["url"]
            })
    return mappings


def get_improvements():
    """
    Suggest what the red teamer can do to improve evasion
    beyond what SilentGate v1.0 provides.
    This is honest — we tell users where to go next.
    """
    return [
        {
            "technique": "Sleep obfuscation",
            "detail": "Encrypt your payload in memory between beacon callbacks. This defeats memory scanners that run during sleep intervals.",
            "complexity": "HIGH"
        },
        {
            "technique": "Call stack spoofing",
            "detail": "Forge the return address on the call stack so the syscall appears to originate from a legitimate module like kernel32.dll.",
            "complexity": "HIGH"
        },
        {
            "technique": "ETW patching",
            "detail": "Patch EtwEventWrite in memory to silence ETW telemetry before sensitive operations. Removes a key detection vector.",
            "complexity": "MEDIUM"
        },
        {
            "technique": "Handle inheritance",
            "detail": "Use handle duplication instead of NtOpenProcess to avoid process access events that trigger on handle acquisition.",
            "complexity": "MEDIUM"
        }
    ]


def print_intelligence_report(api_name, ssn, explain=True):
    """
    Main function - prints the complete intelligence report
    for the given API and SSN.
    """
    edr_data   = load_edr_data()
    mitre_data = load_mitre_data()

    confidence  = analyse_confidence(api_name, edr_data)
    risks       = get_remaining_risks(api_name, edr_data)
    detections  = get_defender_perspective(api_name, edr_data)
    mappings    = get_mitre_mappings(api_name, mitre_data)
    improvements = get_improvements()

    # ── CONFIDENCE RATINGS ────────────────────────────────────
    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  EVASION CONFIDENCE ANALYSIS                                 ║
  ║  API : {api_name:<53}║
  ╚══════════════════════════════════════════════════════════════╝
""")

    edrs = [
        ("Windows Defender",   confidence["windows_defender"]),
        ("CrowdStrike Falcon", confidence["crowdstrike_falcon"]),
        ("SentinelOne",        confidence["sentinelone"]),
    ]

    for edr_name, score in edrs:
        label = get_confidence_label(score)
        bar   = get_confidence_bar(score)
        print(f"  {edr_name:<22} [{bar}] {score:3d}%  {label}")

    print()
    overall_label = get_confidence_label(confidence["overall"])
    overall_bar   = get_confidence_bar(confidence["overall"])
    print(f"  {'OVERALL':<22} [{overall_bar}] {confidence['overall']:3d}%  {overall_label}")
    print(f"\n  Note: {confidence['explanation']}")

    # ── REMAINING RISKS ───────────────────────────────────────
    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  REMAINING DETECTION RISKS                                   ║
  ║  What would still catch this technique                       ║
  ╚══════════════════════════════════════════════════════════════╝
""")
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_risks   = sorted(risks, key=lambda x: severity_order[x["severity"]])

    for risk in sorted_risks:
        sev = risk["severity"]
        print(f"  [{sev:<6}] {risk['risk']}")
        print(f"           {risk['detail']}")
        print()

    # ── DEFENDER PERSPECTIVE ──────────────────────────────────
    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  DEFENDER PERSPECTIVE                                        ║
  ║  What blue team needs to detect this                         ║
  ╚══════════════════════════════════════════════════════════════╝
""")
    for det in detections:
        print(f"  [DETECT] {det['method']}")
        print(f"           Tool   : {det['tool']}")
        print(f"           Detail : {det['detail']}")
        print()

    # ── MITRE MAPPING ─────────────────────────────────────────
    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  MITRE ATT&CK MAPPING                                        ║
  ╚══════════════════════════════════════════════════════════════╝
""")
    for m in mappings:
        print(f"  {m['id']:<12} {m['name']}")
        print(f"               {m['url']}")
        print()

    # ── IMPROVEMENTS ──────────────────────────────────────────
    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  SUGGESTED IMPROVEMENTS BEYOND v1.0                          ║
  ╚══════════════════════════════════════════════════════════════╝
""")
    for imp in improvements:
        print(f"  [{imp['complexity']} COMPLEXITY] {imp['technique']}")
        print(f"    {imp['detail']}")
        print()

    return {
        "api_name":    api_name,
        "ssn":         ssn,
        "confidence":  confidence,
        "risks":       risks,
        "detections":  detections,
        "mappings":    mappings,
        "improvements": improvements
    }
