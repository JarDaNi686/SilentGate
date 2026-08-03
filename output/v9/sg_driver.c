/*
 * SilentGate v9.0 - Custom Kernel Driver
 * Author: JarDani
 * GCC/MinGW compatible - no MSVC extensions
 */
#include <ntddk.h>

#define DEVICE_NAME   L"\\Device\\SilentGate"
#define SYMBOLIC_NAME L"\\DosDevices\\SilentGate"

#define IOCTL_SG_READ_VIRTUAL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SG_WRITE_VIRTUAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct {
    ULONG64 address;
    ULONG   size;
    UCHAR   data[256];
} SG_MEM_REQUEST;

PDEVICE_OBJECT g_DevObj = NULL;

NTSTATUS sg_read_virtual(ULONG64 address, PVOID buffer, ULONG size) {
    RtlCopyMemory(buffer, (PVOID)address, size);
    return STATUS_SUCCESS;
}

NTSTATUS sg_write_virtual(ULONG64 address, PVOID buffer, ULONG size) {
    PMDL mdl = IoAllocateMdl((PVOID)address, size, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    MmBuildMdlForNonPagedPool(mdl);
    PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode,
        MmNonCached, NULL, FALSE, NormalPagePriority);

    if (!mapped) {
        IoFreeMdl(mdl);
        return STATUS_ACCESS_VIOLATION;
    }

    RtlCopyMemory(mapped, buffer, size);
    MmUnmapLockedPages(mapped, mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}

NTSTATUS sg_ioctl(PDEVICE_OBJECT DevObj, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code    = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buf     = Irp->AssociatedIrp.SystemBuffer;
    ULONG in_len  = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out_len = stack->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS status = STATUS_INVALID_PARAMETER;
    ULONG bytes = 0;

    if (in_len >= sizeof(SG_MEM_REQUEST)) {
        SG_MEM_REQUEST* req = (SG_MEM_REQUEST*)buf;

        if (code == IOCTL_SG_READ_VIRTUAL) {
            if (out_len >= req->size && req->size <= 256) {
                status = sg_read_virtual(req->address, buf, req->size);
                if (NT_SUCCESS(status)) bytes = req->size;
            }
        }
        else if (code == IOCTL_SG_WRITE_VIRTUAL) {
            if (req->size <= 256) {
                status = sg_write_virtual(req->address,
                    req->data, req->size);
            }
        }
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
    UNICODE_STRING sym = RTL_CONSTANT_STRING(SYMBOLIC_NAME);
    IoDeleteSymbolicLink(&sym);
    if (g_DevObj) IoDeleteDevice(g_DevObj);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegPath) {
    UNICODE_STRING dev = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING sym = RTL_CONSTANT_STRING(SYMBOLIC_NAME);

    NTSTATUS status = IoCreateDevice(DriverObj, 0, &dev,
        FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DevObj);
    if (!NT_SUCCESS(status)) return status;

    IoCreateSymbolicLink(&sym, &dev);

    DriverObj->MajorFunction[IRP_MJ_CREATE]         = sg_create_close;
    DriverObj->MajorFunction[IRP_MJ_CLOSE]          = sg_create_close;
    DriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = sg_ioctl;
    DriverObj->DriverUnload                          = sg_unload;

    g_DevObj->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
