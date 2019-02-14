//
// @depletionmode 2019
//

#pragma once

#include <initguid.h>

DEFINE_GUID(PspDriverGuid,
            0xdadf460e, 0x2052, 0x45df, 0xac, 0x04, 0xf8, 0x97, 0x24, 0x49, 0x85, 0xb9);

#define IOCTL_PSP_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0xa90, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PSP_READ_MEMORY_REQUEST {
    PVOID Address;
    ULONG ContextProcessId;

    PVOID ResponseBuffer;
    SIZE_T Length;

} PSP_READ_MEMORY_REQUEST, *PPSP_READ_MEMORY_REQUEST;

#define IOCTL_PSP_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0xa91, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PSP_WRITE_MEMORY_REQUEST {
    PVOID Address;
    ULONG ContextProcessId;

    PVOID Buffer;
    SIZE_T Length;  // Must be a multiple of sizeof(ULONG).

} PSP_WRITE_MEMORY_REQUEST, *PPSP_WRITE_MEMORY_REQUEST;
