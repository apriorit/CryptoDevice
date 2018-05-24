/*++

Module Name:

    device.h

Abstract:

    This file contains the device definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#include "public.h"
#include "CryptoDevice.h"

EXTERN_C_START

typedef struct _IO_MEMORY
{
    PVOID Memory;
    SIZE_T Size;
} IO_MEMORY;

//
// The device context performs the same job as
// a WDM device extension in the driver frameworks
//
typedef struct _DEVICE_CONTEXT
{
    CRYPTO_DEVICE CryptoDevice;
    IO_MEMORY IoMemoryBar0;

    WDFSPINLOCK InterruptLock;
    WDFINTERRUPT Interrupt[CryptoDevice_MsiMax];
    ULONG InterruptCount;

} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

//
// This macro will generate an inline function called DeviceGetContext
// which will be used to get a pointer to the device context memory
// in a type safe manner.
//
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)

//
// Function to initialize the device and its callbacks
//
NTSTATUS CryptoDeviceCreateDevice(
    _Inout_ PWDFDEVICE_INIT DeviceInit
    );

EVT_WDF_OBJECT_CONTEXT_CLEANUP CryptoDeviceEvtCleanup;
EVT_WDF_DEVICE_PREPARE_HARDWARE CryptoDeviceEvtDevicePrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE CryptoDeviceEvtDeviceReleaseHardware;
EVT_WDF_DEVICE_D0_ENTRY_POST_INTERRUPTS_ENABLED CryptoDeviceEvtDeviceD0EntryPostInterruptsEnabled;
EVT_WDF_DEVICE_D0_EXIT_PRE_INTERRUPTS_DISABLED CryptoDeviceEvtDeviceD0ExitPreInterruptsDisabled;
EVT_WDF_DEVICE_FILE_CREATE CryptoDeviceEvtDeviceFileCreate;
EVT_WDF_FILE_CLEANUP CryptoDeviceEvtFileCleanup;

EXTERN_C_END
