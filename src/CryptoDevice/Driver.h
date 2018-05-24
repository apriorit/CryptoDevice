/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include <wdf.h>
#include <initguid.h>

#include "Device.h"
#include "Interrupt.h"
#include "Queue.h"
#include "Trace.h"

EXTERN_C_START

//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD CryptoDeviceEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP CryptoDeviceEvtDriverContextCleanup;

EXTERN_C_END
