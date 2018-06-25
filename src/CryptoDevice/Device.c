/*++

Module Name:

    device.c - Device handling events for example driver.

Abstract:

   This file contains the device entry points and callbacks.
    
Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "device.tmh"
#include "CryptoDeviceLogic.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, CryptoDeviceCreateDevice)
#pragma alloc_text (PAGE, CryptoDeviceEvtDevicePrepareHardware)
#pragma alloc_text (PAGE, CryptoDeviceEvtDeviceReleaseHardware)
#pragma alloc_text (PAGE, CryptoDeviceEvtDeviceD0EntryPostInterruptsEnabled)
#pragma alloc_text (PAGE, CryptoDeviceEvtDeviceD0ExitPreInterruptsDisabled)
#pragma alloc_text (PAGE, CryptoDeviceEvtDeviceFileCreate)
#pragma alloc_text (PAGE, CryptoDeviceEvtFileCleanup)
#endif

NTSTATUS CryptoDeviceCreateDevice(
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
/*++

Routine Description:

    Worker routine called to create a device and its software resources.

Arguments:

    DeviceInit - Pointer to an opaque init structure. Memory for this
                    structure will be freed by the framework when the WdfDeviceCreate
                    succeeds. So don't access the structure after that point.

Return Value:

    NTSTATUS

--*/
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Entry");

    PAGED_CODE();

    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_FILEOBJECT_CONFIG_INIT(
        &fileConfig,
        CryptoDeviceEvtDeviceFileCreate,
        WDF_NO_EVENT_CALLBACK,
        CryptoDeviceEvtFileCleanup
    );

    WdfDeviceInitSetFileObjectConfig(
        DeviceInit,
        &fileConfig,
        NULL);

    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDevicePrepareHardware = CryptoDeviceEvtDevicePrepareHardware;
    pnpPowerCallbacks.EvtDeviceReleaseHardware = CryptoDeviceEvtDeviceReleaseHardware;
    pnpPowerCallbacks.EvtDeviceD0EntryPostInterruptsEnabled = CryptoDeviceEvtDeviceD0EntryPostInterruptsEnabled;
    pnpPowerCallbacks.EvtDeviceD0ExitPreInterruptsDisabled = CryptoDeviceEvtDeviceD0ExitPreInterruptsDisabled;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

    WdfDeviceInitSetExclusive(DeviceInit, TRUE);
    WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);

    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);
    deviceAttributes.EvtCleanupCallback = CryptoDeviceEvtCleanup;

    WDFDEVICE device;
    NT_CHECK(WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device));

    PDEVICE_CONTEXT ctx = DeviceGetContext(device);

    WDF_OBJECT_ATTRIBUTES spinlockAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT(&spinlockAttributes);
    spinlockAttributes.ParentObject = device;
    NT_CHECK(WdfSpinLockCreate(&spinlockAttributes, &ctx->InterruptLock));
    ctx->InterruptCount = 0;

    NT_CHECK(WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_CRYPTO, NULL));
    NT_CHECK(CryptoDeviceQueueInitialize(device));

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Exit");
    return STATUS_SUCCESS;
}

VOID CryptoDeviceEvtCleanup(
    _In_ WDFOBJECT Device
)
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Entry");

    PDEVICE_CONTEXT ctx = DeviceGetContext(Device);
    CryptoDeviceRelease(&ctx->CryptoDevice);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Exit");
}

NTSTATUS CryptoDeviceEvtDevicePrepareHardware(
    _In_ WDFDEVICE Device,
    _In_ WDFCMRESLIST ResourcesRaw,
    _In_ WDFCMRESLIST ResourcesTranslated
)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR descriptor;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR raw;
    PDEVICE_CONTEXT ctx = DeviceGetContext(Device);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Entry");

    UNREFERENCED_PARAMETER(ResourcesRaw);

    PAGED_CODE();

    for (ULONG i = 0; i < WdfCmResourceListGetCount(ResourcesTranslated); ++i)
    {
        descriptor = WdfCmResourceListGetDescriptor(ResourcesTranslated, i);

        if (!descriptor)
        {
            TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "WdfResourceCmGetDescriptor");
            return STATUS_DEVICE_CONFIGURATION_ERROR;
        }

        switch (descriptor->Type)
        {
        case CmResourceTypeMemory:

            ASSERT(descriptor->u.Memory.Length == 0x1000);

            if (ctx->IoMemoryBar0.Memory)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "%!FUNC! The device has more than one memory BAR, but the driver expects only one memory region.");
                return STATUS_DEVICE_CONFIGURATION_ERROR;
            }

            ctx->IoMemoryBar0.Memory = MmMapIoSpaceEx(
                descriptor->u.Memory.Start,
                descriptor->u.Memory.Length,
                PAGE_READWRITE | PAGE_NOCACHE);

            if (!ctx->IoMemoryBar0.Memory)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "%!FUNC! MmMapIoSpaceEx failed.");
                return STATUS_DEVICE_CONFIGURATION_ERROR;
            }

            ctx->IoMemoryBar0.Size = descriptor->u.Memory.Length;
            break;

        case CmResourceTypeInterrupt:

            raw = WdfCmResourceListGetDescriptor(ResourcesRaw, i);

            if (0 != ctx->InterruptCount)
            {
                TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "%!FUNC! The device has more than one interrupt descriptors, but the driver expects only one.");
                return STATUS_DEVICE_CONFIGURATION_ERROR;
            }

            if (CM_RESOURCE_INTERRUPT_MESSAGE & descriptor->Flags)
            {
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! MSI mode\n");

                ctx->InterruptCount = min(ARRAYSIZE(ctx->Interrupt), raw->u.MessageInterrupt.Raw.MessageCount);

                if (ctx->InterruptCount != ARRAYSIZE(ctx->Interrupt))
                {
                    TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "%!FUNC! Windows cannot allocate required MSIs. The driver will use only MSI 0");
                    ctx->InterruptCount = 1;
                }

                for (ULONG k = 0; k < ctx->InterruptCount; ++k)
                {
                    NT_CHECK(CryptoDeviceInterruptCreate(Device, descriptor, raw, &ctx->Interrupt[k]));
                }
            }
            else
            {
                TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Legacy Interrupt mode\n");

                //TODO: check
                ctx->InterruptCount = 1;
                NT_CHECK(CryptoDeviceInterruptCreate(Device, descriptor, raw, &ctx->Interrupt[0]));
            }

            break;

        case CmResourceTypeDevicePrivate:
            break;

        default:
            ASSERT(!"Unhandled resource type");
        }
    }

    if (0 == ctx->InterruptCount)
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "%!FUNC! The driver cannot find the device's interrupts");
        return STATUS_DEVICE_INSUFFICIENT_RESOURCES;
    }

    if (!ctx->IoMemoryBar0.Memory)
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "%!FUNC! The driver cannot find the device's IO space");
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    // TODO : check error case and resources
    NT_CHECK(CryptoDeviceInit(&ctx->CryptoDevice, ctx->IoMemoryBar0.Memory));

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Exit");
    return STATUS_SUCCESS;
}

NTSTATUS CryptoDeviceEvtDeviceReleaseHardware(
    _In_ WDFDEVICE Device,
    _In_ WDFCMRESLIST ResourcesTranslated
)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(ResourcesTranslated);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Entry");

    PDEVICE_CONTEXT ctx = DeviceGetContext(Device);
    CryptoDeviceRelease(&ctx->CryptoDevice);

    if (ctx->IoMemoryBar0.Memory)
    {
        MmUnmapIoSpace(ctx->IoMemoryBar0.Memory, ctx->IoMemoryBar0.Size);
        ctx->IoMemoryBar0.Memory = NULL;
        ctx->IoMemoryBar0.Size = 0;
    }

    ctx->InterruptCount = 0;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Exit");
    return STATUS_SUCCESS;
}

NTSTATUS CryptoDeviceEvtDeviceD0EntryPostInterruptsEnabled(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(PreviousState);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Entry");

    PDEVICE_CONTEXT ctx = DeviceGetContext(Device);
    CryptoDeviceInterruptEnable(&ctx->CryptoDevice);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Exit");
    return STATUS_SUCCESS;
}

NTSTATUS CryptoDeviceEvtDeviceD0ExitPreInterruptsDisabled(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE TargetState
)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(TargetState);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Entry");

    PDEVICE_CONTEXT ctx = DeviceGetContext(Device);
    CryptoDeviceInterruptDisable(&ctx->CryptoDevice);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Exit");
    return STATUS_SUCCESS;
}

VOID CryptoDeviceEvtDeviceFileCreate(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ WDFFILEOBJECT FileObject
)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC!");

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(FileObject);
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

VOID CryptoDeviceEvtFileCleanup(
    _In_ WDFFILEOBJECT FileObject
)
{
    PAGED_CODE();
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Entry");

    WDFDEVICE device = WdfFileObjectGetDevice(FileObject);
    PDEVICE_CONTEXT ctx = DeviceGetContext(device);

    CryptoDeviceResetRequest(&ctx->CryptoDevice);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE, "%!FUNC! Exit");
}
