#include "Driver.h"
#include "Interrupt.tmh"
#include "Interrupt.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, CryptoDeviceInterruptCreate)
#endif

NTSTATUS CryptoDeviceInterruptCreate(
    _In_    WDFDEVICE Device,
    _In_    PCM_PARTIAL_RESOURCE_DESCRIPTOR InterruptTranslated,
    _In_    PCM_PARTIAL_RESOURCE_DESCRIPTOR InterruptRaw,
    _Inout_ WDFINTERRUPT *Interrupt
)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_INTERRUPT, "%!FUNC! Entry");

    PDEVICE_CONTEXT devContext = DeviceGetContext(Device);

    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(
        &attributes,
        DEVICE_INTERRUPT_CONTEXT);

    WDF_INTERRUPT_CONFIG interruptConfig;
    WDF_INTERRUPT_CONFIG_INIT(
        &interruptConfig,
        CryptoDeviceEvtInterruptIsr,
        NULL);

    interruptConfig.EvtInterruptDpc = CryptoDeviceEvtInterruptDpc;
    interruptConfig.EvtInterruptEnable = CryptoDeviceEvtInterruptEnable;
    interruptConfig.EvtInterruptDisable = CryptoDeviceEvtInterruptDisable;

    interruptConfig.InterruptTranslated = InterruptTranslated;
    interruptConfig.InterruptRaw = InterruptRaw;
    interruptConfig.SpinLock = devContext->InterruptLock;

    NTSTATUS status = WdfInterruptCreate(
        Device,
        &interruptConfig,
        &attributes,
        Interrupt);

    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_INTERRUPT, "WdfInterruptCreate failed: %!STATUS!", status);
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_INTERRUPT, "%!FUNC! Exit");
    return status;
}

BOOLEAN CryptoDeviceEvtInterruptIsr(
    _In_ WDFINTERRUPT Interrupt,
    _In_ ULONG        MessageID
)
{
    PDEVICE_INTERRUPT_CONTEXT interruptContext = GetInterruptContext(Interrupt);
    PDEVICE_CONTEXT ctx = DeviceGetContext(WdfInterruptGetDevice(Interrupt));

    switch (MessageID)
    {
    case CryptoDevice_MsiZero:
        if (!CryptoDeviceInerruptGetFlags(&ctx->CryptoDevice, &interruptContext->Msi))
        {
            return FALSE;
        }
        break;

    case CryptoDevice_MsiError:
    case CryptoDevice_MsiReady:
        interruptContext->Msi.Flags[MessageID] = TRUE;
        break;
    }

    WdfInterruptQueueWorkItemForIsr(Interrupt);
    return TRUE;
}

_Use_decl_annotations_
VOID CryptoDeviceEvtInterruptDpc(
    _In_ WDFINTERRUPT Interrupt,
    _In_ WDFOBJECT    Device
)
{
    PDEVICE_INTERRUPT_CONTEXT interruptContext = GetInterruptContext(Interrupt);
    WdfInterruptAcquireLock(Interrupt);

    MSI_FLAGS msi = interruptContext->Msi;
    RtlZeroMemory(&interruptContext->Msi, sizeof(interruptContext->Msi));

    WdfInterruptReleaseLock(Interrupt);

    PDEVICE_CONTEXT device = DeviceGetContext(Device);
    CryptoDeviceInterruptHandler(&device->CryptoDevice, &msi);
}

NTSTATUS CryptoDeviceEvtInterruptEnable(
    _In_ WDFINTERRUPT Interrupt,
    _In_ WDFDEVICE    Device
)
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_INTERRUPT,
        "VarjoEvtInterruptEnable: Interrupt 0x%p, Device 0x%p\n",
        Interrupt, Device);
    return STATUS_SUCCESS;
}

NTSTATUS CryptoDeviceEvtInterruptDisable(
    _In_ WDFINTERRUPT Interrupt,
    _In_ WDFDEVICE Device
)
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_INTERRUPT,
        "VarjoEvtInterruptDisable: Interrupt 0x%p, Device 0x%p\n",
        Interrupt, Device);
    return STATUS_SUCCESS;
}
