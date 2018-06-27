/*++

Module Name:

    queue.c

Abstract:

    This file contains the queue entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "queue.tmh"
#include "CryptoDeviceLogic.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, CryptoDeviceQueueInitialize)
#endif

NTSTATUS CryptoDeviceQueueInitialize(
    _In_ WDFDEVICE Device
    )
/*++

Routine Description:

     The I/O dispatch callbacks for the frameworks device object
     are configured in this function.

     A single default I/O Queue is configured for parallel request
     processing, and a driver context memory allocation is created
     to hold our structure QUEUE_CONTEXT.

Arguments:

    Device - Handle to a framework device object.

Return Value:

    VOID

--*/
{
    WDFQUEUE queue;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;

    PAGED_CODE();

    //
    // Configure a default queue so that requests that are not
    // configure-fowarded using WdfDeviceConfigureRequestDispatching to goto
    // other queues get dispatched here.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchParallel
        );

    queueConfig.EvtIoDeviceControl = CryptoDeviceEvtIoDeviceControl;
    queueConfig.EvtIoStop = CryptoDeviceEvtIoStop;

    status = WdfIoQueueCreate(
                 Device,
                 &queueConfig,
                 WDF_NO_OBJECT_ATTRIBUTES,
                 &queue
                 );

    if(!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "WdfIoQueueCreate failed %!STATUS!", status);
        return status;
    }

    return status;
}

__inline PVOID Ulong64ToPtr(ULONG64 h)
{
    return (PVOID)((UINT_PTR)h);
}

static NTSTATUS CheckUserBuffer(PVOID Address, ULONG Lenght)
{
    PVOID end = (PCHAR)Address + Lenght;

    if (!Address && 0 != Lenght)
    {
        return STATUS_INVALID_USER_BUFFER;
    }

    if (Address >= end && 0 != Lenght)
    {
        return STATUS_INVALID_USER_BUFFER;
    }

    if (Address >= MmHighestUserAddress || end >= MmHighestUserAddress)
    {
        return STATUS_INVALID_USER_BUFFER;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS CheckDeviceBuffer(const CryptoDeviceBuffer* Buffer)
{
    return CheckUserBuffer(Ulong64ToPtr(Buffer->Address), Buffer->Size);
}

static NTSTATUS CehckDeviceBufferInOut(const CryptoDeviceBufferInOut* Buffer)
{
    NT_CHECK(CheckDeviceBuffer(&Buffer->In));
    NT_CHECK(CheckDeviceBuffer(&Buffer->Out));
    return STATUS_SUCCESS;
}

VOID CryptoDeviceEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
/*++

Routine Description:

    This event is invoked when the framework receives IRP_MJ_DEVICE_CONTROL request.

Arguments:

    Queue -  Handle to the framework queue object that is associated with the
             I/O request.

    Request - Handle to a framework request object.

    OutputBufferLength - Size of the output buffer in bytes

    InputBufferLength - Size of the input buffer in bytes

    IoControlCode - I/O control code.

Return Value:

    VOID

--*/
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        //
        // We can process IOCTLs only on PASSIVE LEVEL
        //
        WdfRequestCompleteWithInformation(Request, STATUS_NOT_IMPLEMENTED, 0);
        return;
    }

    WDFDEVICE device = WdfIoQueueGetDevice(Queue);
    PDEVICE_CONTEXT ctx = DeviceGetContext(device);
    size_t bytesReturned = 0;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    TraceEvents(TRACE_LEVEL_INFORMATION,
        TRACE_QUEUE,
        "%!FUNC! Queue 0x%p, Request 0x%p OutputBufferLength %d InputBufferLength %d IoControlCode %d",
        Queue, Request, (int)OutputBufferLength, (int)InputBufferLength, IoControlCode);

    switch (IoControlCode)
    {
    case IOCTL_CRYPTO_DEVICE_RESET:
    {
        status = CryptoDeviceResetRequest(&ctx->CryptoDevice);
        break;
    }

    case IOCTL_CRYPTO_DEVICE_GET_STATUS:
    {
        CryptoDeviceStatus * st = NULL;
        bytesReturned = sizeof(*st);
        NT_CHECK_BREAK(WdfRequestRetrieveOutputBuffer(Request, sizeof(*st), &st, NULL));

        DEVICE_STATE state = { 0 };
        NT_CHECK_BREAK(CryptoDeviceStateRequest(&ctx->CryptoDevice, &state));

        st->ErrorCode = state.Error;
        st->State = state.State;
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT:
    {
        CryptoDeviceBufferInOut * buf = NULL;
        NT_CHECK_BREAK(WdfRequestRetrieveInputBuffer(Request, sizeof(*buf), &buf, NULL));
        NT_CHECK_BREAK(CehckDeviceBufferInOut(buf));

        status = CryptoDeviceAesCbcEncryptRequest(&ctx->CryptoDevice,
            Ulong64ToPtr(buf->In.Address), buf->In.Size,
            Ulong64ToPtr(buf->Out.Address), buf->Out.Size);
        break;
    }

    case IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT:
    {
        CryptoDeviceBufferInOut * buf = NULL;
        NT_CHECK_BREAK(WdfRequestRetrieveInputBuffer(Request, sizeof(*buf), &buf, NULL));
        NT_CHECK_BREAK(CehckDeviceBufferInOut(buf));

        status = CryptoDeviceAesCbcDecryptRequest(&ctx->CryptoDevice,
            Ulong64ToPtr(buf->In.Address), buf->In.Size,
            Ulong64ToPtr(buf->Out.Address), buf->Out.Size);
        break;
    }

    case IOCTL_CRYPTO_DEVICE_SHA256:
    {
        CryptoDeviceBufferInOut * buf = NULL;
        NT_CHECK_BREAK(WdfRequestRetrieveInputBuffer(Request, sizeof(*buf), &buf, NULL));
        NT_CHECK_BREAK(CehckDeviceBufferInOut(buf));

        status = CryptoDeviceSha2CbcRequest(&ctx->CryptoDevice,
            Ulong64ToPtr(buf->In.Address), buf->In.Size,
            Ulong64ToPtr(buf->Out.Address), buf->Out.Size);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}

VOID CryptoDeviceEvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
)
/*++

Routine Description:

    This event is invoked for a power-managed queue before the device leaves the working state (D0).

Arguments:

    Queue -  Handle to the framework queue object that is associated with the
             I/O request.

    Request - Handle to a framework request object.

    ActionFlags - A bitwise OR of one or more WDF_REQUEST_STOP_ACTION_FLAGS-typed flags
                  that identify the reason that the callback function is being called
                  and whether the request is cancelable.

Return Value:

    VOID

--*/
{
    TraceEvents(TRACE_LEVEL_INFORMATION, 
                TRACE_QUEUE, 
                "%!FUNC! Queue 0x%p, Request 0x%p ActionFlags %d", 
                Queue, Request, ActionFlags);

    //
    // In most cases, the EvtIoStop callback function completes, cancels, or postpones
    // further processing of the I/O request.
    //
    // Typically, the driver uses the following rules:
    //
    // - If the driver owns the I/O request, it calls WdfRequestUnmarkCancelable
    //   (if the request is cancelable) and either calls WdfRequestStopAcknowledge
    //   with a Requeue value of TRUE, or it calls WdfRequestComplete with a
    //   completion status value of STATUS_SUCCESS or STATUS_CANCELLED.
    //
    //   Before it can call these methods safely, the driver must make sure that
    //   its implementation of EvtIoStop has exclusive access to the request.
    //
    //   In order to do that, the driver must synchronize access to the request
    //   to prevent other threads from manipulating the request concurrently.
    //   The synchronization method you choose will depend on your driver's design.
    //
    //   For example, if the request is held in a shared context, the EvtIoStop callback
    //   might acquire an internal driver lock, take the request from the shared context,
    //   and then release the lock. At this point, the EvtIoStop callback owns the request
    //   and can safely complete or requeue the request.
    //
    // - If the driver has forwarded the I/O request to an I/O target, it either calls
    //   WdfRequestCancelSentRequest to attempt to cancel the request, or it postpones
    //   further processing of the request and calls WdfRequestStopAcknowledge with
    //   a Requeue value of FALSE.
    //
    // A driver might choose to take no action in EvtIoStop for requests that are
    // guaranteed to complete in a small amount of time.
    //
    // In this case, the framework waits until the specified request is complete
    // before moving the device (or system) to a lower power state or removing the device.
    // Potentially, this inaction can prevent a system from entering its hibernation state
    // or another low system power state. In extreme cases, it can cause the system
    // to crash with bugcheck code 9F.
    //

    return;
}
