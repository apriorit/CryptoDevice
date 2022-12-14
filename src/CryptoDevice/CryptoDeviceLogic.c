#include "CryptoDeviceLogic.h"
#include "CryptoDeviceMemory.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, CryptoDeviceResetRequest)
#pragma alloc_text (PAGE, CryptoDeviceAesCbcEncryptRequest)
#pragma alloc_text (PAGE, CryptoDeviceAesCbcDecryptRequest)
#pragma alloc_text (PAGE, CryptoDeviceSha2CbcRequest)
#pragma alloc_text (PAGE, CryptoDeviceStateRequest)
#endif

NTSTATUS CryptoDeviceResetRequest(
    _In_ PCRYPTO_DEVICE Device
)
{
    PAGED_CODE();

    WdfWaitLockAcquire(Device->ResetLock, NULL);

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    WdfWaitLockAcquire(Device->IoLock, NULL);

    if (CryptoDeviceGetState(Device) != CryptoDevice_ResetState)
    {
        CryptoDeviceReset(Device);
        status = STATUS_SUCCESS;
    }
    else
    {
        status = STATUS_DEVICE_BUSY;
    }

    WdfWaitLockRelease(Device->IoLock);

    NT_CHECK_GOTO_CLEAN(status);
    NT_CHECK_GOTO_CLEAN(CryptoDeviceWaitReset(Device));
    KeSetEvent(&Device->CancelEvent, IO_NO_INCREMENT, FALSE);

clean:
    WdfWaitLockRelease(Device->ResetLock);
    return status;
}

static NTSTATUS CryptoDeviceCommandRequestInOut(
    _In_ PCRYPTO_DEVICE Device,
    _In_ PVOID UserBufferIn,
    _In_ ULONG UserBufferInSize,
    _In_ PVOID UserBufferOut,
    _In_ ULONG UserBufferOutSize,
    _In_ CryptoDeviceCommand Command
)
{
    if (0 != InterlockedCompareExchange(&Device->DeviceBusy, 1, 0))
    {
        return STATUS_DEVICE_BUSY;
    }

    DMA_USER_MEMORY bufferIn = { 0 };
    DMA_USER_MEMORY bufferOut = { 0 };
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (0 != UserBufferInSize)
    {
        NT_CHECK_GOTO_CLEAN(MemCreateDmaForUserBuffer(
            UserBufferIn,
            UserBufferInSize,
            Device->DmaEnabler,
            FALSE,
            &bufferIn));
    }

    if (0 != UserBufferOutSize)
    {
        NT_CHECK_GOTO_CLEAN(MemCreateDmaForUserBuffer(
            UserBufferOut,
            UserBufferOutSize,
            Device->DmaEnabler,
            TRUE,
            &bufferOut));
    }

    WdfWaitLockAcquire(Device->IoLock, NULL);

    if (CryptoDeviceGetErrorCode(Device) != CryptoDevice_NoError)
    {
        status = STATUS_DEVICE_DATA_ERROR;
    }
    else if (CryptoDeviceGetState(Device) != CryptoDevice_ReadyState)
    {
        status = STATUS_DEVICE_BUSY;
    }
    else
    {
        CryptoDeviceProgramDmaIn(Device, bufferIn.DmaAddress, bufferIn.DmaCountOfPages, UserBufferInSize);
        CryptoDeviceProgramDmaOut(Device, bufferOut.DmaAddress, bufferOut.DmaCountOfPages, UserBufferOutSize);
        CryptoDeviceSetCommand(Device, Command);
        status = STATUS_SUCCESS;
    }

    WdfWaitLockRelease(Device->IoLock);

    NT_CHECK_GOTO_CLEAN(status);
    NT_CHECK_GOTO_CLEAN(CryptoDeviceWaitForReadyOrError(Device, NULL));

    if (bufferIn.DmaTransaction)
    {
        NTSTATUS dummy = STATUS_UNSUCCESSFUL;
        (VOID)WdfDmaTransactionDmaCompleted(bufferIn.DmaTransaction, &dummy);
    }
    if (bufferOut.DmaTransaction)
    {
        NTSTATUS dummy = STATUS_UNSUCCESSFUL;
        (VOID)WdfDmaTransactionDmaCompleted(bufferOut.DmaTransaction, &dummy);
    }

clean:
    InterlockedDecrement(&Device->DeviceBusy);
    
    if (!NT_SUCCESS(status))
    {
        if (bufferIn.DmaTransaction)
        {
            (VOID)WdfDmaTransactionDmaCompletedFinal(bufferIn.DmaTransaction, 0, &status);
        }
        if (bufferOut.DmaTransaction)
        {
            (VOID)WdfDmaTransactionDmaCompletedFinal(bufferOut.DmaTransaction, 0, &status);
        }
    }

    MemFreeDma(&bufferIn);
    MemFreeDma(&bufferOut);
    return status;
}

NTSTATUS CryptoDeviceAesCbcEncryptRequest(
    _In_ PCRYPTO_DEVICE Device,
    _In_ PVOID UserBufferIn,
    _In_ ULONG UserBufferInSize,
    _In_ PVOID UserBufferOut,
    _In_ ULONG UserBufferOutSize
)
{
    PAGED_CODE();

    return CryptoDeviceCommandRequestInOut(
        Device,
        UserBufferIn,
        UserBufferInSize,
        UserBufferOut,
        UserBufferOutSize,
        CryptoDevice_AesCbcEncryptCommand);
}

NTSTATUS CryptoDeviceAesCbcDecryptRequest(
    _In_ PCRYPTO_DEVICE Device,
    _In_ PVOID UserBufferIn,
    _In_ ULONG UserBufferInSize,
    _In_ PVOID UserBufferOut,
    _In_ ULONG UserBufferOutSize
)
{
    PAGED_CODE();

    return CryptoDeviceCommandRequestInOut(
        Device,
        UserBufferIn,
        UserBufferInSize,
        UserBufferOut,
        UserBufferOutSize,
        CryptoDevice_AesCbcDecryptCommand);
}

NTSTATUS CryptoDeviceSha2CbcRequest(
    _In_ PCRYPTO_DEVICE Device,
    _In_ PVOID UserBufferIn,
    _In_ ULONG UserBufferInSize,
    _In_ PVOID UserBufferOut,
    _In_ ULONG UserBufferOutSize
)
{
    PAGED_CODE();

    return CryptoDeviceCommandRequestInOut(
        Device,
        UserBufferIn,
        UserBufferInSize,
        UserBufferOut,
        UserBufferOutSize,
        CryptoDevice_Sha2Command);
}

NTSTATUS CryptoDeviceStateRequest(
    _In_ PCRYPTO_DEVICE Device,
    _Out_ PDEVICE_STATE State
)
{
    PAGED_CODE();

    WdfWaitLockAcquire(Device->IoLock, NULL);
    State->State = CryptoDeviceGetState(Device);
    State->Error = CryptoDeviceGetErrorCode(Device);
    WdfWaitLockRelease(Device->IoLock);
    return STATUS_SUCCESS;
}