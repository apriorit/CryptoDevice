#include "CryptoDeviceLogic.h"
#include "CryptoDeviceMemory.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, CryptoDeviceResetRequest)
#pragma alloc_text (PAGE, CryptoDeviceAesCbcEncryptRequest)
#pragma alloc_text (PAGE, CryptoDeviceAesCbcDecryptRequest)
#pragma alloc_text (PAGE, CryptoDeviceSha2CbcRequest)
#pragma alloc_text (PAGE, CryptoDeviceStateRequest)
#endif

// TODO: SYNC

NTSTATUS CryptoDeviceResetRequest(
    _In_ PCRYPTO_DEVICE Device
)
{
    PAGED_CODE();

    NT_CHECK(CryptoDeviceDoCommand(Device, CryptoDevice_ResetCommand));
    NT_CHECK(CryptoDeviceWaitForReadyOrError(Device, NULL));
    return STATUS_SUCCESS;
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
    DMA_USER_MEMORY bufferIn = { 0 };
    DMA_USER_MEMORY bufferOut = { 0 };

    NTSTATUS status = STATUS_UNSUCCESSFUL;

    NT_CHECK_GOTO_CLEAN(MemCreateDmaForUserBuffer(
        UserBufferIn,
        UserBufferInSize,
        IoReadAccess,
        &bufferIn));

    NT_CHECK_GOTO_CLEAN(MemCreateDmaForUserBuffer(
        UserBufferOut,
        UserBufferOutSize,
        IoWriteAccess,
        &bufferOut));

    CryptoDeviceProgramDmaIn(Device, bufferIn.DmaAddress, bufferIn.DmaCountOfPages);
    CryptoDeviceProgramDmaOut(Device, bufferOut.DmaAddress, bufferOut.DmaCountOfPages);

    NT_CHECK_GOTO_CLEAN(CryptoDeviceDoCommand(Device, Command));
    NT_CHECK_GOTO_CLEAN(CryptoDeviceWaitForReadyOrError(Device, NULL));

clean:
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
        CryptoDevice_AesEncryptCbcCommand);
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
        CryptoDevice_AesDecryptCbcCommand);
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

    WdfWaitLockAcquire(Device->OperationLock, NULL);
    State->State = CryptoDeviceGetState(Device);
    State->Error = CryptoDeviceGetErrorCode(Device);
    WdfWaitLockRelease(Device->OperationLock);
    return STATUS_SUCCESS;
}