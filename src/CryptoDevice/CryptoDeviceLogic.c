#include "CryptoDeviceLogic.h"
#include "CryptoDeviceMemory.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, CryptoDeviceResetRequest)
#pragma alloc_text (PAGE, CryptoDeviceAesCbcRequest)
#pragma alloc_text (PAGE, CryptoDeviceSha2CbcRequest)
#endif

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

NTSTATUS CryptoDeviceAesCbcRequest(
    _In_ PCRYPTO_DEVICE Device,
    _In_ PVOID UserBufferIn,
    _In_ ULONG UserBufferInSize,
    _In_ PVOID UserBufferOut,
    _In_ ULONG UserBufferOutSize
)
{
    PAGED_CODE();

    NT_CHECK(CryptoDeviceResetRequest(Device));
    NT_CHECK(CryptoDeviceCommandRequestInOut(
        Device,
        UserBufferIn,
        UserBufferInSize,
        UserBufferOut,
        UserBufferOutSize,
        CryptoDevice_AesCbcCommand));
    return STATUS_SUCCESS;
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

    NT_CHECK(CryptoDeviceResetRequest(Device));
    NT_CHECK(CryptoDeviceCommandRequestInOut(
        Device,
        UserBufferIn,
        UserBufferInSize,
        UserBufferOut,
        UserBufferOutSize,
        CryptoDevice_Sha2Command));
    return STATUS_SUCCESS;
}

NTSTATUS CryptoDeviceStateRequest(
    _In_ PCRYPTO_DEVICE Device,
    _Out_ PDEVICE_STATE State
)
{
    State->State = CryptoDeviceGetState(Device);
    State->Error = CryptoDeviceGetErrorCode(Device);
    return STATUS_SUCCESS;
}