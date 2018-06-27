#include "CryptoDevice.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, CryptoDeviceInit)
#pragma alloc_text (PAGE, CryptoDeviceWaitForReadyOrError)
#pragma alloc_text (PAGE, CryptoDeviceWaitReset)
#endif


NTSTATUS CryptoDeviceInit(
    _Inout_ PCRYPTO_DEVICE CryptoDevice,
    _In_    PVOID          CryptoDeviceIo
)
{
    PAGED_CODE();
    
    ASSERT(CryptoDeviceIo);
    ASSERT(!CryptoDevice->Io);

    NT_CHECK(WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &CryptoDevice->IoLock));
    NT_CHECK(WdfWaitLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &CryptoDevice->ResetLock));
    
    CryptoDevice->Io = CryptoDeviceIo;
    CryptoDevice->DeviceBusy = 0;

    KeInitializeEvent(&CryptoDevice->ErrorEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&CryptoDevice->ReadyEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&CryptoDevice->ResetEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&CryptoDevice->CancelEvent, NotificationEvent, FALSE);

    return STATUS_SUCCESS;
}

VOID CryptoDeviceRelease(
    _Inout_ PCRYPTO_DEVICE Device
)
{
    Device->Io = NULL;
    ASSERT(!Device->Io);
}

CryptoDeviceState CryptoDeviceGetState(
    _In_ PCRYPTO_DEVICE Device
)
{
    return (CryptoDeviceState)READ_REGISTER_UCHAR(&Device->Io->State);
}

CryptoDeviceErrorCode CryptoDeviceGetErrorCode(
    _In_ PCRYPTO_DEVICE Device
)
{
    return (CryptoDeviceErrorCode)READ_REGISTER_UCHAR(&Device->Io->ErrorCode);
}

VOID CryptoDeviceSetCommand(
    _In_ PCRYPTO_DEVICE Device,
    _In_ CryptoDeviceCommand Command
)
{
    ASSERT(CryptoDevice_AesCbcEncryptCommand == Command
        || CryptoDevice_AesCbcDecryptCommand == Command
        || CryptoDevice_Sha2Command == Command);

    KeClearEvent(&Device->ErrorEvent);
    KeClearEvent(&Device->ReadyEvent);
    KeClearEvent(&Device->CancelEvent);
    WRITE_REGISTER_UCHAR(&Device->Io->Command, (UINT8)Command);
}

VOID CryptoDeviceReset(
    _In_ PCRYPTO_DEVICE Device
)
{
    KeClearEvent(&Device->ResetEvent);
    WRITE_REGISTER_UCHAR(&Device->Io->Command, (UINT8)CryptoDevice_ResetCommand);
}

VOID CryptoDeviceInterruptEnable(
    _In_ PCRYPTO_DEVICE Device
)
{
    WRITE_REGISTER_UCHAR(&Device->Io->InterruptFlag, CryptoDevice_EnableAllFlag);
}

VOID CryptoDeviceInterruptDisable(
    _In_ PCRYPTO_DEVICE Device
)
{
    WRITE_REGISTER_UCHAR(&Device->Io->InterruptFlag, CryptoDevice_DisableFlag);
}

_Success_(return != 0)
BOOLEAN CryptoDeviceInerruptGetFlags(
    _In_ PCRYPTO_DEVICE Device,
    _Out_ PMSI_FLAGS Msi
)
{
    BOOLEAN hasActiveInterrupt = FALSE;

    if (READ_REGISTER_UCHAR(&Device->Io->MsiErrorFlag))
    {
        WRITE_REGISTER_UCHAR(&Device->Io->MsiErrorFlag, 0);
        Msi->Flags[CryptoDevice_MsiError] = TRUE;
        hasActiveInterrupt = TRUE;
    }

    if (READ_REGISTER_UCHAR(&Device->Io->MsiReadyFlag))
    {
        WRITE_REGISTER_UCHAR(&Device->Io->MsiReadyFlag, 0);
        Msi->Flags[CryptoDevice_MsiReady] = TRUE;
        hasActiveInterrupt = TRUE;
    }

    if (READ_REGISTER_UCHAR(&Device->Io->MsiResetFlag))
    {
        WRITE_REGISTER_UCHAR(&Device->Io->MsiResetFlag, 0);
        Msi->Flags[CryptoDevice_MsiReset] = TRUE;
        hasActiveInterrupt = TRUE;
    }

    return hasActiveInterrupt;
}

VOID CryptoDeviceInterruptHandler(
    _In_ PCRYPTO_DEVICE Device,
    _In_ PMSI_FLAGS Msi
)
{
    if (Msi->Flags[CryptoDevice_MsiError])
    {
        KeSetEvent(&Device->ErrorEvent, IO_NO_INCREMENT, FALSE);
    }

    if (Msi->Flags[CryptoDevice_MsiReady])
    {
        KeSetEvent(&Device->ReadyEvent, IO_NO_INCREMENT, FALSE);
    }

    if (Msi->Flags[CryptoDevice_MsiReset])
    {
        KeSetEvent(&Device->ResetEvent, IO_NO_INCREMENT, FALSE);
    }
}

VOID CryptoDeviceProgramDmaIn(
    _In_ PCRYPTO_DEVICE Device,
    _In_ ULONG32 DmaAddress,
    _In_ ULONG32 DmaPagesCount,
    _In_ ULONG32 DmaSizeInBytes
)
{
    WRITE_REGISTER_ULONG(&Device->Io->DmaInAddress, DmaAddress);
    WRITE_REGISTER_ULONG(&Device->Io->DmaInPagesCount, DmaPagesCount);
    WRITE_REGISTER_ULONG(&Device->Io->DmaInSizeInBytes, DmaSizeInBytes);
}

VOID CryptoDeviceProgramDmaOut(
    _In_ PCRYPTO_DEVICE Device,
    _In_ ULONG32 DmaAddress,
    _In_ ULONG32 DmaPagesCount,
    _In_ ULONG32 DmaSizeInBytes
)
{
    WRITE_REGISTER_ULONG(&Device->Io->DmaOutAddress, DmaAddress);
    WRITE_REGISTER_ULONG(&Device->Io->DmaOutPagesCount, DmaPagesCount);
    WRITE_REGISTER_ULONG(&Device->Io->DmaOutSizeInBytes, DmaSizeInBytes);
}

NTSTATUS CryptoDeviceWaitForReadyOrError(
    _In_ PCRYPTO_DEVICE Device,
    _In_opt_ PLARGE_INTEGER Timeout
)
{
    PAGED_CODE();

    PKEVENT events[3] = { 0 };
    events[0] = &Device->ReadyEvent;
    events[1] = &Device->ErrorEvent;
    events[2] = &Device->CancelEvent;

    NTSTATUS status = KeWaitForMultipleObjects(ARRAYSIZE(events),
        events,
        WaitAny,
        Executive,
        KernelMode,
        FALSE,
        Timeout,
        NULL);

    switch (status)
    {
    case STATUS_WAIT_0:
        //
        // Ready event
        //
        ASSERT(READ_REGISTER_UCHAR(&Device->Io->ErrorCode) == CryptoDevice_NoError);
        ASSERT(READ_REGISTER_UCHAR(&Device->Io->State) == CryptoDevice_ReadyState);
        ASSERT(KeReadStateEvent(&Device->ErrorEvent) == 0);
        return STATUS_SUCCESS;

    case STATUS_WAIT_1:
        //
        // Error event
        //
        ASSERT(READ_REGISTER_UCHAR(&Device->Io->ErrorCode) != CryptoDevice_NoError);
        ASSERT(KeReadStateEvent(&Device->ReadyEvent) == 0);
        return STATUS_DEVICE_DATA_ERROR;

    case STATUS_WAIT_2:
        //
        // Cancel event
        //
        ASSERT(KeReadStateEvent(&Device->CancelEvent) == 0);
        return STATUS_CANCELLED;

    case STATUS_TIMEOUT:

        return STATUS_DEVICE_BUSY;
    }

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS CryptoDeviceWaitReset(
    _In_ PCRYPTO_DEVICE Device
)
{
    PAGED_CODE();

    LARGE_INTEGER timeout = { 0 };
    timeout.QuadPart = WDF_REL_TIMEOUT_IN_MS(CRYPTO_DEVICE_RESET_TIMEOUT_MS);

    NTSTATUS status = KeWaitForSingleObject(&Device->ResetEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout);

    switch (status)
    {
    case STATUS_WAIT_0:
        return STATUS_SUCCESS;

    case STATUS_TIMEOUT:

        return STATUS_DEVICE_BUSY;
    }

    return STATUS_UNSUCCESSFUL;
}