#pragma once

#include "CryptoDeviceCommon.h"

EXTERN_C_START

typedef struct _MSI_FLAGS
{
    UCHAR Flags[CryptoDevice_MsiMax];

} MSI_FLAGS, *PMSI_FLAGS;

typedef struct _CRYPTO_DEVICE
{
    CryptoDeviceIo * Io;
    WDFWAITLOCK IoLock;
    WDFWAITLOCK ResetLock;

    KEVENT ErrorEvent;
    KEVENT ReadyEvent;
    KEVENT ResetEvent;
    KEVENT CancelEvent;

    volatile LONG DeviceBusy;

} CRYPTO_DEVICE, *PCRYPTO_DEVICE;

NTSTATUS CryptoDeviceInit(
    _In_    PVOID          CryptoDeviceIo,
    _Inout_ PCRYPTO_DEVICE CryptoDevice
);

VOID CryptoDeviceRelease(
    _Inout_ PCRYPTO_DEVICE Device
);

CryptoDeviceState CryptoDeviceGetState(
    _In_ PCRYPTO_DEVICE Device
);

CryptoDeviceErrorCode CryptoDeviceGetErrorCode(
    _In_ PCRYPTO_DEVICE Device
);

VOID CryptoDeviceSetCommand(
    _In_ PCRYPTO_DEVICE Device,
    _In_ CryptoDeviceCommand Command
);

VOID CryptoDeviceReset(
    _In_ PCRYPTO_DEVICE Device
);

VOID CryptoDeviceInterruptEnable(
    _In_ PCRYPTO_DEVICE Device
);

VOID CryptoDeviceInterruptDisable(
    _In_ PCRYPTO_DEVICE Device
);

_Success_(return != 0)
BOOLEAN CryptoDeviceInerruptGetFlags(
    _In_ PCRYPTO_DEVICE Device,
    _Out_ PMSI_FLAGS Msi
);

VOID CryptoDeviceInterruptHandler(
    _In_ PCRYPTO_DEVICE Device,
    _In_ PMSI_FLAGS Msi
);

VOID CryptoDeviceProgramDmaIn(
    _In_ PCRYPTO_DEVICE Device,
    _In_ ULONG32 DmaAddress,
    _In_ ULONG32 DmaPagesCount,
    _In_ ULONG32 DmaSizeInBytes
);

VOID CryptoDeviceProgramDmaOut(
    _In_ PCRYPTO_DEVICE Device,
    _In_ ULONG32 DmaAddress,
    _In_ ULONG32 DmaPagesCount,
    _In_ ULONG32 DmaSizeInBytes
);

NTSTATUS CryptoDeviceWaitForReadyOrError(
    _In_ PCRYPTO_DEVICE Device,
    _In_opt_ PLARGE_INTEGER Timeout
);

NTSTATUS CryptoDeviceWaitReset(
    _In_ PCRYPTO_DEVICE Device
);

EXTERN_C_END