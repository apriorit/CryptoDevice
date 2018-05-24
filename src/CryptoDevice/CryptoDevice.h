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

    KEVENT ErrorEvent;
    KEVENT ReadyEvent;

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

NTSTATUS CryptoDeviceDoCommand(
    _In_ PCRYPTO_DEVICE Device,
    _In_ CryptoDeviceCommand Command
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
    _In_ ULONG32 DmaAddr,
    _In_ ULONG32 DmaCountOfPages
);

VOID CryptoDeviceProgramDmaOut(
    _In_ PCRYPTO_DEVICE Device,
    _In_ ULONG32 DmaAddr,
    _In_ ULONG32 DmaCountOfPages
);

NTSTATUS CryptoDeviceWaitForReadyOrError(
    _In_ PCRYPTO_DEVICE Device,
    _In_opt_ PLARGE_INTEGER Timeout
);

EXTERN_C_END