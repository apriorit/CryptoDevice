#pragma once

#include "CryptoDevice.h"

typedef struct _DEVICE_STATE
{
    CryptoDeviceState State;
    CryptoDeviceErrorCode Error;
} DEVICE_STATE, *PDEVICE_STATE;

EXTERN_C_START

NTSTATUS CryptoDeviceResetRequest(
    _In_ PCRYPTO_DEVICE Device
);

NTSTATUS CryptoDeviceAesCbcRequest(
    _In_ PCRYPTO_DEVICE Device,
    _In_ PVOID UserBufferIn,
    _In_ ULONG UserBufferInSize,
    _In_ PVOID UserBufferOut,
    _In_ ULONG UserBufferOutSize
);

NTSTATUS CryptoDeviceSha2CbcRequest(
    _In_ PCRYPTO_DEVICE Device,
    _In_ PVOID UserBufferIn,
    _In_ ULONG UserBufferInSize,
    _In_ PVOID UserBufferOut,
    _In_ ULONG UserBufferOutSize
);

NTSTATUS CryptoDeviceStateRequest(
    _In_ PCRYPTO_DEVICE Device,
    _Out_ PDEVICE_STATE State
);

EXTERN_C_END
