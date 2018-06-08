#pragma once

#include "Common\CryptoDeviceProtocol.h"

namespace crypto
{
    struct DeviceStatus
    {
        CryptoDeviceState State;
        CryptoDeviceErrorCode ErrorCode;
    };
}