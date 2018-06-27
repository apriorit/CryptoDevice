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

inline std::wostream& operator << (std::wostream& out, const CryptoDeviceErrorCode& error)
{
    switch (error)
    {
    case CryptoDevice_NoError:
        out << "no error";
        break;
    case CryptoDevice_DmaError:
        out << "dma error";
        break;
    case CryptoDevice_ResetError:
        out << "reset error";
        break;
    case CryptoDevice_WriteIoError:
        out << "write IO error";
        break;
    case CryptoDevice_InternalError:
        out << "internal error";
        break;
    default:
        out << "unkonwn error";
    }

    out << " (" << std::dec << static_cast<unsigned int>(error) << ")";
    return out;
}

inline std::wostream& operator << (std::wostream& out, const CryptoDeviceState& state)
{
    switch (state)
    {
    case CryptoDevice_ReadyState:
        out << "ReadyState";
        break;
    case CryptoDevice_ResetState:
        out << "ResetState";
        break;
    case CryptoDevice_AesCbcState:
        out << "AesCbcState";
        break;
    case CryptoDevice_Sha2State:
        out << "Sha2State";
        break;
    default:
        out << "UnkonwnState";
    }

    out << " (" << std::dec << static_cast<unsigned int>(state) << ")";
    return out;
}