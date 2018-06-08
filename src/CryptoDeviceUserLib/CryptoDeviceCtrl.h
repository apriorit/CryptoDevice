#pragma once

#include "DriverCtrl.h"
#include "CryptoDeviceStruct.h"

namespace crypto
{
    class CryptoDeviceCtrl
    {
    public:
        const size_t SHA256_SIZE = 64;

    public:
        explicit CryptoDeviceCtrl(const std::wstring& interfaceName);

        void ResetDevice() const;
        DeviceStatus GetDeviceStatus() const;

        void AesCbcEncrypt(void * bufferIn, size_t bufferInSize, void * bufferOut, size_t bufferOutSize) const;
        void AesCbcDecrypt(void * bufferIn, size_t bufferInSize, void * bufferOut, size_t bufferOutSize) const;
        std::vector<uint8_t> Sha256(void * buffer, size_t bufferSize) const;

    private:
        void AesCbcImpl(void * bufferIn, size_t bufferInSize, void * bufferOut, size_t bufferOutSize, DWORD ioctl) const;
        static std::string IoctlToString(DWORD ioctl);

    private:
        utils::DriverCtrl m_device;
    };
}