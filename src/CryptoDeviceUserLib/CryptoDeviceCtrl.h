#pragma once

#include "DriverCtrl.h"
#include "CryptoDeviceStruct.h"

namespace crypto
{
    class CryptoDeviceCtrl
    {
    public:
        static constexpr size_t AesBlockSize = 16;
        static constexpr size_t Sha256Size = 64;
        using Sha256Buffer = std::array<uint8_t, Sha256Size>;

    public:
        explicit CryptoDeviceCtrl(const std::wstring& interfaceName);

        void ResetDevice() const;
        DeviceStatus GetDeviceStatus() const;

        void AesCbcEncrypt(const void * bufferIn, size_t bufferInSize, void * bufferOut, size_t bufferOutSize) const;
        void AesCbcDecrypt(const void * bufferIn, size_t bufferInSize, void * bufferOut, size_t bufferOutSize) const;

        std::vector<uint8_t> Sha256(const void * buffer, size_t bufferSize) const;
        void Sha256(const void * buffer, size_t bufferSize, Sha256Buffer& hash) const;

        static std::vector<std::wstring> GetDevicesIds();
        static size_t GetAesOutBufferSize(size_t inBufferSize);

    private:
        void AesCbcImpl(const void * bufferIn, size_t bufferInSize, void * bufferOut, size_t bufferOutSize, DWORD ioctl) const;
        static std::string IoctlToString(DWORD ioctl);

    private:
        utils::DriverCtrl m_device;
    };
}