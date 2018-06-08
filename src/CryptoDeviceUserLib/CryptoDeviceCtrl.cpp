#include "stdafx.h"
#include "CryptoDeviceCtrl.h"

#include <initguid.h>
#include "CryptoDevice\Public.h"

namespace
{
    void Unpack(const CryptoDeviceStatus& in, crypto::DeviceStatus& out)
    {
        out.ErrorCode = gsl::narrow<CryptoDeviceErrorCode>(in.ErrorCode);
        out.State = gsl::narrow<CryptoDeviceState>(in.State);
    }

    void Pack(void * buffer, size_t size, CryptoDeviceBuffer& out)
    {
        THROW_IF(!buffer, "The buffer is null");
        out.Address = reinterpret_cast<ULONG_PTR>(buffer);
        out.Size = gsl::narrow<UINT32>(size);
    }
}

namespace crypto
{
    CryptoDeviceCtrl::CryptoDeviceCtrl(const std::wstring& interfaceName)
        : m_device(interfaceName, IoctlToString)
    {
    }

    void CryptoDeviceCtrl::ResetDevice() const
    {
        m_device.SendIOCTL(IOCTL_CRYPTO_DEVICE_RESET);
    }

    DeviceStatus CryptoDeviceCtrl::GetDeviceStatus() const
    {
        CryptoDeviceStatus status = {};
        size_t size = sizeof(status);

        m_device.SendIOCTL(IOCTL_CRYPTO_DEVICE_GET_STATUS, nullptr, 0, &status, size);
        THROW_IF(size != sizeof(status), "Unexpected out size for DeviceStatus");

        DeviceStatus result;
        Unpack(status, result);

        return result;
    }

    void CryptoDeviceCtrl::AesCbcEncrypt(void * bufferIn, size_t bufferInSize, void * bufferOut, size_t bufferOutSize) const
    {
        AesCbcImpl(bufferIn, bufferInSize, bufferOut, bufferOutSize, IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT);
    }

    void CryptoDeviceCtrl::AesCbcDecrypt(void * bufferIn, size_t bufferInSize, void * bufferOut, size_t bufferOutSize) const
    {
        AesCbcImpl(bufferIn, bufferInSize, bufferOut, bufferOutSize, IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT);
    }

    std::vector<uint8_t> CryptoDeviceCtrl::Sha256(void * buffer, size_t bufferSize) const
    {
        utils::VirtualAllocGuard sha256Buf = VirtualAlloc(NULL, SHA256_SIZE, MEM_COMMIT, PAGE_READWRITE);
        THROW_WIN_IF(!sha256Buf, "Cannot allocate memory for SHA256");

        CryptoDeviceBufferInOut buf = {};
        Pack(buffer, bufferSize, buf.In);
        Pack(sha256Buf.get(), SHA256_SIZE, buf.Out);

        m_device.SendIOCTL(IOCTL_CRYPTO_DEVICE_SHA256, &buf, sizeof(buf));

        const auto sha256Data = static_cast<uint8_t*>(sha256Buf.get());
        return std::vector<uint8_t>(sha256Data, sha256Data + SHA256_SIZE);
    }

    void CryptoDeviceCtrl::AesCbcImpl(void * bufferIn, size_t bufferInSize, void * bufferOut, size_t bufferOutSize, DWORD ioctl) const
    {
        CryptoDeviceBufferInOut buf = {};
        Pack(bufferIn, bufferInSize, buf.In);
        Pack(bufferOut, bufferOutSize, buf.Out);
        m_device.SendIOCTL(ioctl, &buf, sizeof(buf));
    }

    std::string CryptoDeviceCtrl::IoctlToString(DWORD ioctl)
    {
        switch (ioctl)
        {
        case IOCTL_CRYPTO_DEVICE_RESET:
            return "DeviceReset";

        case IOCTL_CRYPTO_DEVICE_GET_STATUS:
            return "DeviceGetState";

        case IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT:
            return "DeviceAesCbcEncrypt";

        case IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT:
            return "DeviceAesCbcDecrypt";

        case IOCTL_CRYPTO_DEVICE_SHA256:
            return "DeviceSha256";
        }

        std::stringstream st;
        st << std::hex << "0x" << ioctl;
        return st.str();
    }
}
