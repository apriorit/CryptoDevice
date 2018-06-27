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

    void Pack(const void * buffer, size_t size, CryptoDeviceBuffer& out)
    {
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

    void CryptoDeviceCtrl::AesCbcEncrypt(const void * bufferIn, size_t bufferInSize, void * bufferOut, size_t bufferOutSize) const
    {
        AesCbcImpl(bufferIn, bufferInSize, bufferOut, bufferOutSize, IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT);
    }

    void CryptoDeviceCtrl::AesCbcDecrypt(const void * bufferIn, size_t bufferInSize, void * bufferOut, size_t bufferOutSize) const
    {
        AesCbcImpl(bufferIn, bufferInSize, bufferOut, bufferOutSize, IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT);
    }

    std::vector<uint8_t> CryptoDeviceCtrl::Sha256(const void * buffer, size_t bufferSize) const
    {
        Sha256Buffer hash { 0 };
        Sha256(buffer, bufferSize, hash);
        return std::vector<uint8_t>(hash.begin(), hash.end());
    }

    void CryptoDeviceCtrl::Sha256(const void * buffer, size_t bufferSize, Sha256Buffer& hash) const
    {
        utils::VirtualAllocGuard sha256Buf = VirtualAlloc(NULL, Sha256Size, MEM_COMMIT, PAGE_READWRITE);
        THROW_WIN_IF(!sha256Buf, "Cannot allocate memory for SHA256");

        CryptoDeviceBufferInOut buf = {};
        Pack(buffer, bufferSize, buf.In);
        Pack(sha256Buf.get(), Sha256Size, buf.Out);

        m_device.SendIOCTL(IOCTL_CRYPTO_DEVICE_SHA256, &buf, sizeof(buf));
        memcpy(hash.data(), sha256Buf.get(), hash.size());
    }

    std::vector<std::wstring> CryptoDeviceCtrl::GetDevicesIds()
    {
        return utils::GetDevicePath(GUID_DEVINTERFACE_CRYPTO);
    }

    size_t CryptoDeviceCtrl::GetAesOutBufferSize(size_t inBufferSize)
    {
        const size_t tail = inBufferSize % AesBlockSize;

        if (0 != tail)
        {
            inBufferSize += (AesBlockSize - tail);
        }

        return inBufferSize;
    }

    void CryptoDeviceCtrl::AesCbcImpl(const void * bufferIn, size_t bufferInSize, void * bufferOut, size_t bufferOutSize, DWORD ioctl) const
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
