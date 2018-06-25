#include "stdafx.h"
#include "DriverCtrl.h"
#include "CryptoDeviceCtrl.h"
#include "CryptoDevice\Public.h"

namespace
{
    class CryptoDevice_Ioctl : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            auto devices = crypto::CryptoDeviceCtrl::GetDevicesIds();
            m_driver.reset(new utils::DriverCtrl(devices.at(0)));
            ResetDevice();
        }

        CryptoDeviceErrorCode GetDeviceError() const
        {
            CryptoDeviceStatus status = {};
            size_t size = sizeof(status);

            m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_GET_STATUS, nullptr, 0, &status, size);
            THROW_IF(size != sizeof(status), "Unexpected out size for DeviceStatus");

            return static_cast<CryptoDeviceErrorCode>(status.ErrorCode);
        }

        void ResetDevice() const
        {
            m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_RESET);
        }

        CryptoDeviceBuffer CreateBuffer(const void * buffer, size_t size)
        {
            CryptoDeviceBuffer out = {};
            out.Address = reinterpret_cast<ULONG_PTR>(buffer);
            out.Size = gsl::narrow<UINT32>(size);
            return out;
        }

        std::unique_ptr<utils::DriverCtrl> m_driver;
    };
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_GET_STATUS_Ok)
{
    CryptoDeviceStatus status = {};
    size_t size = sizeof(status);
    EXPECT_NO_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_GET_STATUS, nullptr, 0, &status, size));
    EXPECT_EQ(sizeof(status), size);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_GET_STATUS_InvalidOutSize)
{
    CryptoDeviceStatus status = {};
    size_t size = sizeof(status) - 1;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_GET_STATUS, nullptr, 0, &status, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_GET_STATUS_InvalidOutNullPtr)
{
    CryptoDeviceStatus status = {};
    size_t size = sizeof(status);
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_GET_STATUS, nullptr, 0, nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_GET_STATUS_InvalidOutPtr)
{
    CryptoDeviceStatus status = {};
    size_t size = sizeof(status);
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_GET_STATUS, nullptr, 0, reinterpret_cast<void*>(1), size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_RESET_Ok)
{
    size_t size = 0;
    EXPECT_NO_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_RESET, nullptr, 0, nullptr, size));
    EXPECT_EQ(0, size);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_SHA256_Ok)
{
    const std::array<uint8_t, 3> data{ '1', '2', '3' };
    crypto::CryptoDeviceCtrl::Sha256Buffer out{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(data.data(), data.size());
    buf.Out = CreateBuffer(out.data(), out.size());

    size_t size = 0;
    EXPECT_NO_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_SHA256, &buf, sizeof(buf), nullptr, size));
    EXPECT_EQ(0, size);

    const std::string hashStr = utils::BytesToHexString(out);
    EXPECT_EQ("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", hashStr);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_SHA256_BadInSize)
{
    const std::array<uint8_t, 3> data{ '1', '2', '3' };
    crypto::CryptoDeviceCtrl::Sha256Buffer out{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(data.data(), data.size());
    buf.Out = CreateBuffer(out.data(), out.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_SHA256, &buf, sizeof(buf) - 1, nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_SHA256_InBadAddr)
{
    const std::array<uint8_t, 3> data{ '1', '2', '3' };
    crypto::CryptoDeviceCtrl::Sha256Buffer out{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In.Address = 100;
    buf.In.Size = gsl::narrow<ULONG>(data.size());
    buf.Out = CreateBuffer(out.data(), out.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_SHA256, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_SHA256_InNullAddr)
{
    const std::array<uint8_t, 3> data{ '1', '2', '3' };
    crypto::CryptoDeviceCtrl::Sha256Buffer out{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(nullptr, data.size());
    buf.Out = CreateBuffer(out.data(), out.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_SHA256, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_SHA256_InZeroSize)
{
    const std::array<uint8_t, 3> data{ '1', '2', '3' };
    crypto::CryptoDeviceCtrl::Sha256Buffer out{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(data.data(), 0);
    buf.Out = CreateBuffer(out.data(), out.size());

    size_t size = 0;
    EXPECT_NO_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_SHA256, &buf, sizeof(buf), nullptr, size));
    EXPECT_EQ(0, size);

    const std::string hashStr = utils::BytesToHexString(out);
    EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hashStr);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_SHA256_OutBadAddr)
{
    const std::array<uint8_t, 3> data{ '1', '2', '3' };
    crypto::CryptoDeviceCtrl::Sha256Buffer out{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(data.data(), data.size());
    buf.Out.Address = 100;
    buf.Out.Size = gsl::narrow<ULONG>(out.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_SHA256, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_SHA256_OutNullAddr)
{
    const std::array<uint8_t, 3> data{ '1', '2', '3' };
    crypto::CryptoDeviceCtrl::Sha256Buffer out{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(data.data(), data.size());
    buf.Out.Address = 0;
    buf.Out.Size = gsl::narrow<ULONG>(out.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_SHA256, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_SHA256_OutBadSize)
{
    const std::array<uint8_t, 3> data{ '1', '2', '3' };
    crypto::CryptoDeviceCtrl::Sha256Buffer out{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(data.data(), data.size());
    buf.Out = CreateBuffer(out.data(), out.size() - 1);

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_SHA256, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_DmaError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_SHA256_OutZeroSize)
{
    const std::array<uint8_t, 3> data{ '1', '2', '3' };
    crypto::CryptoDeviceCtrl::Sha256Buffer out{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(data.data(), data.size());
    buf.Out = CreateBuffer(out.data(), 0);

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_SHA256, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT_Ok)
{
    std::array<uint8_t, 3> plain{ '1', '2', '3' };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), plain.size());
    buf.Out = CreateBuffer(secret.data(), secret.size());

    size_t size = 0;
    EXPECT_NO_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT, &buf, sizeof(buf), nullptr, size));
    EXPECT_EQ(0, size);
    EXPECT_NE(0, memcmp(plain.data(), secret.data(), plain.size()));
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT_BadInSize)
{
    std::array<uint8_t, 3> plain{ '1', '2', '3' };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), plain.size());
    buf.Out = CreateBuffer(secret.data(), secret.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT, &buf, sizeof(buf) - 1, nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT_InBadAddr)
{
    std::array<uint8_t, 3> plain{ '1', '2', '3' };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(reinterpret_cast<PVOID>(0xffffffffffffffff), plain.size());
    buf.Out = CreateBuffer(secret.data(), secret.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT_InNullAddr)
{
    std::array<uint8_t, 3> plain{ '1', '2', '3' };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(nullptr, plain.size());
    buf.Out = CreateBuffer(secret.data(), secret.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT_InZeroSize)
{
    std::array<uint8_t, 3> plain{ '1', '2', '3' };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), 0);
    buf.Out = CreateBuffer(secret.data(), secret.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT_OutBadAddr)
{
    std::array<uint8_t, 3> plain{ '1', '2', '3' };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), plain.size());
    buf.Out = CreateBuffer(reinterpret_cast<PVOID>(100), secret.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT_OutNullAddr)
{
    std::array<uint8_t, 3> plain{ '1', '2', '3' };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), plain.size());
    buf.Out = CreateBuffer(nullptr, secret.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT_OutBadSize)
{
    std::array<uint8_t, 3> plain{ '1', '2', '3' };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), plain.size());
    buf.Out = CreateBuffer(secret.data(), secret.size() - 1);

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_DmaError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT_OutZeroSize)
{
    std::array<uint8_t, 3> plain{ '1', '2', '3' };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), plain.size());
    buf.Out = CreateBuffer(secret.data(), 0);

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT_Ok)
{
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> plain{ 0 };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), plain.size());
    buf.Out = CreateBuffer(secret.data(), secret.size());

    size_t size = 0;
    EXPECT_NO_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT, &buf, sizeof(buf), nullptr, size));
    EXPECT_EQ(0, size);
    EXPECT_NE(0, memcmp(plain.data(), secret.data(), plain.size()));
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT_BadInSize)
{
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> plain{ 0 };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), plain.size());
    buf.Out = CreateBuffer(secret.data(), secret.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT, &buf, sizeof(buf) - 1, nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT_InBadAddr)
{
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> plain{ 0 };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(reinterpret_cast<PVOID>(0xffffffffffffffff), plain.size());
    buf.Out = CreateBuffer(secret.data(), secret.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT_InNullAddr)
{
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> plain{ 0 };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(nullptr, plain.size());
    buf.Out = CreateBuffer(secret.data(), secret.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT_InZeroSize)
{
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> plain{ 0 };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), 0);
    buf.Out = CreateBuffer(secret.data(), secret.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT_OutBadAddr)
{
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> plain{ 0 };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), plain.size());
    buf.Out = CreateBuffer(reinterpret_cast<PVOID>(100), secret.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT_OutNullAddr)
{
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> plain{ 0 };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), plain.size());
    buf.Out = CreateBuffer(nullptr, secret.size());

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT_OutBadSize)
{
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> plain{ 0 };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), plain.size());
    buf.Out = CreateBuffer(secret.data(), secret.size() - 1);

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_DmaError, GetDeviceError());
}

TEST_F(CryptoDevice_Ioctl, IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT_OutZeroSize)
{
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> plain{ 0 };
    std::array<uint8_t, crypto::CryptoDeviceCtrl::AesBlockSize> secret{ 0 };

    CryptoDeviceBufferInOut buf = {};
    buf.In = CreateBuffer(plain.data(), plain.size());
    buf.Out = CreateBuffer(secret.data(), 0);

    size_t size = 0;
    EXPECT_THROW(m_driver->SendIOCTL(IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT, &buf, sizeof(buf), nullptr, size), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, GetDeviceError());
}
