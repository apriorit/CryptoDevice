#include "stdafx.h"
#include "CryptoDeviceCtrl.h"

namespace
{
    class CryptoDevice_AesCbc : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            auto devices = crypto::CryptoDeviceCtrl::GetDevicesIds();
            m_driver.reset(new crypto::CryptoDeviceCtrl(devices.at(0)));
            m_driver->ResetDevice();
        }

        void TearDown() override
        {
            auto status = m_driver->GetDeviceStatus();
            EXPECT_EQ(CryptoDevice_NoError, status.ErrorCode);
            EXPECT_EQ(CryptoDevice_ReadyState, status.State);
        }

        void TestEncrypt(const void * in, size_t inSize, void * out, size_t outSize) const
        {
            EXPECT_TRUE(inSize > outSize);

            std::vector<uint8_t> inCopy(inSize);
            memcpy(inCopy.data(), in, inSize);

            m_driver->AesCbcEncrypt(in, inSize, out, outSize);
            EXPECT_EQ(0, memcmp(in, inCopy.data(), inSize));
            EXPECT_NE(0, memcmp(in, out, inSize));
        }

        void TestDecrypt(const void * in, size_t inSize, void * out, size_t outSize) const
        {
            EXPECT_TRUE(inSize > outSize);

            std::vector<uint8_t> inCopy(inSize);
            memcpy(inCopy.data(), in, inSize);

            m_driver->AesCbcDecrypt(in, inSize, out, outSize);
            EXPECT_EQ(0, memcmp(in, inCopy.data(), inSize));
            EXPECT_NE(0, memcmp(in, out, inSize));
        }

        void TestBufferAligments(size_t size, size_t sizeToEncrypt, size_t offsetInInBuffer, size_t offsetInOutBuffer, uint8_t initVal)
        {
            const size_t totalSize = size + 3 * m_onePageSize; // for guarded pages and aligment for encrypted data
            const uint8_t guarededPagesByte = initVal + 1;

            const std::vector<uint8_t> pageGuard(m_onePageSize, guarededPagesByte);
            const std::vector<uint8_t> plainText(sizeToEncrypt, initVal);

            THROW_IF(sizeToEncrypt + offsetInInBuffer > size, "Out of buffer");
            THROW_IF(sizeToEncrypt + offsetInOutBuffer > size, "Out of buffer");

            const size_t sizeOfEncrypted = crypto::CryptoDeviceCtrl::GetAesOutBufferSize(sizeToEncrypt);
            const size_t ecryptedDecryptedDiff = sizeOfEncrypted - sizeToEncrypt;

            //
            // In memory
            //
            utils::VirtualAllocGuard inMem(VirtualAlloc(NULL, totalSize, MEM_COMMIT, PAGE_READWRITE));
            THROW_IF(!inMem, "VirtualAlloc failed");

            uint8_t * inPageGuard1Start = static_cast<uint8_t*>(inMem.get()) + offsetInInBuffer;
            uint8_t * inBufferStart = inPageGuard1Start + m_onePageSize;
            uint8_t * inPageGuard2Start = inBufferStart + sizeToEncrypt;

            memset(inMem.get(), guarededPagesByte, totalSize);
            memset(inBufferStart, initVal, sizeToEncrypt);

            //
            // Out memory
            //
            utils::VirtualAllocGuard outMem(VirtualAlloc(NULL, totalSize, MEM_COMMIT, PAGE_READWRITE));
            THROW_IF(!outMem, "VirtualAlloc failed");

            uint8_t * outPageGuard1Start = static_cast<uint8_t*>(outMem.get()) + offsetInOutBuffer;
            uint8_t * outBufferStart = outPageGuard1Start + m_onePageSize;
            uint8_t * outPageGuard2Start = outBufferStart + sizeOfEncrypted;

            memset(outMem.get(), guarededPagesByte, totalSize);

            //
            // Encrypt and check IN,OUT buffer guards and encrypted data
            //
            m_driver->AesCbcEncrypt(inBufferStart, sizeToEncrypt, outBufferStart, sizeOfEncrypted);

            EXPECT_EQ(0, memcmp(inPageGuard1Start, pageGuard.data(), m_onePageSize));
            EXPECT_EQ(0, memcmp(inPageGuard2Start, pageGuard.data(), m_onePageSize));

            EXPECT_EQ(0, memcmp(outPageGuard1Start, pageGuard.data(), m_onePageSize));
            EXPECT_EQ(0, memcmp(outPageGuard2Start, pageGuard.data(), m_onePageSize));

            EXPECT_EQ(0, memcmp(inBufferStart, plainText.data(), sizeToEncrypt));
            EXPECT_NE(0, memcmp(inBufferStart, outBufferStart, sizeToEncrypt));


            //
            // Decrypt and check IN,OUT buffer guards and encrypted data
            //
            memcpy(inBufferStart, outBufferStart, sizeOfEncrypted);
            inPageGuard2Start += ecryptedDecryptedDiff;
            m_driver->AesCbcDecrypt(inBufferStart, sizeOfEncrypted, outBufferStart, sizeOfEncrypted);

            EXPECT_EQ(0, memcmp(inPageGuard1Start, pageGuard.data(), m_onePageSize));
            EXPECT_EQ(0, memcmp(inPageGuard2Start, pageGuard.data(), m_onePageSize));

            EXPECT_EQ(0, memcmp(outPageGuard1Start, pageGuard.data(), m_onePageSize));
            EXPECT_EQ(0, memcmp(outPageGuard2Start, pageGuard.data(), m_onePageSize));

            EXPECT_EQ(0, memcmp(outBufferStart, plainText.data(), sizeToEncrypt));
            EXPECT_NE(0, memcmp(inBufferStart, outBufferStart, sizeOfEncrypted));
        }

        std::unique_ptr<crypto::CryptoDeviceCtrl> m_driver;
        const size_t m_onePageSize = CRYPTO_DEVICE_PAGE_SIZE;
    };
}

TEST_F(CryptoDevice_AesCbc, EncryptArgs)
{
    int dummy = 0;
    EXPECT_THROW(m_driver->AesCbcEncrypt(nullptr, 0, nullptr, 0), std::exception);
    EXPECT_THROW(m_driver->AesCbcEncrypt(&dummy, 0, nullptr, 0), std::exception);
    EXPECT_THROW(m_driver->AesCbcEncrypt(nullptr, 0, &dummy, 0), std::exception);
    EXPECT_THROW(m_driver->AesCbcEncrypt(nullptr, 1, nullptr, 0), std::exception);
    EXPECT_THROW(m_driver->AesCbcEncrypt(nullptr, 0, nullptr, 1), std::exception);
    EXPECT_THROW(m_driver->AesCbcEncrypt(nullptr, 1, nullptr, 1), std::exception);
    EXPECT_THROW(m_driver->AesCbcEncrypt(&dummy, 1, nullptr, 1), std::exception);
    EXPECT_THROW(m_driver->AesCbcEncrypt(nullptr, 1, &dummy, 1), std::exception);
}

TEST_F(CryptoDevice_AesCbc, DecryptArgs)
{
    int dummy = 0;
    EXPECT_THROW(m_driver->AesCbcDecrypt(nullptr, 0, nullptr, 0), std::exception);
    EXPECT_THROW(m_driver->AesCbcDecrypt(&dummy, 0, nullptr, 0), std::exception);
    EXPECT_THROW(m_driver->AesCbcDecrypt(nullptr, 0, &dummy, 0), std::exception);
    EXPECT_THROW(m_driver->AesCbcDecrypt(nullptr, 1, nullptr, 0), std::exception);
    EXPECT_THROW(m_driver->AesCbcDecrypt(nullptr, 0, nullptr, 1), std::exception);
    EXPECT_THROW(m_driver->AesCbcDecrypt(nullptr, 1, nullptr, 1), std::exception);
    EXPECT_THROW(m_driver->AesCbcDecrypt(&dummy, 1, nullptr, 1), std::exception);
    EXPECT_THROW(m_driver->AesCbcDecrypt(nullptr, 1, &dummy, 1), std::exception);
}

TEST_F(CryptoDevice_AesCbc, EncryptDecrypt)
{
    const std::string data = "1234567890qwertyuiopasdfghjklzxcvbnm";
    std::vector<uint8_t> decrypted(crypto::CryptoDeviceCtrl::GetAesOutBufferSize(data.size()));
    std::vector<uint8_t> encrypted(crypto::CryptoDeviceCtrl::GetAesOutBufferSize(data.size()));

    TestEncrypt(data.data(), data.size(), encrypted.data(), encrypted.size());
    TestDecrypt(encrypted.data(), encrypted.size(), decrypted.data(), decrypted.size());

    EXPECT_EQ(0, memcmp(data.data(), decrypted.data(), data.size()));
    EXPECT_NE(0, memcmp(data.data(), encrypted.data(), data.size()));
}

TEST_F(CryptoDevice_AesCbc, EncryptDecryptBigData)
{
    std::vector<uint8_t> data(m_onePageSize * 100, 'A');
    std::vector<uint8_t> decrypted(crypto::CryptoDeviceCtrl::GetAesOutBufferSize(data.size()));
    std::vector<uint8_t> encrypted(crypto::CryptoDeviceCtrl::GetAesOutBufferSize(data.size()));

    TestEncrypt(data.data(), data.size(), encrypted.data(), encrypted.size());
    TestDecrypt(encrypted.data(), encrypted.size(), decrypted.data(), decrypted.size());

    EXPECT_EQ(0, memcmp(data.data(), decrypted.data(), data.size()));
    EXPECT_NE(0, memcmp(data.data(), encrypted.data(), data.size()));
}

TEST_F(CryptoDevice_AesCbc, EncryptDecryptInPlace)
{
    const std::string data = "1234567890qwertyuiopasdfghjklzxcvbnm";
    std::vector<uint8_t> encrypted(crypto::CryptoDeviceCtrl::GetAesOutBufferSize(data.size()));
    memcpy(encrypted.data(), data.data(), data.size());

    TestEncrypt(encrypted.data(), encrypted.size(), encrypted.data(), encrypted.size());
    EXPECT_NE(0, memcmp(data.data(), encrypted.data(), data.size()));

    std::vector<uint8_t> decrypted(encrypted.begin(), encrypted.end());
    TestDecrypt(decrypted.data(), decrypted.size(), decrypted.data(), decrypted.size());
    EXPECT_EQ(0, memcmp(data.data(), decrypted.data(), data.size()));
}

TEST_F(CryptoDevice_AesCbc, EncryptDecryptInPlaceBigData)
{
    std::vector<uint8_t> data(m_onePageSize * 100, 'A');
    std::vector<uint8_t> encrypted(crypto::CryptoDeviceCtrl::GetAesOutBufferSize(data.size()));
    memcpy(encrypted.data(), data.data(), data.size());

    TestEncrypt(encrypted.data(), encrypted.size(), encrypted.data(), encrypted.size());
    EXPECT_NE(0, memcmp(data.data(), encrypted.data(), data.size()));

    std::vector<uint8_t> decrypted(encrypted.begin(), encrypted.end());
    TestDecrypt(decrypted.data(), decrypted.size(), decrypted.data(), decrypted.size());
    EXPECT_EQ(0, memcmp(data.data(), decrypted.data(), data.size()));
}

TEST_F(CryptoDevice_AesCbc, EncryptBadOutBufferLength)
{
    std::vector<uint8_t> in(100, 0);
    std::vector<uint8_t> out(in.size() - 1);

    EXPECT_THROW(TestEncrypt(in.data(), in.size(), out.data(), out.size()), std::exception);
    EXPECT_EQ(CryptoDevice_DmaError, m_driver->GetDeviceStatus().ErrorCode);
    m_driver->ResetDevice();

    EXPECT_THROW(TestEncrypt(in.data(), in.size(), out.data(), 0), std::exception);
    EXPECT_EQ(CryptoDevice_DmaError, m_driver->GetDeviceStatus().ErrorCode);
    m_driver->ResetDevice();
}

TEST_F(CryptoDevice_AesCbc, DecryptBadOutBufferLength)
{
    std::vector<uint8_t> in(100, 0);
    std::vector<uint8_t> out(in.size() - 1);

    EXPECT_THROW(TestDecrypt(in.data(), in.size(), out.data(), out.size()), std::exception);
    EXPECT_EQ(CryptoDevice_DmaError, m_driver->GetDeviceStatus().ErrorCode);
    m_driver->ResetDevice();

    EXPECT_THROW(TestDecrypt(in.data(), in.size(), out.data(), 0), std::exception);
    EXPECT_EQ(CryptoDevice_DmaError, m_driver->GetDeviceStatus().ErrorCode);
    m_driver->ResetDevice();
}

TEST_F(CryptoDevice_AesCbc, EncryptBadAddress)
{
    std::vector<uint8_t> in(100, 0);
    std::vector<uint8_t> out(in.size());

    EXPECT_THROW(TestEncrypt(reinterpret_cast<PVOID>(1), in.size(), out.data(), out.size()), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, m_driver->GetDeviceStatus().ErrorCode);

    EXPECT_THROW(TestEncrypt(in.data(), in.size(), reinterpret_cast<PVOID>(1), out.size()), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, m_driver->GetDeviceStatus().ErrorCode);
}

TEST_F(CryptoDevice_AesCbc, DecryptBadAddress)
{
    std::vector<uint8_t> in(100, 0);
    std::vector<uint8_t> out(in.size());

    EXPECT_THROW(TestDecrypt(reinterpret_cast<PVOID>(1), in.size(), out.data(), out.size()), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, m_driver->GetDeviceStatus().ErrorCode);

    EXPECT_THROW(TestDecrypt(in.data(), in.size(), reinterpret_cast<PVOID>(1), out.size()), std::exception);
    EXPECT_EQ(CryptoDevice_NoError, m_driver->GetDeviceStatus().ErrorCode);
}

TEST_F(CryptoDevice_AesCbc, BufferOnePageAligned)
{
    TestBufferAligments(m_onePageSize, m_onePageSize, 0, 0, 11);
}

TEST_F(CryptoDevice_AesCbc, BufferOnePageNotAligned)
{
    TestBufferAligments(2 * m_onePageSize, m_onePageSize, 100, 0, 22);
    TestBufferAligments(2 * m_onePageSize, m_onePageSize, 0, 100, 23);
}

TEST_F(CryptoDevice_AesCbc, BufferMiddleOfPage)
{
    TestBufferAligments(m_onePageSize, 200, 100, 0, 33);
    TestBufferAligments(m_onePageSize, 200, 0, 100, 34);
}

TEST_F(CryptoDevice_AesCbc, BufferTwoPageAligned)
{
    TestBufferAligments(2 * m_onePageSize, 2 * m_onePageSize, 0, 0, 44);
}

TEST_F(CryptoDevice_AesCbc, BufferTwoPageNotAligned)
{
    TestBufferAligments(3 * m_onePageSize, 2 * m_onePageSize, 250, 0, 55);
    TestBufferAligments(3 * m_onePageSize, 2 * m_onePageSize, 0, 250, 55);
}
