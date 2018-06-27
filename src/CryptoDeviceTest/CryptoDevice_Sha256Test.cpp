#include "stdafx.h"
#include "CryptoDeviceCtrl.h"
#include "HashSha256.h"

namespace
{
    class CryptoDevice_Sha256 : public ::testing::Test
    {
    protected:
        CryptoDevice_Sha256()
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

        void CheckBuffer(const void * data, size_t size) const
        {
            auto devHash = m_driver->Sha256(data, size);
            auto devHashStr = utils::BytesToHexString(devHash);

            utils::HashSha256 sha256;
            sha256.Update(data, size);
            auto apiHashStr = sha256.GetHash();

            EXPECT_EQ(apiHashStr, devHashStr);
        }

        void TestHash(size_t sizeOfBuffer, size_t offsetInBufer, size_t sizeOfHashData, int initVal) const
        {
            utils::VirtualAllocGuard mem(VirtualAlloc(NULL, sizeOfBuffer, MEM_COMMIT, PAGE_READWRITE));
            THROW_IF(!mem, "VirtualAlloc failed");
            memset(mem.get(), initVal, sizeOfBuffer);

            THROW_IF(sizeOfHashData + offsetInBufer > sizeOfBuffer, "Out of buffer");
            CheckBuffer(static_cast<uint8_t*>(mem.get()) + offsetInBufer, sizeOfHashData);
        }

        std::unique_ptr<crypto::CryptoDeviceCtrl> m_driver;
        const size_t m_onePageSize = CRYPTO_DEVICE_PAGE_SIZE;
    };
}

TEST_F(CryptoDevice_Sha256, FuncInterfaces)
{
    const std::array<uint8_t, 10> data{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };

    crypto::CryptoDeviceCtrl::Sha256Buffer hash1 = {};
    m_driver->Sha256(data.data(), data.size(), hash1);
    
    std::vector<uint8_t> hash2 = m_driver->Sha256(data.data(), data.size());

    EXPECT_EQ(hash1.size(), hash2.size());
    EXPECT_EQ(0, memcmp(hash1.data(), hash2.data(), hash1.size()));
}

TEST_F(CryptoDevice_Sha256, NullBuffer)
{
    crypto::CryptoDeviceCtrl::Sha256Buffer hash = {};

    EXPECT_THROW(m_driver->Sha256(nullptr, 0, hash), std::exception);
    EXPECT_THROW(m_driver->Sha256(nullptr, 1, hash), std::exception);

    EXPECT_THROW(m_driver->Sha256(nullptr, 0), std::exception);
    EXPECT_THROW(m_driver->Sha256(nullptr, 1), std::exception);
}

TEST_F(CryptoDevice_Sha256, ZeroLenght)
{
    const std::array<uint8_t, 1> data{ 1 };

    crypto::CryptoDeviceCtrl::Sha256Buffer hash = {};
    m_driver->Sha256(data.data(), 0, hash);

    const std::string hashStr = utils::BytesToHexString(hash);
    EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hashStr);
}

TEST_F(CryptoDevice_Sha256, HashSize)
{
    const std::array<uint8_t, 1> data { 0 };

    auto hash1 = m_driver->Sha256(data.data(), 1);
    EXPECT_EQ(32, hash1.size());

    crypto::CryptoDeviceCtrl::Sha256Buffer hash2 = {};
    EXPECT_EQ(32, hash2.size());
    EXPECT_EQ(32, crypto::CryptoDeviceCtrl::Sha256Size);
}

TEST_F(CryptoDevice_Sha256, Basic)
{
    const std::array<uint8_t, 3> data{ '1', '2', '3' };

    crypto::CryptoDeviceCtrl::Sha256Buffer hash = {};
    m_driver->Sha256(data.data(), data.size(), hash);

    const std::string hashStr = utils::BytesToHexString(hash);
    EXPECT_EQ("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", hashStr);
}

TEST_F(CryptoDevice_Sha256, OnePageAligned)
{
    TestHash(m_onePageSize, 0, m_onePageSize, 11);
}

TEST_F(CryptoDevice_Sha256, OnePageNonAligned)
{
    TestHash(2 * m_onePageSize, 100, m_onePageSize, 22);
}

TEST_F(CryptoDevice_Sha256, MiddleOfPage)
{
    TestHash(m_onePageSize, 200, 10, 33);
}

TEST_F(CryptoDevice_Sha256, TwoPagesAligned)
{
    TestHash(2 * m_onePageSize, 0, 2 * m_onePageSize, 44);
}

TEST_F(CryptoDevice_Sha256, TwoPagesNonAligned)
{
    TestHash(3 * m_onePageSize, 300, 2 * m_onePageSize, 55);
}

TEST_F(CryptoDevice_Sha256, BigData)
{
    TestHash(100 * m_onePageSize, 300, 99 * m_onePageSize, 66);
}
