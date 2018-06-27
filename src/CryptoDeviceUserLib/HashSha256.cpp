#include "stdafx.h"
#include "HashSha256.h"

namespace utils
{
    HashSha256::HashSha256()
    {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&m_provider
            , BCRYPT_SHA256_ALGORITHM
            , NULL
            , 0);
        THROW_IF(!BCRYPT_SUCCESS(status), "BCryptOpenAlgorithmProvider error 0x" << status);

        ULONG outSize = 0;
        ULONG hashSize = 0;

        status = BCryptGetProperty(m_provider
            , BCRYPT_HASH_LENGTH
            , reinterpret_cast<PUCHAR>(&hashSize)
            , sizeof(hashSize)
            , &outSize
            , 0);
        THROW_IF(!BCRYPT_SUCCESS(status), "BCryptGetProperty error 0x" << status);

        if (outSize != sizeof(hashSize) || hashSize != m_hashData.size())
        {
            THROW("Unexpected size of SHA256 hash");
        }

        ULONG hashObjectSize = 0;
        status = BCryptGetProperty(m_provider
            , BCRYPT_OBJECT_LENGTH
            , reinterpret_cast<PUCHAR>(&hashObjectSize)
            , sizeof(hashObjectSize)
            , &outSize
            , 0);
        THROW_IF(!BCRYPT_SUCCESS(status), "BCryptGetProperty error 0x" << status);

        if (outSize != sizeof(hashObjectSize) || 0 == hashObjectSize)
        {
            THROW("Unexpected size of SHA256 hash object");
        }

        m_hashObject.resize(hashObjectSize);
        Reinit(nullptr, 0);
    }

    void HashSha256::Reinit(const void* data, size_t size)
    {
        m_hash.reset();
        const NTSTATUS status = BCryptCreateHash(m_provider
            , &m_hash
            , m_hashObject.data()
            , gsl::narrow<ULONG>(m_hashObject.size())
            , NULL
            , 0
            , 0);
        THROW_IF(!BCRYPT_SUCCESS(status), "BCryptCreateHash error 0x" << status);
        m_hashData.fill(0);

        m_finished = false;
        Update(data, size);
    }

    void HashSha256::Update(const void* data, size_t size) 
    {
        //
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375468(v=vs.85).aspx
        // MSDN: This function does not modify the contents of this buffer.
        //
#pragma warning(suppress : 26492) //Dont use const_cast to cast away const (type.3)
        PUCHAR pData = static_cast<PUCHAR>(const_cast<void*>(data));
        const NTSTATUS status = BCryptHashData(m_hash.get()
            , pData
            , gsl::narrow<ULONG>(size)
            , 0);
        THROW_IF(!BCRYPT_SUCCESS(status), "BCryptHashData error 0x" << status);
    }

    std::string HashSha256::GetHash()
    {
        std::stringstream st;
        Finalize(st);
        return st.str();
    }

    void HashSha256::CloseProvider(PVOID handle) noexcept
    {
        BCryptCloseAlgorithmProvider(handle, 0);
    }

    void HashSha256::CloseHash(PVOID handle) noexcept
    {
        BCryptDestroyHash(handle);
    }

    void HashSha256::Finalize()
    {
        if (m_finished)
        {
            return;
        }

        const NTSTATUS status = BCryptFinishHash(m_hash
            , m_hashData.data()
            , gsl::narrow<ULONG>(m_hashData.size())
            , 0);
        THROW_IF(!BCRYPT_SUCCESS(status), "BCryptFinishHash error 0x" << status);
        m_finished = true;
    }

    void HashSha256::Finalize(std::ostream& st)
    {
        Finalize();

        THROW_IF(m_hashData.max_size() != 0x20, "Invalid m_hashData size");

#define HEX_BYTE($byte) std::hex << std::setfill('0') << std::setw(2) << static_cast<uint16_t>($byte)

        st  << HEX_BYTE(gsl::at(m_hashData, 0x00)) << HEX_BYTE(gsl::at(m_hashData, 0x01)) << HEX_BYTE(gsl::at(m_hashData, 0x02)) << HEX_BYTE(gsl::at(m_hashData, 0x03))
            << HEX_BYTE(gsl::at(m_hashData, 0x04)) << HEX_BYTE(gsl::at(m_hashData, 0x05)) << HEX_BYTE(gsl::at(m_hashData, 0x06)) << HEX_BYTE(gsl::at(m_hashData, 0x07)) 
            << HEX_BYTE(gsl::at(m_hashData, 0x08)) << HEX_BYTE(gsl::at(m_hashData, 0x09)) << HEX_BYTE(gsl::at(m_hashData, 0x0a)) << HEX_BYTE(gsl::at(m_hashData, 0x0b))
            << HEX_BYTE(gsl::at(m_hashData, 0x0c)) << HEX_BYTE(gsl::at(m_hashData, 0x0d)) << HEX_BYTE(gsl::at(m_hashData, 0x0e)) << HEX_BYTE(gsl::at(m_hashData, 0x0f))
            << HEX_BYTE(gsl::at(m_hashData, 0x10)) << HEX_BYTE(gsl::at(m_hashData, 0x11)) << HEX_BYTE(gsl::at(m_hashData, 0x12)) << HEX_BYTE(gsl::at(m_hashData, 0x13))
            << HEX_BYTE(gsl::at(m_hashData, 0x14)) << HEX_BYTE(gsl::at(m_hashData, 0x15)) << HEX_BYTE(gsl::at(m_hashData, 0x16)) << HEX_BYTE(gsl::at(m_hashData, 0x17))
            << HEX_BYTE(gsl::at(m_hashData, 0x18)) << HEX_BYTE(gsl::at(m_hashData, 0x19)) << HEX_BYTE(gsl::at(m_hashData, 0x1a)) << HEX_BYTE(gsl::at(m_hashData, 0x1b))
            << HEX_BYTE(gsl::at(m_hashData, 0x1c)) << HEX_BYTE(gsl::at(m_hashData, 0x1d)) << HEX_BYTE(gsl::at(m_hashData, 0x1e)) << HEX_BYTE(gsl::at(m_hashData, 0x1f));

#undef HEX_BYTE
    }
}
