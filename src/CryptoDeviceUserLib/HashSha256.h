#pragma once
#include "Utils.h"

#pragma comment(lib, "bcrypt.lib")

namespace utils
{
    class HashSha256
    {
    public:

    public:
        HashSha256();

        void Reinit(const void* data, size_t size);
        void Update(const void* data, size_t size);
        std::string GetHash();

    private:
        static void CloseProvider(PVOID handle) noexcept;
        static void CloseHash(PVOID handle) noexcept;

        using ProviderHandle = ScopedHandle<PVOID, decltype(CloseProvider), CloseProvider>;
        using HashHandle = ScopedHandle<PVOID, decltype(CloseHash), CloseHash>;
        using HashBuffer = std::array<UCHAR, 32>;

        void Finalize();
        void Finalize(std::ostream& st);

        friend std::ostream& operator << (std::ostream& os, HashSha256& sha256);

    private:
        ProviderHandle m_provider;
        std::vector<UCHAR> m_hashObject;
        HashHandle m_hash;
        HashBuffer m_hashData;
        bool m_finished = false;
    };

    inline std::ostream& operator << (std::ostream& os, HashSha256& sha256)
    {
        sha256.Finalize(os);
        return os;
    }
}
