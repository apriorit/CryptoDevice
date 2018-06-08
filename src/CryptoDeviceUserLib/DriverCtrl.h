#pragma once
#include "Utils.h"
#include <string>
#include <vector>
#include <functional>

namespace utils
{
    class DriverCtrl
    {
    public:
        enum class IoctlResult
        {
            Ok,
            BadOutputLength
        };

        using IoctlToString = std::function<std::string(DWORD)>;

    public:
        explicit DriverCtrl(const std::wstring& driverPath);
        DriverCtrl(const std::wstring& driverPath, IoctlToString ioctlToString);

        IoctlResult SendIOCTL(DWORD ioctl
            , void *in
            , size_t inSize
            , void *out
            , size_t& outSize) const;

        void SendIOCTL(DWORD ioctl
            , void *in
            , size_t inSize) const;

        void SendIOCTL(DWORD ioctl) const;

    private:
        static std::string DefaultIoctlToString(DWORD ioctl);

    private:
        utils::HandleFileGuard m_driver;
        IoctlToString m_ioctlToStr;
    };
}
