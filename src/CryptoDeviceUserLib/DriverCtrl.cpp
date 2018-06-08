#include "stdafx.h"
#include "DriverCtrl.h"

namespace utils
{
    DriverCtrl::DriverCtrl(const std::wstring& driverPath)
        : DriverCtrl(driverPath, DefaultIoctlToString)
    {
    }

    DriverCtrl::DriverCtrl(const std::wstring& driverPath, IoctlToString ioctlToString)
        : m_ioctlToStr(std::move(ioctlToString))
    {
        if (!m_ioctlToStr)
        {
            THROW("Invalid argument ioctlToString");
        }

        m_driver.reset(CreateFileW(driverPath.c_str()
            , GENERIC_READ | GENERIC_WRITE
            , 0
            , NULL
            , OPEN_EXISTING
            , FILE_FLAG_OVERLAPPED
            , NULL));
        THROW_WIN_IF(!m_driver, "Cannot open " << utils::Utf16To8(driverPath));
    }

    DriverCtrl::IoctlResult DriverCtrl::SendIOCTL(DWORD ioctl
        , void *in
        , size_t inSize
        , void *out
        , size_t& outSize) const
    {
        //
        // Send IO request to driver
        //
        DWORD bytesReturned = 0;
        const BOOL result = DeviceIoControl(m_driver
            , ioctl
            , in
            , gsl::narrow<DWORD>(inSize)
            , out
            , gsl::narrow<DWORD>(outSize)
            , &bytesReturned
            , nullptr);

        if (result)
        {
            outSize = bytesReturned;
            return IoctlResult::Ok;
        }

        switch (GetLastError())
        {
        case ERROR_IO_PENDING:
            //
            // The request was pended
            //
            THROW("Pending IO is not implemented");
            break;

        case ERROR_BAD_LENGTH:
            //
            // Output buffer is too small
            //
            outSize = bytesReturned;
            return IoctlResult::BadOutputLength;

        default:
            //
            // Error
            //
            THROW_WIN("IOCLT " << m_ioctlToStr(ioctl) << " failed");
        }
    }

    void DriverCtrl::SendIOCTL(DWORD ioctl
        , void *in
        , size_t inSize) const
    {
        size_t size = 0;
        const auto res = SendIOCTL(ioctl, in, inSize, nullptr, size);

        if (IoctlResult::Ok != res)
        {
            THROW_WIN("IOCTL " << m_ioctlToStr(ioctl) << " failed with reason " << static_cast<int>(res));
        }
    }

    void DriverCtrl::SendIOCTL(DWORD ioctl) const
    {
        size_t size = 0;
        const auto res = SendIOCTL(ioctl, nullptr, 0, nullptr, size);

        if (IoctlResult::Ok != res)
        {
            THROW_WIN("IOCTL " << m_ioctlToStr(ioctl) << " failed with reason " << static_cast<int>(res));
        }
    }

    std::string DriverCtrl::DefaultIoctlToString(DWORD ioctl)
    {
        std::stringstream st;
        st << "0x" << std::hex << ioctl;
        return st.str();
    }
}
