#pragma once

#include "Exceptions.h"
#include "ScopedHandle.h"

#include <vector>
#include <string>
#include <windows.h>
#include <shlobj.h>

#pragma comment(lib, "Cfgmgr32.lib")

namespace utils
{
    inline void VirtualFreeRelease(PVOID addr) noexcept
    {
        VirtualFree(addr, 0, MEM_RELEASE);
    }

    using HandleGuard = ScopedHandle<HANDLE, decltype(::CloseHandle), ::CloseHandle, NULL>;
    using HandleFileGuard = ScopedHandle<HANDLE, decltype(::CloseHandle), ::CloseHandle, INVALID_HANDLE_VALUE>;
    using VirtualAllocGuard = ScopedHandle<PVOID, decltype(VirtualFreeRelease), VirtualFreeRelease, NULL>;
    using MapViewGuard = ScopedHandle<PVOID, decltype(::UnmapViewOfFile), ::UnmapViewOfFile, NULL>;

    std::string Utf16To8(const std::wstring& utf16);
    std::wstring Utf8To16(const std::string& utf8, bool nothrow = false);
    
    std::vector<std::wstring> GetDevicePath(GUID interfaceGuid);

    uint64_t GetFileSize(const wchar_t* fileName);

    template<typename Container>
    void BytesToHex(const Container& c, std::ostream& out)
    {
        for (const auto& i : c)
        {
            static_assert(sizeof(i) == sizeof(uint8_t), "Unexpected size");
            out << std::hex << std::setfill('0') << std::setw(2) << gsl::narrow<uint16_t>(gsl::narrow_cast<uint8_t>(i));
        }
    }

    template<typename Container>
    std::string BytesToHexString(const Container& c)
    {
        std::stringstream st;
        BytesToHex(c, st);
        return st.str();
    }
}