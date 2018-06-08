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

    std::string Utf16To8(const std::wstring& utf16);
    std::wstring Utf8To16(const std::string& utf8, bool nothrow = false);
    
    std::vector<std::wstring> GetDevicePath(GUID interfaceGuid);
}