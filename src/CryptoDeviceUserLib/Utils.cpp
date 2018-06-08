#include "stdafx.h"
#include "Utils.h"

namespace utils
{
    std::string Utf16To8(const std::wstring& utf16)
    {
#pragma warning(suppress: 4996) //deprecated
        return std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t>().to_bytes(utf16);
    }

    std::wstring Utf8To16(const std::string& utf8, bool nothrow)
    {
        try
        {
#pragma warning(suppress: 4996) //deprecated
            return std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(utf8);
        }
        catch (const std::exception&)
        {
            if (nothrow)
            {
                return std::wstring();
            }
            throw;
        }
    }

    std::vector<std::wstring> GetDevicePath(GUID interfaceGuid)
    {
        ULONG deviceInterfaceListLength = 0;
        CONFIGRET cr = CM_Get_Device_Interface_List_SizeW(&deviceInterfaceListLength
            , &interfaceGuid
            , NULL
            , CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

        if (cr != CR_SUCCESS)
        {
            THROW("CM_Get_Device_Interface_List_Size error 0x" << std::hex << cr);
        }

        if (0 == deviceInterfaceListLength)
        {
            THROW("CM_Get_Device_Interface_List_Size error zero length");
        }

        if (1 == deviceInterfaceListLength)
        {
            THROW("Interface not found");
        }

        std::vector<wchar_t> deviceInterfaceList(deviceInterfaceListLength);

        cr = CM_Get_Device_Interface_ListW(&interfaceGuid
            , NULL
            , deviceInterfaceList.data()
            , deviceInterfaceListLength
            , CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

        if (cr != CR_SUCCESS)
        {
            THROW("CM_Get_Device_Interface_List error 0x" << std::hex << cr);
        }

        std::vector<std::wstring> devices;
        size_t index = 0;

        while (deviceInterfaceList.at(index) != L'\0')
        {
            devices.push_back(&deviceInterfaceList.at(index));
            index += devices.back().size() + 1;
        }

        return devices;
    }
}