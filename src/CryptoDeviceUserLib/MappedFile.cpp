#include "stdafx.h"
#include "MappedFile.h"

namespace utils
{
    MappedFile::MappedFile(LPCWSTR fileName, 
        DWORD desiredAccess, 
        DWORD creationDisposition, 
        DWORD shareMode, 
        DWORD sectionProtect, 
        DWORD sectionSize,
        DWORD viewDesiredAccess,
        DWORD viewOffset,
        DWORD viewSize)
    {
        m_file = CreateFile(fileName, desiredAccess, shareMode, NULL, creationDisposition, FILE_ATTRIBUTE_NORMAL, NULL);
        THROW_WIN_IF(!m_file, "Cannot open file " << Utf16To8(fileName));

        m_section = CreateFileMapping(m_file, NULL, sectionProtect, 0, sectionSize, NULL);
        THROW_WIN_IF(!m_section, "Cannot map file " << Utf16To8(fileName));

        m_viewSize = viewSize;
        m_view = MapViewOfFile(m_section, viewDesiredAccess, 0, viewOffset, viewSize);
        THROW_WIN_IF(!m_view, "Cannot view file " << Utf16To8(fileName));
    }

    DWORD MappedFile::GetViewSize() const
    {
        return m_viewSize;
    }

    PVOID MappedFile::GetViewData() const
    {
        assert(!!m_view);
        return m_view;
    }
}
