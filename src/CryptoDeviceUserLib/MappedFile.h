#pragma once

#include "Utils.h"

namespace utils
{
    class MappedFile
    {
    public:
        MappedFile();
        MappedFile(LPCWSTR fileName,
                    DWORD desiredAccess,
                    DWORD creationDisposition,
                    DWORD shareMode,
                    DWORD sectionProtect,
                    DWORD sectionSize,
                    DWORD viewDesiredAccess,
                    DWORD viewOffset,
                    DWORD viewSize);

        ~MappedFile() = default;

        MappedFile(const MappedFile&) = delete;
        MappedFile& operator=(const MappedFile&) = delete;

        MappedFile(MappedFile&&) = default;
        MappedFile& operator=(MappedFile&&) = default;

        DWORD GetViewSize() const;
        PVOID GetViewData() const;

        template<typename T>
        T* GetViewPointer(DWORD offset = 0) const
        {
            THROW_IF(offset > m_viewSize, "Out of view pointer");
            THROW_IF(sizeof(T) > m_viewSize, "Out of view pointer");
            THROW_IF(offset > (m_viewSize - sizeof(T)), "Out of view pointer");
            auto start = static_cast<uint8_t*>(GetViewData());
            if constexpr (std::is_same_v<T, uint8_t>)
            {
                return start + offset;
            }
            else
            {
                return reinterpret_cast<T*>(start + offset);
            }
        }

    private:
        HandleFileGuard m_file;
        HandleGuard m_section;
        MapViewGuard m_view;
        DWORD m_viewSize;
    };
}

