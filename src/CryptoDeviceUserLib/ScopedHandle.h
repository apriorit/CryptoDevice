#pragma once
#include <assert.h>

namespace utils
{
    template <typename HandleType, typename FreeFnType, FreeFnType *FreeFn, HandleType ZeroHandle = 0>
    class ScopedHandle
    {
    public:
        ScopedHandle(HandleType h = ZeroHandle) noexcept
            : m_Handle(h)
        {
        }
        ~ScopedHandle() noexcept
        {
            reset();
        }
        
        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;
        
        ScopedHandle(ScopedHandle&& other) noexcept
        {
            m_Handle = other.m_Handle;
            other.m_Handle = ZeroHandle;
        }
        ScopedHandle& operator=(ScopedHandle&& other) noexcept
        {
            if (this == std::addressof(other))
            {
                return *this;
            }
            reset(other.release());
            return *this;
        }
        void reset(HandleType h = ZeroHandle) noexcept
        {
            if (m_Handle == h)
            {
                return;
            }
            if (m_Handle != ZeroHandle)
            {
                FreeFn(m_Handle);
            }
            m_Handle = h;
        }
        HandleType release() noexcept
        {
            HandleType tmp = m_Handle;
            m_Handle = ZeroHandle;
            return tmp;
        }
        HandleType get() const noexcept
        {
            return m_Handle;
        }
        operator HandleType() const noexcept
        {
            assert(m_Handle != ZeroHandle);
            return m_Handle;
        }
        HandleType* operator &() noexcept
        {
            assert(m_Handle == ZeroHandle);
            return &m_Handle;
        }
        explicit operator bool() const noexcept
        {
            return (m_Handle != ZeroHandle);
        }
    private:
        HandleType m_Handle;
    };
}
