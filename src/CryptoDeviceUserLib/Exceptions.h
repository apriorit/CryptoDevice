#pragma once

#include <sstream>
#include <system_error>

#define THROW_IF($cond, $mess) if ($cond) { THROW($mess); }
#define THROW($mess) {                      \
    std::stringstream $st;                  \
    $st << $mess;                           \
    throw std::runtime_error($st.str());    \
}

#define THROW_WIN_IF($cond, $mess) if ($cond) { THROW_WIN($mess); }
#define THROW_WIN($mess) {                                      \
    DWORD $lastError = ::GetLastError();                        \
    std::error_code $ec($lastError, std::system_category());    \
    std::stringstream $st;                                      \
    $st << $mess;                                               \
    throw std::system_error($ec, $st.str());                    \
}
