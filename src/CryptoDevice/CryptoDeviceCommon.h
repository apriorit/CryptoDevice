#pragma once

#include <ntifs.h>
#include <wdf.h>
#include <stddef.h>
#include <basetsd.h>

typedef UCHAR uint8_t;
typedef USHORT uint16_t;
typedef ULONG uint32_t;
typedef ULONGLONG uint64_t;

#include "CryptoDeviceProtocol.h"

static_assert(CRYPTO_DEVICE_PAGE_SHIFT == PAGE_SHIFT, "Unexpected CRYPTO_DEVICE_PAGE_SHIFT");

#define NT_BREAK() KdBreakPoint()
#define NT_CHECK($expression) { NTSTATUS $s = ($expression); if (!NT_SUCCESS($s)) { NT_BREAK(); return $s; }}
#define NT_CHECK_GOTO_CLEAN($expression) { status = ($expression); if (!NT_SUCCESS(status)) { NT_BREAK(); goto clean; }}
#define NT_CHECK_BREAK($expression) { status = ($expression); if (!NT_SUCCESS(status)) { NT_BREAK(); break; }}

