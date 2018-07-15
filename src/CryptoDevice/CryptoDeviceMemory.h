#pragma once

#include <ntifs.h>
#include <wdf.h>

EXTERN_C_START

typedef struct _DMA_USER_MEMORY
{
    PMDL UserBufferMdl;

    ULONG32 DmaAddress;
    ULONG32 DmaCountOfPages;
    ULONG32 DmaBufferSize;

    WDFCOMMONBUFFER DmaBuffer;
    WDFDMATRANSACTION DmaTransaction;

} DMA_USER_MEMORY, *PDMA_USER_MEMORY;

NTSTATUS MemCreateUserBufferMdl(
    _In_ PVOID Buffer,
    _In_ ULONG Size,
    _In_ LOCK_OPERATION Operation,
    _Out_ PMDL * Mdl
);

VOID MemFreeUserBufferMdl(
    _In_ PMDL Mdl
);

NTSTATUS MemCreateDmaForUserBuffer(
    _In_ PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _In_ WDFDMAENABLER DmaEnabler,
    _In_ BOOLEAN WriteToDevice,
    _Out_ PDMA_USER_MEMORY Dma
);

VOID MemFreeDma(
    _Inout_ PDMA_USER_MEMORY Dma
);

EXTERN_C_END
