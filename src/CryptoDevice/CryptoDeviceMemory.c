#include "CryptoDeviceMemory.h"
#include "CryptoDeviceCommon.h"
#include <limits.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, MemCreateUserBufferMdl)
#pragma alloc_text (PAGE, MemCreateDmaForUserBuffer)
#endif

NTSTATUS MemCreateUserBufferMdl(
    _In_ PVOID Buffer,
    _In_ ULONG Size,
    _In_ LOCK_OPERATION Operation,
    _Out_ PMDL * Mdl
)
{
    PAGED_CODE();

    PMDL mdl = IoAllocateMdl(Buffer, Size, FALSE, FALSE, NULL);

    if (!mdl)
    {
        return STATUS_NO_MEMORY;
    }

    __try
    {
        MmProbeAndLockPages(mdl, UserMode, Operation);
        *Mdl = mdl;
        return STATUS_SUCCESS;
    }
#pragma warning(suppress : 6320) // Exception - filter expression is the constant EXCEPTION_EXECUTE_HANDLER.
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        IoFreeMdl(mdl);
        return GetExceptionCode();
    }
}

VOID MemFreeUserBufferMdl(
    _In_ PMDL Mdl
)
{
    MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);
}

NTSTATUS MemCreateDmaForUserBuffer(
    _In_ PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _In_ LOCK_OPERATION Operation,
    _Out_ PDMA_USER_MEMORY Dma
)
{
    PAGED_CODE();

    PMDL userMdl = NULL;
    PULONG64 kernelVa = NULL;

    ULONG32 countOfPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(UserBuffer, UserBufferSize);
    ULONG64 contigMemSize = countOfPages * sizeof(ULONG64);

    if (0 == countOfPages || contigMemSize > ULONG_MAX)
    {
        return STATUS_UNSUCCESSFUL;
    }

    NT_CHECK(MemCreateUserBufferMdl(UserBuffer, UserBufferSize, Operation, &userMdl));

    const PHYSICAL_ADDRESS physZero = { 0 };
    PHYSICAL_ADDRESS phys = { 0 };
    phys.QuadPart = CRYPTO_DEVICE_DMA_MAX;

    kernelVa = MmAllocateContiguousMemorySpecifyCache(
        contigMemSize,
        physZero,
        phys,
        physZero,
        MmNonCached);

    if (!kernelVa)
    {
        MemFreeUserBufferMdl(userMdl);
        return STATUS_NO_MEMORY;
    }

    PPFN_NUMBER pfn = MmGetMdlPfnArray(userMdl);
    kernelVa[0] = pfn[0] + MmGetMdlByteOffset(userMdl);

    for (ULONG i = 1; i < countOfPages; ++i)
    {
        kernelVa[i] = pfn[i];
    }

    phys = MmGetPhysicalAddress(kernelVa);
    ASSERT(phys.QuadPart < CRYPTO_DEVICE_DMA_MAX);

    Dma->DmaAddress = CRYPTO_DEVICE_TO_DMA(phys.QuadPart);
    Dma->UserBufferMdl = userMdl;
    Dma->KernelContigVa = kernelVa;
    Dma->DmaCountOfPages = countOfPages;

    return STATUS_SUCCESS;
}

VOID MemFreeDma(
    _Inout_ PDMA_USER_MEMORY Dma
)
{
    if (Dma->KernelContigVa)
    {
        MmFreeContiguousMemory(Dma->KernelContigVa);
        Dma->KernelContigVa = NULL;
    }

    if (Dma->UserBufferMdl)
    {
        MemFreeUserBufferMdl(Dma->UserBufferMdl);
        Dma->UserBufferMdl = NULL;
    }
}