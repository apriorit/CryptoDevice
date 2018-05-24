#include "CryptoDeviceMemory.h"
#include "CryptoDeviceCommon.h"
#include <limits.h>

NTSTATUS MemCreateUserBufferMdl(
    _In_ PVOID Buffer,
    _In_ ULONG Size,
    _In_ LOCK_OPERATION Operation,
    _Out_ PMDL * Mdl
)
{
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
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    IoFreeMdl(mdl);
    return STATUS_ACCESS_VIOLATION;
}

VOID MemFreeUserBufferMdl(
    _In_ PMDL Mdl
)
{
    MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);
}

PVOID MemAllocateContigPhysMemory(
    _In_ ULONG Size,
    _Out_ PMDL * Mdl
)
{
    const PHYSICAL_ADDRESS skipBytes = { 0 };
    const PHYSICAL_ADDRESS lowAddress = { 0 };
    PHYSICAL_ADDRESS highAddress = { 0 };

    highAddress.QuadPart = CRYPTO_DEVICE_DMA_MAX;

    PMDL mdl = MmAllocatePagesForMdlEx(
        lowAddress,
        highAddress,
        skipBytes,
        ROUND_TO_PAGES(Size),
        MmCached,
        MM_ALLOCATE_FULLY_REQUIRED | MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS);

    if (!mdl)
    {
        return NULL;
    }

    PVOID kernelVa = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmCached,
        NULL,
        FALSE,
        NormalPagePriority | MdlMappingNoExecute);

    if (!kernelVa)
    {
        MmFreePagesFromMdl(mdl);
        return NULL;
    }

    *Mdl = mdl;
    return kernelVa;
}

VOID MemFreeContigPhysMemory(
    _In_ PVOID KernelVa,
    _In_ PMDL Mdl
)
{
    MmUnmapLockedPages(KernelVa, Mdl);
    MmFreePagesFromMdl(Mdl);
}

NTSTATUS MemCreateDmaForUserBuffer(
    _In_ PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _In_ LOCK_OPERATION Operation,
    _Out_ PDMA_USER_MEMORY Dma
)
{
    PMDL userMdl = NULL;
    PULONG64 kernelVa = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    ULONG32 countOfPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(UserBuffer, UserBufferSize);
    ULONG64 contigMemSize = countOfPages * sizeof(ULONG64);

    if (0 == countOfPages || contigMemSize > ULONG_MAX)
    {
        return STATUS_UNSUCCESSFUL;
    }

    NT_CHECK_GOTO_CLEAN(MemCreateUserBufferMdl(UserBuffer, UserBufferSize, Operation, &userMdl));

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
        goto clean;
    }

    PPFN_NUMBER pfn = MmGetMdlPfnArray(userMdl);

    ASSERT(pfn[0] <= ULONG_MAX);
    kernelVa[0] = (ULONG)pfn[0] + MmGetMdlByteOffset(userMdl);

    for (ULONG i = 1; i < countOfPages; ++i)
    {
        ASSERT(pfn[i] <= ULONG_MAX);
        kernelVa[i] = (ULONG)pfn[i];
    }

    phys = MmGetPhysicalAddress(DmaBuffer->ConfigBuf);
    DmaBuffer->ConfigDmaAddr = VARJO_PHYS_TO_DMA(phys.QuadPart);

    return STATUS_SUCCESS;











    kernelVa = MemAllocateContigPhysMemory(kernelMdl);

        clean:
    if (userInMdl)
    {
        MemFreeUserBufferMdl(userInMdl);
    }
    if (userOutMdl)
    {
        MemFreeUserBufferMdl(userOutMdl);
    }
    if (kernelMdl)
    {
        MemFreeContigPhysMemory(kernelVa, kernelMdl);
    }
    return status;
}
