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

_Function_class_(EVT_WDF_PROGRAM_DMA)
_IRQL_requires_same_
_IRQL_requires_(DISPATCH_LEVEL)
static BOOLEAN MemEvtProgramDma(
    _In_ WDFDMATRANSACTION Transaction,
    _In_ WDFDEVICE Device,
    _In_ PDMA_USER_MEMORY Memory,
    _In_ WDF_DMA_DIRECTION Direction,
    _In_ PSCATTER_GATHER_LIST SgList
)
{
    UNREFERENCED_PARAMETER(Transaction);
    UNREFERENCED_PARAMETER(Direction);
    UNREFERENCED_PARAMETER(Device);

    ULONG dmaBufIndex = 0;
    PULONG64 dmaBufVa = (PULONG64)WdfCommonBufferGetAlignedVirtualAddress(Memory->DmaBuffer);

    for (ULONG i = 0; i < SgList->NumberOfElements; ++i)
    {
        ULONG32 size = SgList->Elements[i].Length;
        ULONG64 addr = SgList->Elements[i].Address.QuadPart;

        if (0 == size || 0 == addr || 0 != (addr & ~CRYPTO_DEVICE_DMA_MAX))
        {
            //
            // Unexpected size of logical device address
            //
            return FALSE;
        }

        while (size)
        {
            if (dmaBufIndex >= Memory->DmaCountOfPages)
            {
                //
                // Logic error, dmaBufIndex is out of dmaBufVa range
                //
                return FALSE;
            }

            dmaBufVa[dmaBufIndex++] = addr;

            const ULONG pageOffset = addr & CRYPTO_DEVICE_PAGE_MASK;
            const ULONG sizeToNextPage = (0 != pageOffset)
                ? CRYPTO_DEVICE_PAGE_SIZE - pageOffset
                : CRYPTO_DEVICE_PAGE_SIZE;

            size -= min(size, sizeToNextPage);
            addr += sizeToNextPage;
        }
    }

    if (Memory->DmaCountOfPages != dmaBufIndex)
    {
        //
        // Logic error, final count of SG items should be equal to Memory->DmaCountOfPages
        //
        return FALSE;
    }

    return TRUE;
}

NTSTATUS MemCreateDmaForUserBuffer(
    _In_ PVOID UserBuffer,
    _In_ ULONG UserBufferSize,
    _In_ WDFDMAENABLER DmaEnabler,
    _In_ BOOLEAN WriteToDevice,
    _Out_ PDMA_USER_MEMORY Dma
)
{
    PAGED_CODE();

    RtlZeroMemory(Dma, sizeof(*Dma));

    //
    // Check buffer size
    //
    const ULONG32 countOfPages = ADDRESS_AND_SIZE_TO_SPAN_PAGES(UserBuffer, UserBufferSize);
    const ULONG64 contigMemSize = countOfPages * sizeof(ULONG64);

    if (0 == countOfPages || 0 == contigMemSize || contigMemSize > ULONG_MAX)
    {
        return STATUS_UNSUCCESSFUL;
    }
    
    //
    // Create MDL and validate the memory range
    //
    LOCK_OPERATION op = WriteToDevice ? IoWriteAccess : IoReadAccess;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    NT_CHECK_GOTO_CLEAN(MemCreateUserBufferMdl(UserBuffer, UserBufferSize, op, &Dma->UserBufferMdl));

    //
    // Allocate contiguouse DMA meory for SG pages
    //
    Dma->DmaCountOfPages = countOfPages;
    Dma->DmaBufferSize = (ULONG32)contigMemSize;

    WDF_COMMON_BUFFER_CONFIG dmaBufConfig;
    WDF_COMMON_BUFFER_CONFIG_INIT(&dmaBufConfig, CRYPTO_DEVICE_PAGE_MASK);
    NT_CHECK_GOTO_CLEAN(WdfCommonBufferCreateWithConfig(
        DmaEnabler,
        Dma->DmaBufferSize,
        &dmaBufConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &Dma->DmaBuffer));

    PVOID dmaBufVa = WdfCommonBufferGetAlignedVirtualAddress(Dma->DmaBuffer);
    PHYSICAL_ADDRESS dmaBufPa = WdfCommonBufferGetAlignedLogicalAddress(Dma->DmaBuffer);
    RtlZeroMemory(dmaBufVa, Dma->DmaBufferSize);

    Dma->DmaAddress = CRYPTO_DEVICE_TO_DMA(dmaBufPa.QuadPart);

    if (0 != (dmaBufPa.QuadPart & CRYPTO_DEVICE_PAGE_MASK))
    {
        goto clean;
    }

    //
    // Create DMA transaction
    //
    NT_CHECK_GOTO_CLEAN(WdfDmaTransactionCreate(
        DmaEnabler,
        WDF_NO_OBJECT_ATTRIBUTES,
        &Dma->DmaTransaction));

    PVOID va = MmGetMdlVirtualAddress(Dma->UserBufferMdl);
    ULONG length = MmGetMdlByteCount(Dma->UserBufferMdl);

    ASSERT(va == UserBuffer);
    ASSERT(length == UserBufferSize);

    if (0 == length)
    {
        goto clean;
    }

    WDF_DMA_DIRECTION dmaDirection = WriteToDevice ? WdfDmaDirectionWriteToDevice : WdfDmaDirectionReadFromDevice;
    NT_CHECK_GOTO_CLEAN(WdfDmaTransactionInitialize(
        Dma->DmaTransaction,
        MemEvtProgramDma,
        dmaDirection,
        Dma->UserBufferMdl,
        va,
        length));

    //
    // Fill out contiguouse memory with SG values
    //
    NT_CHECK_GOTO_CLEAN(WdfDmaTransactionExecute(Dma->DmaTransaction, Dma));

    return STATUS_SUCCESS;

clean:
    if (Dma->DmaTransaction)
    {
        (VOID) WdfDmaTransactionDmaCompletedFinal(Dma->DmaTransaction, 0, &status);
    }
    MemFreeDma(Dma);
    return status;
}

VOID MemFreeDma(
    _Inout_ PDMA_USER_MEMORY Dma
)
{
    Dma->DmaAddress = 0;
    Dma->DmaCountOfPages = 0;
    Dma->DmaBufferSize = 0;
    
    if (Dma->DmaTransaction)
    {
        WdfObjectDelete(Dma->DmaTransaction);
        Dma->DmaTransaction = NULL;
    }

    if (Dma->DmaBuffer)
    {
        WdfObjectDelete(Dma->DmaBuffer);
        Dma->DmaBuffer = NULL;
    }
    
    if (Dma->UserBufferMdl)
    {
        MemFreeUserBufferMdl(Dma->UserBufferMdl);
        Dma->UserBufferMdl = NULL;
    }
}