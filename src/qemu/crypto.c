#include <assert.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"

#include "../Common/CryptoDeviceProtocol.h"

#define TYPE_PCI_CRYPTO_DEV "pci-crypto"
#define PCI_CRYPTO_DEV($obj) OBJECT_CHECK(PCICryptoState, ($obj), TYPE_PCI_CRYPTO_DEV)

#define PRINT(...) printf("crypto: " __VA_ARGS__)
#define ASSERT($expr) if (!($expr)) { \
    PRINT("ASSERTION FAILED! (%s) in %s %s:%d\n", #$expr, __ASSERT_FUNCTION, __FILE__, __LINE__); \
}

static const unsigned char CRYPTO_DEVICE_AES_CBC_IV[32] = { 50, 173, 92, 223, 82, 154, 174, 43, 225, 92, 126, 46, 161, 158, 81, 99, 75, 234, 234, 192, 43, 235, 197, 208, 66, 133, 233, 189, 80, 222, 183, 193 }; // 256bit

typedef struct PCICryptoState
{
    /*< private >*/
    PCIDevice parent_obj;

    /*< public >*/
    MemoryRegion memio;
    CryptoDeviceIo * io;
    unsigned char memio_data[4096];
    unsigned char aes_cbc_key[32]; // 256bit

    QemuMutex io_mutex;
    QemuThread thread;
    QemuCond thread_cond;
    bool thread_running;

} PCICryptoState;

typedef struct DmaBuf
{
    uint64_t page_addr;   // address to the current page 
    uint32_t page_offset; // offset in the current page
    uint32_t size;        // size of the remaining data
} DmaBuf;

typedef struct DmaRequest
{
    DmaBuf in;
    DmaBuf out;
} DmaRequest;

//
// Working with interrupts
//
static void raise_interrupt(PCICryptoState * dev, CryptoDeviceMSI msi)
{
    const uint8_t msi_flag = (1u << msi) >> 1u;
    ASSERT(msi != CryptoDevice_MsiZero);

    if (0 == (dev->io->InterruptFlag & msi_flag))
    {
        PRINT("MSI %u is disabled\n", msi);
        return;
    }

    qemu_mutex_unlock(&dev->io_mutex);

    if (msi_enabled(&dev->parent_obj))
    {
        //
        // MSI is enabled
        //
        if (CryptoDevice_MsiMax != msi_nr_vectors_allocated(&dev->parent_obj))
        {
            PRINT("Send MSI 0 (origin msi =%u), allocated msi %u\n"
                , msi
                , msi_nr_vectors_allocated(&dev->parent_obj));
            msi = CryptoDevice_MsiZero;
        }
        else
        {
            PRINT("Send MSI %u\n", msi);
        }
        msi_notify(&dev->parent_obj, msi);
    }
    else
    {
        //
        // Raise legacy interrupt 
        //
        PRINT("Set legacy interrupt %u\n", msi);
        pci_set_irq(&dev->parent_obj, 1);
    }

    qemu_mutex_lock(&dev->io_mutex);
}

static void clear_interrupt(PCICryptoState * dev)
{
    if (!msi_enabled(&dev->parent_obj))
    {
        PRINT("Clear legacy interrupt\n");

        if (0 == dev->io->MsiErrorFlag && 0 == dev->io->MsiReadyFlag)
        {
            pci_set_irq(&dev->parent_obj, 0);
        }
    }
}

static void raise_error_int(PCICryptoState * dev, CryptoDeviceErrorCode error)
{
    PRINT("gererate error %d\n", error);
    ASSERT(error <= 0xff);

    dev->io->ErrorCode = (uint8_t)error;
    dev->io->MsiErrorFlag = 1;
    raise_interrupt(dev, CryptoDevice_MsiError);
}

static void raise_ready_int(PCICryptoState * dev)
{
    dev->io->MsiReadyFlag = 1;
    raise_interrupt(dev, CryptoDevice_MsiReady);
}

static void raise_reset_int(PCICryptoState * dev)
{
    dev->io->MsiResetFlag = 1;
    raise_interrupt(dev, CryptoDevice_MsiReset);
}

//
// Working with DMA 
//
static ssize_t rw_dma_data(PCICryptoState * dev, 
                            bool write,
                            DmaBuf * dma, 
                            uint8_t * data, 
                            uint32_t size)
{
    uint32_t rw_size = 0;

    while (0 != size)
    {
        if (0 == dma->size)
        {
            break;
        }

        uint64_t phys = 0;
        cpu_physical_memory_read(dma->page_addr, &phys, sizeof(phys));

        if (0 == phys)
        {
            return -1;
        }

        ASSERT(CRYPTO_DEVICE_PAGE_SIZE > dma->page_offset);
        ASSERT(CRYPTO_DEVICE_PAGE_SIZE > (dma->page_offset + (phys & CRYPTO_DEVICE_PAGE_MASK)));

        phys += dma->page_offset;

        const uint32_t size_to_page_end = CRYPTO_DEVICE_PAGE_SIZE - (phys & CRYPTO_DEVICE_PAGE_MASK);
        const uint32_t available_size_in_page = MIN(size_to_page_end, dma->size);
        const uint32_t size_to_rw = MIN(available_size_in_page, size);

        ASSERT(size_to_rw <= size);
        ASSERT(size_to_rw <= dma->size);
        ASSERT(size_to_rw <= CRYPTO_DEVICE_PAGE_SIZE);

        if (write)
        {
            cpu_physical_memory_write(phys, data, size_to_rw);
        }
        else
        {
            cpu_physical_memory_read(phys, data, size_to_rw);
        }

        data += size_to_rw;
        size -= size_to_rw;

        if (size_to_rw == size_to_page_end)
        {
            dma->page_addr += sizeof(uint64_t);
            dma->page_offset = 0;
        }
        else
        {
            dma->page_offset += size_to_rw;
            ASSERT(CRYPTO_DEVICE_PAGE_SIZE > dma->page_offset);
        }

        dma->size -= size_to_rw;
        rw_size += size_to_rw;
    }

    return rw_size;
}

//
// Commands handlers 
//
static void FillDmaRequest(PCICryptoState * dev, DmaRequest * dma)
{
    dma->in.page_offset = 0;
    dma->in.page_addr = CRYPTO_DEVICE_TO_PHYS(dev->io->DmaInAddress);
    dma->in.size = dev->io->DmaInSizeInBytes;

    dma->out.page_offset = 0;
    dma->out.page_addr = CRYPTO_DEVICE_TO_PHYS(dev->io->DmaOutAddress);
    dma->out.size = dev->io->DmaOutSizeInBytes;
}

static void DoReset(PCICryptoState * dev)
{
    dev->io->ErrorCode = CryptoDevice_NoError;
    dev->io->State = CryptoDevice_ReadyState;
    dev->io->Command = CryptoDevice_IdleCommand;
    dev->io->DmaInAddress = 0;
    dev->io->DmaInPagesCount = 0;
    dev->io->DmaInSizeInBytes = 0;
    dev->io->DmaOutAddress = 0;
    dev->io->DmaOutPagesCount = 0;
    dev->io->DmaOutSizeInBytes = 0;
    raise_reset_int(dev);
}

static bool CheckStop(PCICryptoState * dev)
{
    bool res = false;
    qemu_mutex_lock(&dev->io_mutex);
    
    if (CryptoDevice_ResetCommand == dev->io->Command || !dev->thread_running)
    {
        DoReset(dev);
        res = true;
    }

    qemu_mutex_unlock(&dev->io_mutex);
    return res;
}

static int DoSha256(PCICryptoState * dev, DmaRequest * dma)
{
    unsigned char digest[SHA256_DIGEST_LENGTH] = {};
    unsigned char page[CRYPTO_DEVICE_PAGE_SIZE] = {};
    SHA256_CTX hash = {};

    if (!dma->out.page_addr || dma->out.size < SHA256_DIGEST_LENGTH)
    {
        return CryptoDevice_DmaError;
    }

    if (!dma->in.page_addr && dma->in.size != 0)
    {
        return CryptoDevice_DmaError;
    }

    SHA256_Init(&hash);

    while (0 != dma->in.size)
    {
        ssize_t size = rw_dma_data(dev, false, &dma->in, page, sizeof(page));

        if (-1 == size)
        {
            return CryptoDevice_DmaError;
        }

        SHA256_Update(&hash, page, size);

        if (CheckStop(dev))
        {
            return CryptoDevice_DeviceHasBeenReseted;
        }
    }

    SHA256_Final(digest, &hash);

    if (sizeof(digest) != rw_dma_data(dev, true, &dma->out, digest, sizeof(digest)))
    {
        return CryptoDevice_DmaError;
    }

    return CryptoDevice_NoError;
}

static int DoAesCbc(PCICryptoState * dev, DmaRequest * dma, bool encrypt)
{
    AES_KEY key;
    unsigned char in[CRYPTO_DEVICE_PAGE_SIZE] = {};
    unsigned char out[CRYPTO_DEVICE_PAGE_SIZE] = {};
    unsigned char iv[sizeof(CRYPTO_DEVICE_AES_CBC_IV)] = {};
    const int key_lenght = sizeof(dev->aes_cbc_key) * 8; 

    typedef int (*PAES_set_key)(const unsigned char *userKey, const int bits, AES_KEY *key);
    const PAES_set_key AES_set_key = encrypt ? AES_set_encrypt_key : AES_set_decrypt_key;
    const int enc = encrypt ? AES_ENCRYPT : AES_DECRYPT;

    const size_t tail = dma->in.size % AES_BLOCK_SIZE;
    const size_t out_size = dma->in.size + (tail == 0 ? 0 : AES_BLOCK_SIZE - tail);

    static_assert(sizeof(iv) == sizeof(CRYPTO_DEVICE_AES_CBC_IV), "Unexpected sizeof iv");
    memcpy(iv, CRYPTO_DEVICE_AES_CBC_IV, sizeof(iv));
    
    ASSERT(0 == (out_size % AES_BLOCK_SIZE));
    static_assert(sizeof(in) % AES_BLOCK_SIZE == 0, "Invalid size of in buffer");

    if (!dma->in.page_addr || !dma->in.size || !dma->out.page_addr || out_size > dma->out.size)
    {
        return CryptoDevice_DmaError;
    }

    if (0 != AES_set_key(dev->aes_cbc_key, key_lenght, &key))
    {
        PRINT("AES_set_key failed\n");
        return CryptoDevice_InternalError;
    }

    while (0 != dma->in.size)
    {
        ssize_t size = rw_dma_data(dev, false, &dma->in, in, sizeof(in));

        if (-1 == size)
        {
            return CryptoDevice_DmaError;
        }

        if (0 != (size % AES_BLOCK_SIZE))
        {
            const uint32_t tail = AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE);
            memset(&in[size], 0, tail);
            size += tail;
        }

        ASSERT(0 == (size % AES_BLOCK_SIZE));
        AES_cbc_encrypt(in, out, (unsigned long)size, &key, iv, enc);

        if (size != rw_dma_data(dev, true, &dma->out, out, size))
        {
            return CryptoDevice_DmaError;
        }

        if (CheckStop(dev))
        {
            return CryptoDevice_DeviceHasBeenReseted;
        }
    } 	

    return CryptoDevice_NoError;
}

//
// Working thread
//
static void* worker_thread(void * pdev)
{
    PCICryptoState * dev = (PCICryptoState*)pdev;

    qemu_mutex_lock(&dev->io_mutex);
    PRINT("worker thread started\n");

    for (;;)
    {
        while(CryptoDevice_IdleCommand == dev->io->Command && dev->thread_running)
        {
            qemu_cond_wait(&dev->thread_cond, &dev->io_mutex);
        }

        if (!dev->thread_running)
        {
            PRINT("worker thread stopped\n");
            return NULL;
        }

        if (CryptoDevice_IdleCommand != dev->io->Command)
        {
            int error = 0;
            DmaRequest dma = {};
            FillDmaRequest(dev, &dma);

            switch (dev->io->Command)
            {
            case CryptoDevice_ResetCommand:
                dev->io->State = CryptoDevice_ResetState;
                DoReset(dev);
                error = CryptoDevice_DeviceHasBeenReseted;                
                break;
                
            case CryptoDevice_AesCbcEncryptCommand:
                dev->io->State = CryptoDevice_AesCbcState;
                qemu_mutex_unlock(&dev->io_mutex);
                error = DoAesCbc(dev, &dma, true);
                qemu_mutex_lock(&dev->io_mutex);
                break;

            case CryptoDevice_AesCbcDecryptCommand:
                dev->io->State = CryptoDevice_AesCbcState;
                qemu_mutex_unlock(&dev->io_mutex);
                error = DoAesCbc(dev, &dma, false);
                qemu_mutex_lock(&dev->io_mutex);
                break;

            case CryptoDevice_Sha2Command:
                dev->io->State = CryptoDevice_Sha2State;
                qemu_mutex_unlock(&dev->io_mutex);
                error = DoSha256(dev, &dma);
                qemu_mutex_lock(&dev->io_mutex);
                break;
            }

            switch (error)
            {
            case CryptoDevice_DeviceHasBeenReseted:
                break;

            case CryptoDevice_NoError:
                raise_ready_int(dev);
                break;

            case CryptoDevice_DmaError:
            case CryptoDevice_InternalError:
                raise_error_int(dev, error);
                break;

            default:
                PRINT("Unexpected error status %d\n", error);
                raise_error_int(dev, error);
            }

            dev->io->State = CryptoDevice_ReadyState;
            dev->io->Command = CryptoDevice_IdleCommand;
        }
    }

    ASSERT(!"Never execute");
}

//
// IO memory operations
//
static uint64_t pci_crypto_memio_read(void * opaque, 
                                    hwaddr addr, 
                                    unsigned size)
{
    uint64_t res = 0;
    PCICryptoState *dev = (PCICryptoState *)opaque;
  
    if (addr >= sizeof(dev->memio_data)) {
        PRINT("Read from unknown IO offset 0x%lx\n", addr);
        return 0;
    }

    if (addr + size >= sizeof(dev->memio_data)) {
        PRINT("Read from IO offset 0x%lx but bad size %d\n", addr, size);
        return 0;
    }

    qemu_mutex_lock(&dev->io_mutex);

    switch (size)
    {
    case sizeof(uint8_t):
        res = *(uint8_t*)&dev->memio_data[addr];
        break;
    case sizeof(uint16_t):
        res = *(uint16_t*)&dev->memio_data[addr];
        break;
    case sizeof(uint32_t):
        res = *(uint32_t*)&dev->memio_data[addr];
        break;
    case sizeof(uint64_t):
        res = *(uint64_t*)&dev->memio_data[addr];
        break;
    }

    qemu_mutex_unlock(&dev->io_mutex);
    return res;
}

static void pci_crypto_memio_write(void * opaque, 
                                hwaddr addr, 
                                uint64_t val, 
                                unsigned size)
{
    PCICryptoState *dev = (PCICryptoState *)opaque;

    if (addr >= sizeof(dev->memio_data)) {
        PRINT("Write to unknown IO offset 0x%lx\n", addr);
        return;
    }

    if (addr + size >= sizeof(dev->memio_data)) {
        PRINT("write to IO offset 0x%lx but bad size %d\n", addr, size);
        return;
    }

    qemu_mutex_lock(&dev->io_mutex);

#define CASE($field) \
    case offsetof(CryptoDeviceIo, $field): \
        ASSERT(size == sizeof(dev->io->$field));

    switch (addr)
    {
    CASE(ErrorCode)
        raise_error_int(dev, CryptoDevice_WriteIoError);
        break;

    CASE(State)
        raise_error_int(dev, CryptoDevice_WriteIoError);
        break;

    CASE(Command)
        dev->io->Command = (uint8_t)val;
        switch (dev->io->Command)
        {
        case CryptoDevice_ResetCommand:
        case CryptoDevice_AesCbcEncryptCommand:
        case CryptoDevice_AesCbcDecryptCommand:
        case CryptoDevice_Sha2Command:
            qemu_cond_signal(&dev->thread_cond);
            break;

        default:
            ASSERT(!"Unexpected command value\n");
            raise_error_int(dev, CryptoDevice_WriteIoError);
        }
        break;

    CASE(InterruptFlag)
        dev->io->InterruptFlag = (uint8_t)val;
        break;

    CASE(DmaInAddress)
        dev->io->DmaInAddress = (uint32_t)val;
        break;

    CASE(DmaInPagesCount)
        dev->io->DmaInPagesCount = (uint32_t)val;
        break;

    CASE(DmaInSizeInBytes)
        dev->io->DmaInSizeInBytes = (uint32_t)val;
        break;

    CASE(DmaOutAddress)
        dev->io->DmaOutAddress = (uint32_t)val;
        break;

    CASE(DmaOutPagesCount)
        dev->io->DmaOutPagesCount = (uint32_t)val;
        break;

    CASE(DmaOutSizeInBytes)
        dev->io->DmaOutSizeInBytes = (uint32_t)val;
        break;

    CASE(MsiErrorFlag)
        dev->io->MsiErrorFlag = (uint8_t)val;
        clear_interrupt(dev);
        break;

    CASE(MsiReadyFlag)
        dev->io->MsiReadyFlag = (uint8_t)val;
        clear_interrupt(dev);
        break;

    CASE(MsiResetFlag)
        dev->io->MsiResetFlag = (uint8_t)val;
        clear_interrupt(dev);
        break;
    }
#undef CASE

    qemu_mutex_unlock(&dev->io_mutex);
}

static const MemoryRegionOps pci_crypto_memio_ops = {
    .read = pci_crypto_memio_read,
    .write = pci_crypto_memio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    },
    .valid = {
        .min_access_size = 1,
        .max_access_size = 4,
    },

};

static void pci_crypto_realize(PCIDevice * pci_dev, Error **errp)
{
    PCICryptoState *dev = PCI_CRYPTO_DEV(pci_dev);
    PRINT("pci_crypto_realize\n");

    memory_region_init_io(&dev->memio, OBJECT(dev), 
                        &pci_crypto_memio_ops, dev, 
                        "pci-crypto-mmio", sizeof(dev->memio_data));

    pci_register_bar(pci_dev, 0, 
                    PCI_BASE_ADDRESS_SPACE_MEMORY, 
                    &dev->memio);

    pci_config_set_interrupt_pin(pci_dev->config, 1);

    if (msi_init(pci_dev, 0, CryptoDevice_MsiMax, true, false, errp)) {
        PRINT("Cannot init MSI\n");
    }

    dev->thread_running = true;
    dev->io = (CryptoDeviceIo*)dev->memio_data;
    memset(dev->memio_data, 0, sizeof(dev->memio_data));

    qemu_mutex_init(&dev->io_mutex);
    qemu_cond_init(&dev->thread_cond);
    qemu_thread_create(&dev->thread, "crypto-device-worker", worker_thread, dev, QEMU_THREAD_JOINABLE);

    const unsigned char * key = dev->aes_cbc_key;
    PRINT("AES CBC 256 bit key: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
        key[0x00], key[0x01], key[0x02], key[0x03], key[0x04], key[0x05], key[0x06], key[0x07],
        key[0x08], key[0x09], key[0x0a], key[0x0b], key[0x0c], key[0x0d], key[0x0e], key[0x0f],
        key[0x10], key[0x11], key[0x12], key[0x13], key[0x14], key[0x15], key[0x16], key[0x17],
        key[0x18], key[0x19], key[0x1a], key[0x1b], key[0x1c], key[0x1d], key[0x1e], key[0x1f]); 
}

static void pci_crypto_uninit(PCIDevice * pci_dev)
{
    PCICryptoState *dev = PCI_CRYPTO_DEV(pci_dev);
    PRINT("pci_crypto_uninit\n");

    qemu_mutex_lock(&dev->io_mutex);
    dev->thread_running = false;
    qemu_mutex_unlock(&dev->io_mutex);
    qemu_cond_signal(&dev->thread_cond);
    qemu_thread_join(&dev->thread);

    qemu_cond_destroy(&dev->thread_cond);
    qemu_mutex_destroy(&dev->io_mutex);
}

static void pci_crypto_reset(DeviceState * pci_dev)
{
    PCICryptoState *dev = PCI_CRYPTO_DEV(pci_dev);
    PRINT("pci_crypto_reset\n");

    qemu_mutex_lock(&dev->io_mutex);
    dev->io->ErrorCode = CryptoDevice_NoError;
    dev->io->State = CryptoDevice_ReadyState;
    dev->io->Command = CryptoDevice_IdleCommand;
    dev->io->InterruptFlag = CryptoDevice_DisableFlag;
    dev->io->DmaInAddress = 0;
    dev->io->DmaInPagesCount = 0;
    dev->io->DmaInSizeInBytes = 0;
    dev->io->DmaOutAddress = 0;
    dev->io->DmaOutPagesCount = 0;
    dev->io->DmaOutSizeInBytes = 0;
    dev->io->MsiErrorFlag = 0;
    dev->io->MsiReadyFlag = 0;
    dev->io->MsiResetFlag = 0;
    qemu_mutex_unlock(&dev->io_mutex);
}

static void crypto_set_aes_cbc_key_256(Object *obj, const char * value, Error **errp)
{
    PCICryptoState *dev = PCI_CRYPTO_DEV(obj);

    // calc sha256 from the user string => it's our 256bit key for AES CBC
    static_assert(sizeof(dev->aes_cbc_key) == SHA256_DIGEST_LENGTH, "Unexpected size of aes_cbc_key");
    SHA256((const unsigned char*)value, strlen(value), dev->aes_cbc_key);
}

static void pci_crypto_instance_init(Object *obj)
{
    PCICryptoState *dev = PCI_CRYPTO_DEV(obj);
    PRINT("pci_crypto_instance_init\n");
    
    memset(dev->aes_cbc_key, 0, sizeof(dev->aes_cbc_key));
    object_property_add_str(obj, "aes_cbc_256", 
                            NULL, 
                            crypto_set_aes_cbc_key_256, 
                            NULL);
}

static void pci_crypto_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    PRINT("pci_crypto_class_init\n");

    k->is_express = false;
    k->realize = pci_crypto_realize;
    k->exit = pci_crypto_uninit;
    k->vendor_id = 0x1111;
    k->device_id = 0x2222;
    k->revision = 0x00;
    k->class_id = PCI_CLASS_OTHERS;
    dc->desc = "PCI Crypto Device";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->reset = pci_crypto_reset;
    dc->hotpluggable = false;
}

static void pci_crypto_register_types(void)
{
    static InterfaceInfo interfaces[] = {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    };
    static const TypeInfo pci_crypto_info = {
        .name          = TYPE_PCI_CRYPTO_DEV,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(PCICryptoState),
        .instance_init = pci_crypto_instance_init,
        .class_init    = pci_crypto_class_init,
        .interfaces    = interfaces,
    };

    type_register_static(&pci_crypto_info);
}

type_init(pci_crypto_register_types)