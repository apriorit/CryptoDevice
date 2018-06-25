/*
 * CryptoDevice PCI device structures and types
 */

#pragma once

#pragma pack(push, 1) // all data must be aligned by 1 byte

#define CRYPTO_DEVICE_DMA_MAGIC_BYTE 0x11
#define CRYPTO_DEVICE_PAGE_MASK 0xFFF
#define CRYPTO_DEVICE_PAGE_SIZE 0x1000
#define CRYPTO_DEVICE_PAGE_SHIFT 0x0C
#define CRYPTO_DEVICE_TO_PHYS($dma) (uint64_t)(((uint64_t)($dma)) << CRYPTO_DEVICE_PAGE_SHIFT)
#define CRYPTO_DEVICE_TO_DMA($phys) (uint32_t)(((uint64_t)($phys)) >> CRYPTO_DEVICE_PAGE_SHIFT)
#define CRYPTO_DEVICE_DMA_MAX 0xFFFFFFFFFFF

typedef enum tagCryptoDeviceErrorCode
{
    CryptoDevice_NoError       = 0x00,
    CryptoDevice_DmaError      = 0x01,
    CryptoDevice_ResetError    = 0x02,
    CryptoDevice_WriteIoError  = 0x03,
    CryptoDevice_InternalError = 0x04,

    CryptoDevice_DeviceHasBeenReseted = -1

} CryptoDeviceErrorCode;

typedef enum tagCryptoDeviceState
{
    CryptoDevice_ReadyState     = 0x00,
    CryptoDevice_ResetState     = 0x01,
    CryptoDevice_AesCbcState    = 0x02,
    CryptoDevice_Sha2State      = 0x03
} CryptoDeviceState;

typedef enum tagCryptoDeviceCommand
{
    CryptoDevice_IdleCommand            = 0x00,
    CryptoDevice_ResetCommand           = 0x01,
    CryptoDevice_AesCbcEncryptCommand   = 0x02,
    CryptoDevice_AesCbcDecryptCommand   = 0x03,
    CryptoDevice_Sha2Command            = 0x04
} CryptoDeviceCommand;

typedef enum tagCryptoDeviceInterruptFlag
{
    CryptoDevice_DisableFlag    = 0x00,
    CryptoDevice_EnableAllFlag  = 0xff
} CryptoDeviceInterruptFlag;

typedef enum tagCryptoDeviceMSI
{
    CryptoDevice_MsiZero   = 0x00,
    CryptoDevice_MsiError  = 0x01,
    CryptoDevice_MsiReady  = 0x02,
    CryptoDevice_MsiReset  = 0x03,
    CryptoDevice_MsiMax    = 0x04
} CryptoDeviceMSI;

typedef struct tagCryptoDeviceIo
{
    /*0x00*/ uint8_t  ErrorCode;
    /*0x01*/ uint8_t  State;
    /*0x02*/ uint8_t  Command;
    /*0x03*/ uint8_t  InterruptFlag;
    /*0x04*/ uint32_t DmaInAddress;
    /*0x08*/ uint32_t DmaInPagesCount;
    /*0x0C*/ uint32_t DmaInSizeInBytes;
    /*0x10*/ uint32_t DmaOutAddress;
    /*0x14*/ uint32_t DmaOutPagesCount;
    /*0x18*/ uint32_t DmaOutSizeInBytes;
    /*0x1C*/ uint8_t  MsiErrorFlag;
    /*0x1D*/ uint8_t  MsiReadyFlag;
    /*0x1E*/ uint8_t  MsiResetFlag;
    /*0x1F*/ uint8_t  Unused;
    
} CryptoDeviceIo;

static_assert(0x00 == offsetof(CryptoDeviceIo, ErrorCode), "Invalid ErrorCode offset");
static_assert(0x01 == offsetof(CryptoDeviceIo, State), "Invalid State offset");
static_assert(0x02 == offsetof(CryptoDeviceIo, Command), "Invalid Command offset");
static_assert(0x03 == offsetof(CryptoDeviceIo, InterruptFlag), "Invalid InterruptFlag offset");
static_assert(0x04 == offsetof(CryptoDeviceIo, DmaInAddress), "Invalid DmaInAddress offset");
static_assert(0x08 == offsetof(CryptoDeviceIo, DmaInPagesCount), "Invalid DmaInPagesCount offset");
static_assert(0x0C == offsetof(CryptoDeviceIo, DmaInSizeInBytes), "Invalid DmaInSizeInBytes offset");
static_assert(0x10 == offsetof(CryptoDeviceIo, DmaOutAddress), "Invalid DmaOutAddress offset");
static_assert(0x14 == offsetof(CryptoDeviceIo, DmaOutPagesCount), "Invalid DmaOutPagesCount offset");
static_assert(0x18 == offsetof(CryptoDeviceIo, DmaOutSizeInBytes), "Invalid DmaOutSizeInBytes offset");
static_assert(0x1C == offsetof(CryptoDeviceIo, MsiErrorFlag), "Invalid MsiErrorFlag offset");
static_assert(0x1D == offsetof(CryptoDeviceIo, MsiReadyFlag), "Invalid MsiReadyFlag offset");
static_assert(0x1E == offsetof(CryptoDeviceIo, MsiResetFlag), "Invalid MsiResetFlag offset");
static_assert(0x1F == offsetof(CryptoDeviceIo, Unused), "Invalid Unused offset");

#pragma pack(pop)
