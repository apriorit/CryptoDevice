/*
 * CryptoDevice PCI device structures and types
 */

#pragma once

#pragma pack(push, 1) // all data must be aligned by 1 byte

#define CRYPTO_DEVICE_PAGE_SIZE 0x1000
#define CRYPTO_DEVICE_PAGE_SHIFT 0x0C
#define CRYPTO_DEVICE_TO_PHYS($dma) (uint64_t)(((uint64_t)($dma)) << CRYPTO_DEVICE_PAGE_SHIFT)
#define CRYPTO_DEVICE_TO_DMA($phys) (uint32_t)(((uint64_t)($phys)) >> CRYPTO_DEVICE_PAGE_SHIFT)
#define CRYPTO_DEVICE_DMA_MAX 0xFFFFFFFFFFF

typedef enum tagCryptoDeviceErrorCode
{
    CryptoDevice_NoError    = 0x00,
    CryptoDevice_DmaError   = 0x01,
    CryptoDevice_ResetError = 0x02
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
    CryptoDevice_IdleCommand    = 0x00,
    CryptoDevice_ResetCommand   = 0x01,
    CryptoDevice_AesCbcCommand  = 0x02,
    CryptoDevice_Sha2Command    = 0x03

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
    CryptoDevice_MsiMax    = 0x04

} CryptoDeviceMSI;

typedef struct tagCryptoDeviceIo
{
    /*0x00*/ uint8_t  ErrorCode;
    /*0x01*/ uint8_t  State;
    /*0x02*/ uint8_t  Command;
    /*0x03*/ uint8_t  InterruptFlag;
    /*0x04*/ uint32_t DmaBufIn;
    /*0x08*/ uint32_t DmaBufOut;
    /*0x0C*/ uint32_t DmaCountIn;
    /*0x10*/ uint32_t DmaCountOut;
    /*0x14*/ uint8_t  MsiErrorFlag;
    /*0x15*/ uint8_t  MsiReadyFlag;
    /*0x16*/ uint16_t Unused;
    
} CryptoDeviceIo;

static_assert(0x00 == offsetof(CryptoDeviceIo, ErrorCode), "Invalid ErrorCode offset");
static_assert(0x01 == offsetof(CryptoDeviceIo, State), "Invalid State offset");
static_assert(0x02 == offsetof(CryptoDeviceIo, Command), "Invalid Command offset");
static_assert(0x03 == offsetof(CryptoDeviceIo, InterruptFlag), "Invalid InterruptFlag offset");
static_assert(0x04 == offsetof(CryptoDeviceIo, DmaBufIn), "Invalid DmaBufIn offset");
static_assert(0x08 == offsetof(CryptoDeviceIo, DmaBufOut), "Invalid DmaBufOut offset");
static_assert(0x0C == offsetof(CryptoDeviceIo, DmaCountIn), "Invalid DmaCountIn offset");
static_assert(0x10 == offsetof(CryptoDeviceIo, DmaCountOut), "Invalid DmaCountOut offset");
static_assert(0x14 == offsetof(CryptoDeviceIo, MsiErrorFlag), "Invalid MsiErrorFlag offset");
static_assert(0x15 == offsetof(CryptoDeviceIo, MsiReadyFlag), "Invalid MsiReadyFlag offset");
static_assert(0x16 == offsetof(CryptoDeviceIo, Unused), "Invalid Unused offset");

#pragma pack(pop)
