/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_CRYPTO,
    0xd7b78033,0xe888,0x47dc,0x98,0x34,0x88,0x3d,0x89,0x80,0x46,0x80);
// {d7b78033-e888-47dc-9834-883d89804680}

/////////////////////////////////////////////////////////////////////////////////////////////////
//// The user mode interface for communication with the driver
////

typedef struct tagCryptoDeviceStatus
{
    UINT8 State;
    UINT8 ErrorCode;

} CryptoDeviceStatus;

typedef struct tagCryptoDeviceBuffer
{
    UINT64 Address;
    UINT32 Size;

} CryptoDeviceBuffer;

typedef struct tagCryptoDeviceBufferInOut
{
    CryptoDeviceBuffer In;
    CryptoDeviceBuffer Out;

} CryptoDeviceBufferInOut;

//
// Software reset for the device
//
// IN:  None
// OUT: None
//
#define IOCTL_CRYPTO_DEVICE_RESET CTL_CODE(FILE_DEVICE_UNKNOWN, 800, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Get current device's state
//
// IN:  None
// OUT: CryptoDeviceStatus
//
#define IOCTL_CRYPTO_DEVICE_GET_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 801, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Encrypt buffer with AES CBC 
//
// IN:  CryptoDeviceBufferInOut 
// OUT: None 
//
#define IOCTL_CRYPTO_DEVICE_AES_CBC_ENCRYPT CTL_CODE(FILE_DEVICE_UNKNOWN, 802, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Decrypt buffer with AES CBC 
//
// IN:  CryptoDeviceBufferInOut 
// OUT: None 
//
#define IOCTL_CRYPTO_DEVICE_AES_CBC_DECRYPT CTL_CODE(FILE_DEVICE_UNKNOWN, 803, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Calculate SHA256 for the buffer
//
// IN:  CryptoDeviceBufferInOut
// OUT: None
//
#define IOCTL_CRYPTO_DEVICE_SHA256 CTL_CODE(FILE_DEVICE_UNKNOWN, 804, METHOD_BUFFERED, FILE_ANY_ACCESS)
