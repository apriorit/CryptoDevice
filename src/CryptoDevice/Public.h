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

DEFINE_GUID (GUID_DEVINTERFACE_CryptoDevice,
    0xd7b78033,0xe888,0x47dc,0x98,0x34,0x88,0x3d,0x89,0x80,0x46,0x80);
// {d7b78033-e888-47dc-9834-883d89804680}
