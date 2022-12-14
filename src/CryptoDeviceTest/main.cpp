// CryptoDeviceTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "CryptoDeviceCtrl.h"
#include "MappedFile.h"

#pragma warning(push, 0)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS_2)
#define GTEST_LANG_CXX11 1
#include <src/gtest-all.cc>
#pragma warning(pop)

#pragma comment(lib, "Shlwapi.lib")

namespace commands
{
    static const std::wstring hash = L"hash ";
    static const std::wstring encrypt = L"encrypt ";
    static const std::wstring decrypt = L"decrypt ";
    static const std::wstring status = L"status";
    static const std::wstring reset = L"reset";
    static const std::wstring devices = L"devices";
    static const std::wstring tests = L"unit tests";
    static const std::wstring exit = L"exit";
}

namespace
{
    std::unique_ptr<crypto::CryptoDeviceCtrl> OpenDevice()
    {
        return std::make_unique<crypto::CryptoDeviceCtrl>(crypto::CryptoDeviceCtrl::GetDevicesIds().at(0));
    }

    bool CheckCommand(const std::wstring& userCmd, const std::wstring& cmd)
    {
        return (userCmd.c_str() == StrStrIW(userCmd.c_str(), cmd.c_str()));
    }

    void PrintDeviceStatus(const crypto::CryptoDeviceCtrl& device)
    {
        crypto::DeviceStatus status = device.GetDeviceStatus();
        std::wcout << "State: " << status.State << "\n";
        std::wcout << "Error: " << status.ErrorCode << "\n";
    }

    template<typename Callback>
    bool RunInThread(const crypto::CryptoDeviceCtrl& device, Callback cb)
    {
        std::wcout << "press any key to cancel operation\n";

        INPUT_RECORD inputRecord = {};
        DWORD numberOfEventsRead = 0;
        DWORD secondsLeft = 0;

        std::string error;
        std::thread thread([&]()
        {
            try
            {
                cb();
            }
            catch (const std::exception& ex)
            {
                error = ex.what();
            }
        });

        HANDLE handles[] = { thread.native_handle(), GetStdHandle(STD_INPUT_HANDLE) };
        bool stop = false;

        while (!stop)
        {
            DWORD res = WaitForMultipleObjects(ARRAYSIZE(handles), &handles[0], FALSE, 1000);

            switch (res)
            {
            case WAIT_TIMEOUT:

                std::wcout << "\rState: " << device.GetDeviceStatus().State << " <time: " << ++secondsLeft << " second(s)>";
                break;

            case WAIT_OBJECT_0:

                if (!error.empty())
                {
                    std::wcout << "\nError: " << error.c_str() << "\n";
                    PrintDeviceStatus(device);
                }
                stop = true;
                break;

            case WAIT_OBJECT_0 + 1:

                if (ReadConsoleInput(GetStdHandle(STD_INPUT_HANDLE), &inputRecord, 1, &numberOfEventsRead))
                {
                    if (inputRecord.EventType == ENABLE_PROCESSED_INPUT)
                    {
                        device.ResetDevice();
                        WaitForSingleObject(thread.native_handle(), INFINITE);
                        stop = true;
                    }
                }

                break;
            }
        }

        std::wcout << "\n";
        thread.join();
        return error.empty();
    }

    std::optional<std::vector<uint8_t>> FileSha256(const crypto::CryptoDeviceCtrl& device, const std::wstring& filename)
    {
        const uint64_t size = utils::GetFileSize(filename.c_str());
        utils::MappedFile file(filename.c_str()
            , GENERIC_READ
            , OPEN_EXISTING
            , FILE_SHARE_READ
            , PAGE_READONLY
            , gsl::narrow<ULONG>(size)
            , FILE_MAP_READ
            , 0
            , gsl::narrow<ULONG>(size));

        std::vector<uint8_t> sha256;

        auto cb = [&]()
        {
            sha256 = device.Sha256(file.GetViewData(), file.GetViewSize());
        };

        if (!RunInThread(device, cb))
        {
            return {};
        }

        return std::make_optional<std::vector<uint8_t>>(sha256);
    }

    bool FileEncrypt(const crypto::CryptoDeviceCtrl& device, const std::wstring& filename)
    {
        const size_t inSize = gsl::narrow<size_t>(utils::GetFileSize(filename.c_str()));
        const size_t outSize = crypto::CryptoDeviceCtrl::GetAesOutBufferSize(inSize);
        const size_t sizeWithPaddingInfo = outSize + crypto::CryptoDeviceCtrl::AesBlockSize;

        utils::MappedFile file(filename.c_str()
            , GENERIC_ALL
            , OPEN_EXISTING
            , 0
            , PAGE_READWRITE
            , gsl::narrow<ULONG>(sizeWithPaddingInfo)
            , FILE_MAP_READ | FILE_MAP_WRITE
            , 0
            , gsl::narrow<ULONG>(sizeWithPaddingInfo));

        static_assert(sizeof(uint16_t) <= crypto::CryptoDeviceCtrl::AesBlockSize, "Unexpected size of block");
        const uint16_t paddingSize = gsl::narrow<uint16_t>(sizeWithPaddingInfo - inSize);
        *file.GetViewPointer<uint16_t>(gsl::narrow<DWORD>(outSize)) = paddingSize;
        std::wcout << "File paddig: " << paddingSize << " byte(s)\n";

        auto cb = [&]()
        {
            device.AesCbcEncrypt(file.GetViewData()
                , sizeWithPaddingInfo
                , file.GetViewData()
                , sizeWithPaddingInfo);
        };

        return RunInThread(device, cb);
    }

    bool FileDecrypt(const crypto::CryptoDeviceCtrl& device, const std::wstring& filename)
    {
        const size_t size = gsl::narrow<size_t>(utils::GetFileSize(filename.c_str()));
        THROW_IF(crypto::CryptoDeviceCtrl::GetAesOutBufferSize(size) != size, "Invalid encrypted file size");

        auto file = std::make_unique<utils::MappedFile>(filename.c_str()
            , GENERIC_ALL
            , OPEN_EXISTING
            , 0
            , PAGE_READWRITE
            , gsl::narrow<ULONG>(size)
            , FILE_MAP_READ | FILE_MAP_WRITE
            , 0
            , gsl::narrow<ULONG>(size));

        auto cb = [&]()
        {
            device.AesCbcDecrypt(file->GetViewData()
                , size
                , file->GetViewData()
                , size);
        };

        if (!RunInThread(device, cb))
        {
            return false;
        }

        const DWORD paddingSizeOffset = gsl::narrow<DWORD>(size - crypto::CryptoDeviceCtrl::AesBlockSize);
        const DWORD paddigSize = *file->GetViewPointer<uint16_t>(paddingSizeOffset);
        
        if (0 == paddigSize || paddigSize >= (2 * crypto::CryptoDeviceCtrl::AesBlockSize))
        {
            //
            // Invalid padding value
            //
            std::wcout << "Warning: invalid file padding value\n";
            return true;
        }

        std::wcout << "File paddig: " << paddigSize << " byte(s)\n";

        file.reset();

        //
        // Shrink file size to remove padding info data
        //
        utils::HandleFileGuard fileToShrink = CreateFile(filename.c_str()
            , GENERIC_ALL
            , 0
            , NULL
            , OPEN_EXISTING
            , FILE_ATTRIBUTE_NORMAL
            , NULL);
        THROW_WIN_IF(!fileToShrink, "Cannot open file " << utils::Utf16To8(filename));

        const DWORD res = SetFilePointer(fileToShrink.get()
            , paddigSize * -1l
            , NULL
            , FILE_END);
        THROW_IF(INVALID_SET_FILE_POINTER == res, "SetFilePointer failed");
        THROW_IF(!SetEndOfFile(fileToShrink.get()), "SetEndOfFile failed");

        return true;
    }
}

int wmain(int argc, wchar_t** argv) 
{
    try
    {
        if (argc > 1)
        {
            testing::InitGoogleTest(&argc, argv);
            return RUN_ALL_TESTS();
        }

        std::wstring cmd;

        for (;;)
        {
            std::wcout << "Please choose the command:\n";
            std::wcout << "  " << commands::hash << " <file path>\n";
            std::wcout << "  " << commands::encrypt << " <file path>\n";
            std::wcout << "  " << commands::decrypt << " <file path>\n";
            std::wcout << "  " << commands::status << "\n";
            std::wcout << "  " << commands::reset << "\n";
            std::wcout << "  " << commands::devices << "\n";
            std::wcout << "  " << commands::tests << "\n";
            std::wcout << "  " << commands::exit << "\n";

            std::wcout << "> ";
            std::getline(std::wcin, cmd);

            try
            {
                if (CheckCommand(cmd, commands::hash))
                {
                    const std::wstring filePath = cmd.substr(commands::hash.size());
                    auto hash = FileSha256(*OpenDevice(), filePath);

                    if (hash.has_value())
                    {
                        std::wcout << filePath << " : ";
                        std::wcout << utils::BytesToHexString(hash.value()).c_str() << "\n";
                    }
                }
                else if (CheckCommand(cmd, commands::encrypt))
                {
                    const std::wstring filePath = cmd.substr(commands::encrypt.size());

                    if (FileEncrypt(*OpenDevice(), filePath))
                    {
                        std::wcout << "File '" << filePath << "' encrypted\n";
                    }
                }
                else if (CheckCommand(cmd, commands::decrypt))
                {
                    const std::wstring filePath = cmd.substr(commands::encrypt.size());

                    if (FileDecrypt(*OpenDevice(), filePath))
                    {
                        std::wcout << "File '" << filePath << "' decrypted\n";
                    }
                }
                else if (CheckCommand(cmd, commands::reset))
                {
                    OpenDevice()->ResetDevice();
                    std::wcout << "Reset done\n";
                }
                else if (CheckCommand(cmd, commands::status))
                {
                    PrintDeviceStatus(*OpenDevice());
                }
                else if (CheckCommand(cmd, commands::devices))
                {
                    auto devices = crypto::CryptoDeviceCtrl::GetDevicesIds();

                    for (const auto& dev : devices)
                    {
                        std::wcout << dev << "\n";
                    }
                }
                else if (CheckCommand(cmd, commands::tests))
                {
                    testing::InitGoogleTest(&argc, argv);
                    RUN_ALL_TESTS();
                }
                else if (CheckCommand(cmd, commands::exit))
                {
                    break;
                }
                else
                {
                    std::wcout << "Unknown command '" << cmd << "'\n";
                }

                std::wcout << std::endl;
            }
            catch (std::exception& ex)
            {
                std::wcout << "Error: " << ex.what() << "\n\n";
            }
        }
    }
    catch (const std::exception& ex)
    {
        std::wcerr << "Error: " << ex.what() << std::endl;
        return -1;
    }

    return 0;
}

