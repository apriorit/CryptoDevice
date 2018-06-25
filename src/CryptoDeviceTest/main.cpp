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
    static const std::wstring hash = L"hash";
    static const std::wstring encrypt = L"encrypt";
    static const std::wstring decrypt = L"decrypt";
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
}

int wmain(int argc, wchar_t** argv) 
{
    // in process status 
    // check AES cbc algo

    try
    {
        if (argc > 1)
        {
            testing::InitGoogleTest(&argc, argv);
            return RUN_ALL_TESTS();
        }

        std::wstring cmd;

        while (cmd != commands::exit)
        {
            std::cout << "Please choose the command:\n";
            std::wcout << commands::hash << " <file path>\n";
            std::wcout << commands::encrypt << " <file path>\n";
            std::wcout << commands::decrypt << " <file path>\n";
            std::wcout << commands::status << "\n";
            std::wcout << commands::reset << "\n";
            std::wcout << commands::devices << "\n";
            std::wcout << commands::tests << "\n";
            std::wcout << commands::exit << "\n";

            std::cout << "> ";
            std::getline(std::wcin, cmd);

            try
            {
                if (0 == StrStrIW(cmd.c_str(), commands::hash.c_str()))
                {
                    const std::wstring filePath = cmd.substr(commands::hash.size());
                    const uint64_t size = utils::GetFileSize(filePath.c_str());
                    utils::MappedFile file(filePath.c_str()
                        , GENERIC_READ
                        , OPEN_EXISTING
                        , FILE_SHARE_READ
                        , PAGE_READONLY
                        , gsl::narrow<ULONG>(size)
                        , FILE_MAP_READ
                        , 0
                        , gsl::narrow<ULONG>(size));

                    crypto::CryptoDeviceCtrl::Sha256Buffer sha256 = { 0 };
                    OpenDevice()->Sha256(file.GetViewData(), file.GetViewSize(), sha256);

                    std::wcout << filePath << " : ";
                    std::cout << utils::BytesToHexString(sha256) << "\n";
                }
                else if (0 == StrStrIW(cmd.c_str(), commands::encrypt.c_str()))
                {
                    const std::wstring filePath = cmd.substr(commands::encrypt.size());
                    const size_t inSize = gsl::narrow<size_t>(utils::GetFileSize(filePath.c_str()));
                    const size_t outSize = crypto::CryptoDeviceCtrl::GetAesOutBufferSize(inSize);

                    utils::MappedFile file(filePath.c_str()
                        , GENERIC_ALL
                        , OPEN_EXISTING
                        , 0
                        , PAGE_READWRITE
                        , gsl::narrow<ULONG>(outSize)
                        , FILE_MAP_READ | FILE_MAP_WRITE
                        , 0
                        , gsl::narrow<ULONG>(outSize));

                    OpenDevice()->AesCbcEncrypt(file.GetViewData()
                        , inSize
                        , file.GetViewData()
                        , outSize);
                }
                else if (0 == StrStrIW(cmd.c_str(), commands::decrypt.c_str()))
                {
                    const std::wstring filePath = cmd.substr(commands::encrypt.size());
                    const size_t inSize = gsl::narrow<size_t>(utils::GetFileSize(filePath.c_str()));
                    const size_t outSize = crypto::CryptoDeviceCtrl::GetAesOutBufferSize(inSize);

                    utils::MappedFile file(filePath.c_str()
                        , GENERIC_ALL
                        , OPEN_EXISTING
                        , 0
                        , PAGE_READWRITE
                        , gsl::narrow<ULONG>(outSize)
                        , FILE_MAP_READ | FILE_MAP_WRITE
                        , 0
                        , gsl::narrow<ULONG>(outSize));

                    OpenDevice()->AesCbcDecrypt(file.GetViewData()
                        , inSize
                        , file.GetViewData()
                        , outSize);
                }
                else if (0 == StrCmpIW(cmd.c_str(), commands::status.c_str()))
                {
                    OpenDevice()->ResetDevice();
                }
                else if (0 == StrCmpIW(cmd.c_str(), commands::reset.c_str()))
                {
                    crypto::DeviceStatus status = OpenDevice()->GetDeviceStatus();
                    std::wcout << "State: " << status.State << "\n";
                    std::wcout << "Error: " << status.ErrorCode << "\n";
                }
                else if (0 == StrCmpIW(cmd.c_str(), commands::devices.c_str()))
                {
                    auto devices = crypto::CryptoDeviceCtrl::GetDevicesIds();

                    for (const auto& dev : devices)
                    {
                        std::wcout << dev << "\n";
                    }
                }
                else if (0 == StrCmpIW(cmd.c_str(), commands::tests.c_str()))
                {
                    testing::InitGoogleTest(&argc, argv);
                    RUN_ALL_TESTS();
                }

                std::cout << std::endl;
            }
            catch (std::exception& ex)
            {
                std::cout << "Error: " << ex.what() << "\n";
            }
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Error: " << ex.what() << std::endl;
        return -1;
    }

    return 0;
}


