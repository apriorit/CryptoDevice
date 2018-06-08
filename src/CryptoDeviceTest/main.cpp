// CryptoDeviceTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#pragma warning(push, 0)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS_2)
#define GTEST_LANG_CXX11 1
#include <src/gtest-all.cc>
#pragma warning(pop)

int main(int argc, char** argv) 
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

