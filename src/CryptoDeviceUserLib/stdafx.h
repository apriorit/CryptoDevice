// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define NOMINMAX

#include <stdio.h>
#include <tchar.h>
#include <assert.h>

#include <locale>
#include <codecvt>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <mutex>
#include <shared_mutex>
#include <array>

#include <Windows.h>
#include <Cfgmgr32.h>
#include <winioctl.h>
#include <bcrypt.h>
#include <intrin.h>

#include <codeanalysis\warnings.h>
#define ALL_CODE_ANALYSIS_WARNINGS_2 ALL_CODE_ANALYSIS_WARNINGS 26496 26497 26400 26401 26408 26409 26411 26426 26429 26430 26432 26433 26436 26439 26440 26443 26444 26446 26447 26451 26461 26462 26466 26471 26472 26474 26481 26482 26485 26486 26487 26489 26490 26492 26494 26495

#pragma warning(push, 0)
#pragma warning(disable: ALL_CODE_ANALYSIS_WARNINGS_2)
#define GSL_THROW_ON_CONTRACT_VIOLATION
#include <gsl\gsl>
#pragma warning(pop)
