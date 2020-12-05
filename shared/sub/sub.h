/* This File serves as a Base for other Headres to build on  */
#pragma once

// Windows (NT) Specific
#define _WIN32_WINNT         0x06010000 // Windows 7 and up
#define  WIN32_LEAN_AND_MEAN            // Reduce Header Size
#define  UNICODE
#include <windows.h>                    // Windows Header

// Win32.riftV2 Specific
#include "sub/def.h"
#include "sub/dbg.h"
