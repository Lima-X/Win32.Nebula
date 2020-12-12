/* This File serves as a Base for other Headres to build on  */
#pragma once

// Disable Useless/Inaccurate Warnings
#pragma warning(disable : 4100)
#pragma warning(disable : 4200)
#pragma warning(disable : 4267)
#pragma warning(disable : 4302)
#pragma warning(disable : 4311)
#pragma warning(disable : 4706)

// Language (C/C++) Specific
#include <intrin.h>

// Windows (NT) Specific
#define _WIN32_WINNT         0x06010000 // Windows 7 and up
#define  WIN32_LEAN_AND_MEAN            // Reduce Header Size
#define  UNICODE                        // Use Unicode Charset
#include <windows.h>                    // Windows Header

// Win32.riftV2 Specific
#include "sub/def.h"
#include "sub/status.h"
#include "sub/dbg.h"
