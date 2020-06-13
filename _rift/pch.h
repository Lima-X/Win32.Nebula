#pragma once

#include <Windows.h>
#include <intrin.h>
#include <psapi.h>
#include <strsafe.h>
#include <TlHelp32.h>

// Doing it Explicitly instead for Obfuscation
// #pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "bcrypt.lib")
#include <bcrypt.h>
#pragma comment(lib, "cabinet.lib")
#include <compressapi.h>
#pragma comment(lib, "pathcch.lib")
#include <PathCch.h>
#pragma comment(lib, "shlwapi.lib")
#include <Shlwapi.h>
#pragma comment(lib, "wininet.lib")
#include <WinInet.h>

#include "..\msDetours\include\detours.h"

/* MemoryModule */
#include "MemoryModule.h"
#include <winnt.h>
#include <stddef.h>
#include <tchar.h>