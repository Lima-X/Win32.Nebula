// TODO: this needs precomp states, this is the base for virtually all TU's


#pragma once

#include <Windows.h>
#include <intrin.h>
#include <psapi.h>
#include <strsafe.h>
#include <TlHelp32.h>

#include <Shlobj.h>
#include <KnownFolders.h>
#include <PathCch.h>

// Doing it Explicitly instead for Obfuscation
// #pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "rpcrt4.lib")
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

/* Disable useless/unimportant Warnings */
#pragma warning(disable : 4024)
#pragma warning(disable : 4047)
#pragma warning(disable : 4200)
#pragma warning(disable : 4201)

/* Microsoft Detours */
#pragma comment(lib, "..\\msDetours\\lib.X86\\detours.lib")
#include "..\msDetours\include\detours.h"

/* Shared Declarations */
#ifdef __cplusplus
#include "shared.h"
#endif