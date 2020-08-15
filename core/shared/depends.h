// TODO: this needs precomp states, this is the base for virtually all TU's
#pragma once

#include <windows.h>
#include <psapi.h>
#include <tlHelp32.h>
#include <shlobj.h>
#include <knownfolders.h>

#pragma comment(lib, "bcrypt.lib")
#include <bcrypt.h>
#pragma comment(lib, "cabinet.lib")
#include <compressapi.h>
#pragma comment(lib, "pathcch.lib")
#include <pathcch.h>
#pragma comment(lib, "shlwapi.lib")
#include <shlwapi.h>
#pragma comment(lib, "wininet.lib")
#include <wininet.h>

#include <stdio.h>

/* Disable useless/unimportant Warnings */
#pragma warning(disable : 4024)
#pragma warning(disable : 4047)
#pragma warning(disable : 4200)
#pragma warning(disable : 4201)

/* Microsoft Detours */
#pragma comment(lib, "..\\..\\other\\msDetours\\lib.X86\\detours.lib")
#include "..\..\other\msDetours\include\detours.h"

/* Shared Declarations */
#ifdef __cplusplus
#include "shared.h"
#endif