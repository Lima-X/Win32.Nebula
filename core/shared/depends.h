// TODO: this needs precomp states, this is the base for virtually all TU's in riftCore
#pragma once

// C Library Headers
#include <stdio.h>

// C++ Library Headers (currently completely unused as i dont make use of the STL (, and probably wont in this project))
#ifdef __cplusplus
#endif

// Windows special Headers
#include <psapi.h>
#include <tlHelp32.h>
#include <shlobj.h>
#include <knownfolders.h>

// Windows unlinked Headers
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

// Microsoft Detours
#pragma comment(lib, "..\\..\\other\\msDetours\\lib.X86\\detours.lib")
#include "..\..\other\msDetours\include\detours.h"

// Shared Declarations (extra)
#ifdef __cplusplus
#include "shared.h"
#endif