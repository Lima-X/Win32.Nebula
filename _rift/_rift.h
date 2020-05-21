#pragma once
#include "_rift_shared.h"
#include "MemoryModule.h"
#include "resource.h"

/* WinMain : main.c */
WCHAR g_szMFN[MAX_PATH];
WCHAR g_szCD[MAX_PATH];
HMODULE g_hmMH;

/* _riftdll */
typedef BOOL(*pfnDllInit)(int);

/* Unpack Resource / Copressor and Crypto / UnpackRes.c */
PVOID fnUnpackResource(_In_ PCWSTR szInFN, _In_ WORD wResID, _Out_ PSIZE_T nData);

/* Xoshiro PRNG Algorithm : Xoshiro.c */
UINT32 fnNext128ss(_Inout_ PVOID pui32S);
UINT32 fnNext128p(_Inout_ PVOID pui32S);
#if _DISABLE_JUMPS == 0
VOID fnLJump128(_Inout_ PVOID pui32S);
VOID fnSJump128(_Inout_ PVOID pui32S);
#endif
UINT32 fnURID32(_In_ UINT32 ui32Max, _In_ UINT32 ui32Min, _Inout_ PVOID pui32S);
float fnURRD24(_Inout_ PVOID pui32S);
PVOID fnAllocXSR(_In_ PXSR sParamA);
BOOL fnRelocXSR(_Inout_ PVOID pS, _In_ PXSR sParamA);
PVOID fnCopyXSR(_In_ PVOID pui32S);
VOID fnDelocXSR(_Inout_ PVOID pui32S);

/* Anti-ReverseEngineering : AntiRE.c */
BOOL fnAntiRE();

/* VMDetection : VMDetect.c */
BOOL fnCheckVMPresent();

/* Crypto Tools : BCrypt.c */

/* ConsoleHost : Console.c */
BOOL fnAllocConsole();
extern const WCHAR szConsoleTitle[];
extern const UINT8 nConsoleTitleLen;

/* NT Functions : NT.c */
BOOL fnAdjustPrivilege(_In_ PCTSTR lpszPrivilege, _In_ BOOL bEnablePrivilege);