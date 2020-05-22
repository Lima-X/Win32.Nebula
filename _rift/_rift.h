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
BOOL fnInitializeXSR();
VOID fnDeleteXSR();

DWORD fnNext128ss();
DWORD fnNext128p();
UINT  fnURID(_In_ UINT uiMin, _In_ UINT uiMax);
FLOAT fnURRD();

/* Anti-ReverseEngineering : AntiDebug.c, AnitDllInject.c, AntiRE.c */
BOOL fnAntiRE();
BOOL fnAntiDebug();
BOOL HideThread(_In_opt_ HANDLE hThread);

/* VMDetection : VMDetect.c */
BOOL fnCheckVMPresent();

/* ConsoleHost : Console.c */
BOOL fnOpenConsole();

/* NT Functions : NT.c */
BOOL fnAdjustPrivilege(_In_ PCTSTR lpszPrivilege, _In_ BOOL bEnablePrivilege);

/* FileSystem Tools : FileSytsem.c */
BOOL fnWriteFileW(_In_ PCWSTR pFileName, _In_ PVOID pBuffer, _In_ SIZE_T nBuffer);