#ifndef _rift_HIG
#define _rift_HIG

#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma warning(disable : 4214)
#include "_rift_shared.h"
#include "resource.h"

/* Main : main.c */
extern WCHAR g_wcsMFN[MAX_PATH];
extern WCHAR g_wcsCD[MAX_PATH];
extern HMODULE g_hmCM;
extern HANDLE g_hPH;

/* CRC32 Hash-Algorithm : CRC32.c */
VOID fnAllocTable();
UINT32 fnCRC32(_In_ PBYTE pData, _In_ UINT32  ui32DataLen);

/* XorCrypt Algorithm : XorCrypt.c */
VOID fnXorEncrypt(_Inout_ PVOID pData, _In_ UINT32 nDataLen, _Inout_ PVOID pKey, _In_ UINT16 nKeyLen);
VOID fnXorDecrypt(_Inout_ PVOID pData, _In_ UINT32 nDataLen, _Inout_ PVOID pKey, _In_ UINT16 nKeyLen);

/* Xoshiro PRNG Algorithm : Xoshiro.c */
UINT32 fnNext128ss(_Inout_ PVOID pui32S);
UINT32 fnNext128p(_Inout_ PVOID pui32S);
#if _DISABLE_JUMPS == 0
VOID fnLJump128(_Inout_ PVOID pui32S);
VOID fnSJump128(_Inout_ PVOID pui32S);
#endif
UINT32 fnURID32(_In_ UINT32 ui32Max, _In_ UINT32 ui32Min, _Inout_ PVOID pui32S);
float fnURRD24(_Inout_ PVOID pui32S);
PVOID fnAllocXSR(_In_ pXSRP sParamA, _In_ pSMP sParamB);
BOOL fnRelocXSR(_Inout_ PVOID pS, _In_ pXSRP sParamA, _In_ pSMP sParamB);
PVOID fnCopyXSR(_In_ PVOID pui32S);
VOID fnDelocXSR(_Inout_ PVOID pui32S);

/* ResourceManager : Resource.c */
BOOL fnExtractResourceW(_In_ WORD wResID, _In_ PCWSTR lpResType, _In_ PCWSTR lpFileName);
PVOID fnLoadResourceW(_In_ WORD wResID, _In_ PCWSTR lpResType, _Out_ PDWORD dwBufferSize);

/* Anti-ReverseEngineering : AntiRE.c */
VOID fnAntiRE();

/* VMDetection : VMDetect.c */
BOOL fnCheckVMPresent();

/* Crypto Tools : BCrypt.c */
NTSTATUS fnBCryptOpenRNGH();
NTSTATUS fnBCryptCloseRNGH();
PVOID fnBCryptGenRandomFB(_In_ PVOID pBuffer, _In_ UINT32 ui32BufferSize);

/* ConsoleHost : Console.c */
BOOL fnAllocConsole();

#endif // !_rift_HIG