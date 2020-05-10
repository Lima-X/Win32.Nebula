#ifndef _rift_HIG
#define _rift_HIG
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#include "_rift_shared.h"

/* CRC32 Hash-Algorithm : CRC32.c */
PUINT32 fnAllocTable();
UINT32 fnCRC32(_In_ PBYTE pData, _In_ UINT32  ui32DataLen, _In_ PUINT32 ui32a256Table);

/* XorCrypt Algorithm : XorCrypt.c */
VOID fnXorEncrypt(_Inout_ PVOID pData, _In_ UINT32 nDataLen, _Inout_ PVOID pKey, _In_ UINT16 nKeyLen);
VOID fnXorDecrypt(_Inout_ PVOID pData, _In_ UINT32 nDataLen, _Inout_ PVOID pKey, _In_ UINT16 nKeyLen);

/* Xoshiro PRNG Algorithm : Xoshiro.c */
UINT32 fnNext128ss(_Inout_ PVOID pui32S);
UINT32 fnNext128p(_Inout_ PVOID pui32S);
VOID fnLJump128(_Inout_ PVOID pui32S);
VOID fnSJump128(_Inout_ PVOID pui32S);
UINT32 fnURID32(_In_ UINT32 ui32Max, _In_ UINT32 ui32Min, _Inout_ PVOID pui32S);
float fnURRD24(_Inout_ PVOID pui32S);
PVOID fnAllocXSR(_In_ UINT64 ui64Seed, _In_ sXSRP sParamA, _In_ sSMP sParamB);
PVOID fnRelocXSR(_Inout_ PVOID pui32S, _In_ UINT64 ui64Seed, _In_ sXSRP sParamA, _In_ sSMP sParamB);
PVOID fnCopyXSR(_In_ PVOID pui32S);
VOID fnDelocXSR(_Inout_ PVOID pui32S);

/* ResourceManager : ResourceMgr.c */
BOOL fnExtractResourceW(_In_ WORD wResID, _In_ PCWSTR lpResType, _In_ PCWSTR lpFileName);
PVOID fnLoadResourceW(_In_ WORD wResID, _In_ PCWSTR lpResType, _Out_ PDWORD dwBufferSize);

/* Anti-ReverseEngineering : AntiRE.c */
VOID fnAntiRE();

/* VMDetection : VMDetect.c */
BOOL fnCheckVMPresent();


#endif // !_rift_HIG