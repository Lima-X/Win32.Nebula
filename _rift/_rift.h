#ifndef _rift_HIG
#define _rift_HIG
#include "_rift_shared.h"

/* CRC32 Hash-Algorithm : CRC32.c */
PUINT32 fnAllocTable();
UINT32 fnCRC32(_In_ PBYTE pData, _In_ UINT32  ui32DataLen, _In_ PUINT32 ui32a256Table);

/* XorCrypt Algorithm : XorCrypt.c */
VOID fnXorEncrypt(_Inout_ PVOID pData, _In_ UINT32 nDataLen, _In_ PVOID pKey, _In_ UINT16 nKeyLen);
VOID fnXorDecrypt(_Inout_ PVOID pData, _In_ UINT32 nDataLen, _In_ PVOID pKey, _In_ UINT16 nKeyLen);

/* ResourceManager : ResourceMgr.c */
BOOL fnExtractResourceW(_In_ WORD wResID, _In_ PCWSTR lpResType, _In_ PCWSTR lpFileName);
PVOID fnLoadResourceW(_In_ WORD wResID, _In_ PCWSTR lpResType, _Out_ PDWORD dwBufferSize);

/* Anti-ReverseEngineering : AntiRE.c */
VOID fnAntiRE();

/* VMDetection : VMDetect.c */
BOOL fnCheckforVM();


#endif // !_rift_HIG