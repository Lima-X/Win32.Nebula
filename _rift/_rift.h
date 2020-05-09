#ifndef _rift_HIG
#define _rift_HIG
#include "_rift_shared.h"

/* CRC32 Algorithm : CRC32.c */
PUINT32 fnAllocTable();
UINT32 fnCRC32(_In_ PBYTE pData, _In_ UINT32  ui32DataLen, _In_ PUINT32 ui32a256Table);

/* XorCrypt Algorithm : XorCrypt.c */
VOID fnXorEncrypt(_Inout_ PVOID pData, _In_ UINT32 nDataLen, _In_ PVOID pKey, _In_ UINT16 nKeyLen);
VOID fnXorDecrypt(_Inout_ PVOID pData, _In_ UINT32 nDataLen, _In_ PVOID pKey, _In_ UINT16 nKeyLen);

#endif // !_rift_HIG