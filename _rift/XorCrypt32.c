#include "pch.h"
#include "_rift.h"

static inline VOID fnRoAL(
	_In_ PVOID  pKey,
	_In_ UINT16 nKeyLen
) {
	UINT8 bT = ((UINT32*)pKey)[0] >> ((sizeof(UINT32) * 8) - 1);
	for (UINT8 i = 0; i < (((nKeyLen / 8) / sizeof(UINT32)) - 1); i++) {
		((UINT32*)pKey)[i] <<= 1;
		((UINT32*)pKey)[i] |= ((UINT32*)pKey)[i + 1] >> ((sizeof(UINT32) * 8) - 1);
	}

	((UINT32*)pKey)[((nKeyLen / 8) / sizeof(UINT32)) - 1] <<= 1;
	((UINT32*)pKey)[((nKeyLen / 8) / sizeof(UINT32)) - 1] |= bT;
}

VOID fnXorEncrypt(
	_Inout_ PVOID  pData,
	_In_    UINT32 nDataLen,
	_In_    PVOID  pKey,
	_In_    UINT16 nKeyLen
) {
	for (UINT32 i = 0; i < (nDataLen / sizeof(UINT32)); i++) {
		UINT32 dwT = ((UINT32*)pData)[i];
		((UINT32*)pData)[i] ^= ((UINT32*)pKey)[i % ((nKeyLen / 8) / sizeof(UINT32))];
		((UINT32*)pKey)[i % ((nKeyLen / 8) / sizeof(UINT32))] ^= dwT;
		fnRoAL(pKey, nKeyLen);
	}
}

VOID fnXorDecrypt(
	_Inout_ PVOID  pData,
	_In_    UINT32 nDataLen,
	_In_    PVOID  pKey,
	_In_    UINT16 nKeyLen
) {
	for (UINT32 i = 0; i < nDataLen / sizeof(UINT32); i++) {
		((UINT32*)pData)[i] ^= ((UINT32*)pKey)[i % ((nKeyLen / 8) / sizeof(UINT32))];
		((UINT32*)pKey)[i % ((nKeyLen / 8) / sizeof(UINT32))] ^= ((UINT32*)pData)[i];
		fnRoAL(pKey, nKeyLen);
	}
}