#include "pch.h"
#include "_rift_shared.h"
#ifdef _rift
#include "_rift.h"
#endif

// Deprecated, use md5 implementation instead
// will be removed in the future when md5 is fully implemented
static PDWORD l_dwa256Table;
DWORD fnCRC32(
	_In_ PBYTE pBuffer,
	_In_ SIZE_T nBufferLen
) {
	DWORD dwCRC = 0;
	while (nBufferLen--) {
		dwCRC = (dwCRC << 8) ^ l_dwa256Table[((dwCRC >> 24) ^ *(PBYTE)pBuffer) & 255];
		pBuffer++;
	}

	return dwCRC;
}

VOID fnAllocTable() {
	DWORD dwa2T[2];
	l_dwa256Table = (PDWORD)HeapAlloc(g_hPH, 0, 256 * sizeof(DWORD));

	for (UINT16 i = 0; i < 256; i++) {
		for (dwa2T[0] = i << 24, dwa2T[1] = 8; dwa2T[1] > 0; dwa2T[1]--)
			dwa2T[0] = dwa2T[0] & 0x80000000 ? (dwa2T[0] << 1) ^ 0x04c11db7 : (dwa2T[0] << 1);
		l_dwa256Table[i] = dwa2T[0];
	}
}
VOID fnFreeTable() {
	if (l_dwa256Table)
		HeapFree(g_hPH, 0, l_dwa256Table);
	l_dwa256Table = 0;
}