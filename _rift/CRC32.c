#include "pch.h"
#include "_rift.h"

PUINT32 fnAllocTable() {
	UINT32 dwa2X[2];
	PUINT32 dwa256T = (PUINT32)malloc(256 * sizeof(INT32));

	for (UINT32 i = 0; i < 256; i++) {
		for (dwa2X[0] = i << 24, dwa2X[1] = 8; dwa2X[1] > 0; dwa2X[1]--)
			dwa2X[0] = dwa2X[0] & 0x80000000 ? (dwa2X[0] << 1) ^ 0x04c11db7 : (dwa2X[0] << 1);
		dwa256T[i] = dwa2X[0];
	}

	return dwa256T;
}

UINT32 fnCRC32(
	_In_ PBYTE   pData,
	_In_ UINT32  ui32DataLen,
	_In_ PUINT32 ui32a256Table
) {
	UINT32 ui32Crc = 0;
	while (ui32DataLen--) {
		ui32Crc = (ui32Crc << 8) ^ ui32a256Table[((ui32Crc >> 24) ^ *pData) & 255];
		pData++;
	}

	return ui32Crc;
}
