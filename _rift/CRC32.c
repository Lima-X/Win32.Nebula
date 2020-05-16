#include "pch.h"
#include "_rift.h"

static PUINT32 ui32a256Table;
VOID fnAllocTable() {
	UINT32 ui32a2X[2];
	ui32a256Table = (PUINT32)malloc(256 * sizeof(INT32));

	for (UINT32 i = 0; i < 256; i++) {
		for (ui32a2X[0] = i << 24, ui32a2X[1] = 8; ui32a2X[1] > 0; ui32a2X[1]--)
			ui32a2X[0] = ui32a2X[0] & 0x80000000 ? (ui32a2X[0] << 1) ^ 0x04c11db7 : (ui32a2X[0] << 1);
		ui32a256Table[i] = ui32a2X[0];
	}
}

UINT32 fnCRC32(
	_In_ PUCHAR pData,
	_In_ UINT32 ui32DataLen
) {
	UINT32 ui32Crc = 0;
	while (ui32DataLen--) {
		ui32Crc = (ui32Crc << 8) ^ ui32a256Table[((ui32Crc >> 24) ^ *(PBYTE)pData) & 255];
		pData++;
	}

	return ui32Crc;
}
