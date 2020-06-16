/* Base64 Encoder/Decoder taken from FreeBSD Project.
   Modified Version (Style Convention), no Newlines.
   It also doesn't zero Terminate the string! */

#include "pch.h"
#include "_rift.h"

CONST CHAR g_Base64Table[64] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/"
};

PBYTE EBase64Decode(
	_In_  PBYTE   pBuffer,
	_In_  SIZE_T  nBuffer,
	_Out_ PSIZE_T nResult
) {
	BYTE bDTable[256];
	SetMemory(bDTable, 0x80, 256);
	for (UINT i = 0; i < sizeof(g_Base64Table) - 1; i++)
		bDTable[g_Base64Table[i]] = (BYTE)i;
	bDTable['='] = 0;

	SIZE_T nC = 0;
	for (UINT i = 0; i < nBuffer; i++)
		if (bDTable[pBuffer[i]] != 0x80)
			nC++;
	if (!nC || nC % 4)
		return 0;

	CONST PBYTE pOut = AllocMemory(nC / 4 * 3);
	PBYTE pPos = pOut;
	if (!pOut)
		return 0;

	BYTE bPad = 0, bBlock[4];
	nC = 0;
	for (UINT i = 0; i < nBuffer; i++) {
		if (pBuffer[i] == '=')
			bPad++;
		bBlock[nC] = bDTable[pBuffer[i]];
		nC++;

		if (nC == 4) {
			*pPos++ = (bBlock[0] << 2) | (bBlock[1] >> 4);
			*pPos++ = (bBlock[1] << 4) | (bBlock[2] >> 2);
			*pPos++ = (bBlock[2] << 6) | bBlock[3];
			nC = 0;

			if (bPad) {
				if (bPad == 1)
					pPos--;
				else if (bPad == 2)
					pPos -= 2;
				else {
					FreeMemory(pOut);
					return 0;
				} break;
			}
		}
	}

	*nResult = pPos - pOut;
	return pOut;
}