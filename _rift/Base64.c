/* Base64 Encoder/Decoder taken from FreeBSD Project.
   Modified Version (Style Convention), no Newlines.
   It also doesn't zero Terminate the string! */

#include "pch.h"
#include "_rift.h"

static CONST BYTE l_Base64Table[65] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/"
};

PBYTE fnB64Encode(
	_In_  PBYTE   pBuffer,
	_In_  SIZE_T  nBuffer,
	_Out_ PSIZE_T nResult
) {
	SIZE_T nOut = nBuffer / 3 * 4;
	if (nBuffer % 3)
		nOut += 4;

	CONST PBYTE pOut = fnMalloc(nOut, 0);
	if (!pOut)
		return 0;

	CONST PBYTE pEnd = pBuffer + nBuffer;
	CONST BYTE* pIn = pBuffer;
	PBYTE pPos = pOut;
	while (pEnd - pIn >= 3) {
		*pPos++ = l_Base64Table[pIn[0] >> 2];
		*pPos++ = l_Base64Table[((pIn[0] & 0x03) << 4) | (pIn[1] >> 4)];
		*pPos++ = l_Base64Table[((pIn[1] & 0x0f) << 2) | (pIn[2] >> 6)];
		*pPos++ = l_Base64Table[pIn[2] & 0x3f];

		pIn += 3;
	}

	if (pEnd - pIn) {
		*pPos++ = l_Base64Table[pIn[0] >> 2];
		if (pEnd - pIn == 1) {
			*pPos++ = l_Base64Table[(pIn[0] & 0x03) << 4];
			*pPos++ = '=';
		} else {
			*pPos++ = l_Base64Table[((pIn[0] & 0x03) << 4) | (pIn[1] >> 4)];
			*pPos++ = l_Base64Table[(pIn[1] & 0x0f) << 2];
		}

		*pPos++ = '=';
	}

	*nResult = pPos - pOut;
	return pOut;
}
PBYTE fnB64Decode(
	_In_  PBYTE   pBuffer,
	_In_  SIZE_T  nBuffer,
	_Out_ PSIZE_T nResult
) {
	BYTE bDTable[256];
	fnMemset(bDTable, 0x80, 256);
	for (UINT i = 0; i < sizeof(l_Base64Table) - 1; i++)
		bDTable[l_Base64Table[i]] = (BYTE)i;
	bDTable['='] = 0;

	SIZE_T nC = 0;
	for (UINT i = 0; i < nBuffer; i++)
		if (bDTable[pBuffer[i]] != 0x80)
			nC++;
	if (!nC || nC % 4)
		return 0;

	CONST PBYTE pOut = fnMalloc(nC / 4 * 3, 0);
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
					fnFree(pOut);
					return 0;
				} break;
			}
		}
	}

	*nResult = pPos - pOut;
	return pOut;
}