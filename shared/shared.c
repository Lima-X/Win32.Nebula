#ifdef _riftldr
#include "..\_riftldr\_riftldr.h"
#elif _riftTool
#include "..\_riftTool\_riftTool.h"
#endif

// Standard Base64 Table
EXTERN_C CONST CHAR e_Base64Table[64];

/* Base64 Encoder/Decoder taken from FreeBSD Project. */
STATIC PCSTR IBase64EncodeA(
	_In_  PVOID   pData,
	_In_  SIZE_T  nData,
	_Out_ PSIZE_T nOut,
	_In_  PCSTR   pTable,
	_In_  BOOLEAN bPad
) {
	if (nData >= SIZE_MAX / 4)
		return NULL;
	SIZE_T nOLen = nData * 4 / 3 + 4;
	if (bPad)
		nOLen += nOLen / 72;
	nOLen++;
	if (nOLen < nData)
		return NULL;
	PCHAR pOut = AllocMemory(nOLen);
	if (!pOut)
		return NULL;

	PVOID pEnd = (PTR)pData + nData;
	PBYTE pIn = pData;
	PCHAR pPos = pOut;
	UINT8 nLLen = 0;
	while ((PTR)pEnd - (PTR)pIn >= 3) {
		*pPos++ = pTable[(pIn[0] >> 2) & 0x3f];
		*pPos++ = pTable[(((pIn[0] & 0x03) << 4) | (pIn[1] >> 4)) & 0x3f];
		*pPos++ = pTable[(((pIn[1] & 0x0f) << 2) | (pIn[2] >> 6)) & 0x3f];
		*pPos++ = pTable[pIn[2] & 0x3f];

		pIn += 3;
		nLLen += 4;
		if (bPad && nLLen >= 72) {
			*pPos++ = '\n';
			nLLen = 0;
		}
	}

	if ((PTR)pEnd - (PTR)pIn) {
		*pPos++ = pTable[(pIn[0] >> 2) & 0x3f];
		if ((PTR)pEnd - (PTR)pIn == 1) {
			*pPos++ = pTable[((pIn[0] & 0x03) << 4) & 0x3f];
			if (bPad)
				*pPos++ = '=';
		} else {
			*pPos++ = pTable[(((pIn[0] & 0x03) << 4) |
				(pIn[1] >> 4)) & 0x3f];
			*pPos++ = pTable[((pIn[1] & 0x0f) << 2) & 0x3f];
		} if (bPad)
			*pPos++ = '=';
		nLLen += 4;
	} if (bPad && nLLen)
		*pPos++ = '\n';

	*pPos = '\0';
	if (nOut)
		*nOut = pPos - pOut;
	return pOut;
}
PCSTR EBase64EncodeA(
	_In_  PVOID   pData,
	_In_  SIZE_T  nData,
	_Out_ PSIZE_T nResult
) {
	return IBase64EncodeA(pData, nData, nResult, e_Base64Table, TRUE);
}

STATIC PVOID IBase64DecodeA(
	_In_  PCSTR   pString,
	_In_  SIZE_T  nString,
	_Out_ PSIZE_T nOut,
	_In_  PCSTR   pTable
) {
	CHAR cTable[256];
	SetMemory(cTable, 0x80, 256);
	for (UINT8 i = 0; i < 64; i++)
		cTable[pTable[i]] = (CHAR)i;
	cTable['='] = '\0';

	SIZE_T nC = 0;
	for (UINT i = 0; i < nString; i++)
		if (cTable[pString[i]] != 0x80)
			nC++;
	if (!nC)
		return NULL;

	UINT nEPad = (4 - nC % 4) % 4;
	SIZE_T nOLen = (nC + nEPad) / 4 * 3;
	PVOID pOut = AllocMemory(nOLen);
	PBYTE pPos = pOut;
	if (!pOut)
		return NULL;

	UINT nPad = 0;
	BYTE bBlock[4];
	nC = 0;
	for (UINT i = 0; i < nString + nEPad; i++) {
		CHAR bVal;
		if (i >= nString)
			bVal = '=';
		else
			bVal = pString[i];

		BYTE bT = cTable[bVal];
		if (bT == 0x80)
			continue;
		if (bVal == '=')
			nPad++;

		bBlock[nC] = bT;
		nC++;
		if (nC == 4) {
			*pPos++ = (bBlock[0] << 2) | (bBlock[1] >> 4);
			*pPos++ = (bBlock[1] << 4) | (bBlock[2] >> 2);
			*pPos++ = (bBlock[2] << 6) | bBlock[3];
			nC = 0;

			if (nPad) {
				if (nPad == 1)
					pPos--;
				else if (nPad == 2)
					pPos -= 2;
				else {
					/* Invalid padding */
					FreeMemory(pOut);
					return NULL;
				} break;
			}
		}
	}

	*nOut = pPos - pOut;
	return pOut;
}
PVOID EBase64DecodeA(
	_In_  PCSTR   pString,
	_In_  SIZE_T  nString,
	_Out_ PSIZE_T nResult
) {
	return IBase64DecodeA(pString, nString, nResult, e_Base64Table);
}

// UUID Encoder/Decoder
PCSTR EUuidEncodeA(
	_In_ PUUID pId
) {
	PSTR sz = AllocMemory((16 * 2) + 5);
	for (UINT8 i = 0; i < 2; i++)
		for (UINT8 j = 0; j < 2 + (4 * i); j++)
			StringCchPrintfA((sz + j * 2) + (19 + 5 * i), 2 + 1, "%02x", pId->Data4[j + (2 * i)]);
	sz[19 + 4] = '-';
	StringCchPrintfA(sz, ((16 * 2) + 5), "%08x-%04x-%04x-%s",
		pId->Data1, pId->Data2, pId->Data3,
		sz + 19);
	return sz;
}

FORCEINLINE UINT8 ICharToInt(
	_In_ CHAR c
) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
}
VOID EUuidDecodeA(
	_In_  PCSTR pString,
	_Out_ PUUID pId
) {
	CONST SIZE_T nPart[] = { 8, 4, 4 };
	for (UINT8 i = 0; i < sizeof(nPart) / sizeof(SIZE_T); i++) {

	}


	while (pString[0] && pString[1]) {
		if (pString[0] == '-')
			pString++;
		*(((PBYTE)pId)++) = (ICharToInt(pString[0]) << 4) + ICharToInt(pString[1]);
		(PTR)pString += 2;
	}
}

PVOID ISigScan(
	_In_ PVOID  pData, // Address of Data
	_In_ SIZE_T nData, // Sizeof Data
	_In_ PSIG   sig    // Signature
) {
	while ((nData-- - sig->nLength) + 1) {
		SIZE_T nSig = sig->nLength;
		while (nSig--)
			if ((sig->szMask[nSig] == 'x') && (((PBYTE)pData)[nSig] != ((PBYTE)sig->pSig)[nSig]))
				break;
		if (nSig == -1)
			return pData;
		((PBYTE)pData)++;
	} return NULL;
}