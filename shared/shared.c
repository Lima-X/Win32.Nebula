#ifdef _riftldr
#include "..\_riftldr\_riftldr.h"
#elif _riftTool
#include "..\_riftTool\_riftTool.h"
#endif

// Standard Base64 Table
EXTERN_C CONST CHAR e_Base64Table[64];

/* Base64 Encoder/Decoder taken from FreeBSD Project. */
STATUS EBase64EncodeA(        // returns length of string(not including Null) or space needed for string
	_In_      PVOID   pData,  // Data to be encoded
	_In_      SIZE_T  nData,  // Size of Data
	_Out_opt_ PSTR    psz,    // Output Buffer to fill / if NULL Calculates the neccessary size
	_In_      PCSTR   pTable, // Base64 Table to use
	_In_      BOOLEAN bPad    // Enables Padding
) {
	if (nData >= (((UINT)-1) / 2) / 4)
		return -1; // Too much Data
	if (!psz) { // Calculate Neccessary Space if Output is NULL
		// Raw Space Needed
		SIZE_T nOLen = nData / 3 * 4;
		if (nData % 3)
			nOLen += 4;
		if (bPad) { // Add Space Needed for Padding
			SIZE_T nPad = nOLen / 72;
			if (nPad && !(nOLen % 72))
				nPad--;
			nOLen += nPad;
		}
		nOLen++; // Nullterminator
		if (nOLen <	nData)
			return -2; // Overflow
		return nOLen;
	}

	// Encode Data
	PTR pEnd = (PTR)pData + nData;
	PCHAR pPos = psz;
	UINT8 nPLen = 0;
	while (pEnd - (PTR)pData >= 3) { // Encode full Blocks
		*pPos++ = pTable[(((PBYTE)pData)[0] >> 2) & 0x3f];
		*pPos++ = pTable[(((((PBYTE)pData)[0] & 0x03) << 4) | (((PBYTE)pData)[1] >> 4)) & 0x3f];
		*pPos++ = pTable[(((((PBYTE)pData)[1] & 0x0f) << 2) | (((PBYTE)pData)[2] >> 6)) & 0x3f];
		*pPos++ = pTable[((PBYTE)pData)[2] & 0x3f];

		((PBYTE)pData) += 3, nPLen += 4;
		if (bPad && nPLen >= 72) // Add Newline after 72-Chars
			*pPos++ = '\n', nPLen = 0;
	} if (pEnd - (PTR)pData) { // Encode last Block (with Padding) if neccessary
		*pPos++ = pTable[(((PBYTE)pData)[0] >> 2) & 0x3f];
		if (pEnd - (PTR)pData == 1) {
			*pPos++ = pTable[((((PBYTE)pData)[0] & 0x03) << 4) & 0x3f];
			if (bPad)
				*pPos++ = '=';
		} else {
			*pPos++ = pTable[(((((PBYTE)pData)[0] & 0x03) << 4) | (((PBYTE)pData)[1] >> 4)) & 0x3f];
			*pPos++ = pTable[((((PBYTE)pData)[1] & 0x0f) << 2) & 0x3f];
		} if (bPad)
			*pPos++ = '=';
		nPLen += 4;
	} if (bPad && !nPLen) // Remove last Newline if on 72-Char Boundary
		pPos--;

	*pPos = '\0';
	return pPos - (PTR)psz; // Return actuall Size (not including Nullterminator)
}

STATUS EBase64DecodeA(      // Decodes a Base64 String / returns Size of Data
	_In_      PCSTR  psz,   // Base64 String to decode
	_In_      SIZE_T nsz,   // Length of String
	_Out_opt_ PVOID  pData, // Output Buffer to fill with raw Data
	_In_      PUCHAR pTable // Base64 Table to use
) {
	// Setup Internal Table & get unpadded Length
	PCHAR cTable = AllocMemory(256);
	SetMemory(cTable, 0x80, 256);
	for (UINT8 i = 0; i < 64; i++)
		cTable[pTable[i]] = (CHAR)i;
	cTable['='] = '\0';
	SIZE_T nC = 0;
	for (UINT i = 0; i < nsz; i++)
		if (cTable[((PUCHAR)psz)[i]] != 0x80)
			nC++;
	if (!nC)
		return -1; // Invalid Size

	// Calculate Padding (optional: return size of space needed)
	UINT nEPad = (4 - nC % 4) % 4;
	if (!pData)
		return (nC + nEPad) / 4 * 3; // return required space
	nC = 0;

	UINT nPad = 0;
	BYTE bBlock[4];
	PBYTE pPos = pData;
	for (UINT i = 0; i < nsz + nEPad; i++) {
		// Ignore Padding
		CHAR bVal;
		if (i >= nsz)
			bVal = '=';
		else
			bVal = psz[i];
		BYTE bT = cTable[bVal];
		if (bT == 0x80)
			continue;
		if (bVal == '=')
			nPad++;

		// Decode Block
		bBlock[nC] = bT;
		nC++;
		if (nC == 4) {
			*pPos++ = (bBlock[0] << 2) | (bBlock[1] >> 4);
			*pPos++ = (bBlock[1] << 4) | (bBlock[2] >> 2);
			*pPos++ = (bBlock[2] << 6) | bBlock[3];

			nC = 0;
			if (nPad) { // Remove Padding
				if (nPad == 1)
					pPos--;
				else if (nPad == 2)
					pPos -= 2;
				else
					return -2; // Invalid Padding
				break;
			}
		}
	}

	FreeMemory(cTable);
	return (PTR)pPos - (PTR)pData;
}

/* UUID Converters */
// TODO: maybe rewrite this, its nightmareful
DEPRECATED VOID EUuidEncodeA(      // UUID to String
	_In_  PUUID pId,    // UUID to Encode
	_Out_ PSTR  pString // String to fill
) {
	for (UINT8 i = 0; i < 2; i++)
		for (UINT8 j = 0; j < 2 + (4 * i); j++)
			StringCchPrintfA((pString + j * 2) + (19 + 5 * i), 2 + 1, "%02x", pId->Data4[j + (2 * i)]);
	pString[19 + 4] = '-';
	StringCchPrintfA(pString,  UUID_STRLEN, "%08x-%04x-%04x-%s", pId->Data1, pId->Data2, pId->Data3, pString + 19);
}

FORCEINLINE UINT8 ICharToHex( // Char to Hexvalue
	_In_ CHAR c               // Char to convert
) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
}
VOID EUuidDecodeA(       // String to UUID
	_In_  PCSTR pString, // String to Decode
	_Out_ PUUID pId      // UUID to fill
) {
	CONST UINT8 nPart[] = { 4, 2, 2 };
	for (UINT8 i = 0; i < sizeof(nPart); i++) {
		UINT nC = nPart[i];
		while (nC--)
			((PBYTE)pId)[nC] = (ICharToHex(*pString++) << 4) + ICharToHex(*pString++);
		(PBYTE)pId += nPart[i];
		pString++;
	} while (pString[0] && pString[1]) {
		if (pString[0] == '-')
			pString++;
		*((PBYTE)pId)++ = (ICharToHex(*pString++) << 4) + ICharToHex(*pString++);
	}
}

#if 0
// Wrappers for rpcApi UUID's (unneccessary)
STATUS EUidToStringW(     // UUID to String
	_In_  PUUID  pId,     // UUID to Encode
	_Out_ PWSTR  pString, // String to fill
	_In_  SIZE_T nString  // Size of String
) {
	RPC_WSTR rpcString;
	STATUS s = UuidToStringW(pId, &rpcString);
	s |= StringCchCopyW(pString, nString, rpcString);
	s |= RpcStringFreeW(&rpcString);
	return s;
}
STATUS EUidFromStringW(   // String to UUID
	_In_  PCWSTR pString, // String to Decode
	_Out_ PUUID  pId      // UUID to fill
) {
	return UuidFromStringW(pString, pId);
}
#endif

PVOID ESigScan(        // Signatrure Scanner/Finder
	_In_ PVOID  pData, // Address of Data
	_In_ SIZE_T nData, // Size of Data
	_In_ PSIG   sig    // Signature Info
) {
	do {
		SIZE_T nSig = sig->nLength;
		while (nSig--)
			if ((sig->szMask[nSig] == 'x') && (((PBYTE)pData)[nSig] != ((PBYTE)sig->pSig)[nSig]))
				break;
		if (nSig == -1)
			return pData;
		((PBYTE)pData)++;
	} while (nData-- - sig->nLength);
	return NULL;
}
