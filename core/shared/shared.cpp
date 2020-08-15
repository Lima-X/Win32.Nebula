#ifdef _riftldr
#include "..\_riftldr\_riftldr.h"
#elif _riftTool
#include "..\_riftTool\_riftTool.h"
#endif

namespace alg {
#pragma region Base64
	/* Base64 Encoder/Decoder taken from FreeBSD Project.
	   Migrated to C++ into a class */
	Base64::Base64(
		_In_opt_ void(*TableConstructorCbA)(_In_ void* pTable)
	) {
		pcTable = (char*)malloc(64);
		if (!TableConstructorCbA) {
			// This constructs the standard Base64 Table
			const char ofs[] = { 'A', 'a' }; // offsets to startingpoints in ascii128 table
			const char ofl[] = { 31, 31 };   // run length of offsets
			for (char i = 0, n = 0; i < sizeof(ofs); n += ofl[i], i++)
				for (char j = 0; j < ofl[i]; j++)
					pcTable[n + j] = ofs[i] + j;

			const char ext[] = { '+', '/' }; // single extra chars
			for (char i = 0; i < 2; i++)
				pcTable[i + 62] = ext[i];
		} else
			TableConstructorCbA(pcTable);
	}
	Base64::~Base64() {
		free(pcTable);
		pcTable = nullptr;
	}
	status Base64::EBase64EncodeA( // returns length of string(not including Null) or space needed for string
		_In_      void*  pData,    // Data to be encoded
		_In_      size_t nData,    // Size of Data
		_Out_opt_ PSTR   psz,      // Output Buffer to fill / if nul Calculates the neccessary size
		_In_      bool   bPad      // Enables Padding
	) {
		if (nData >= (((uint)-1) / 2) / 4)
			return -1; // Too much Data
		if (!psz) { // Calculate Neccessary Space if Output is NULL
			// Raw Space Needed
			size_t nOLen = (nData / 3) * 4;
			nOLen += 4 * !!(nData % 3);
			if (bPad) { // Add Space Needed for Padding
				size_t nPad = nOLen / 72;
				if (nPad && !(nOLen % 72))
					nPad--;
				nOLen += nPad;
			}
			nOLen++; // Nullterminator
			if (nOLen < nData)
				return -2; // Overflow
			return nOLen;
		}

		// Encode Data
		ptr pEnd = (ptr)pData + nData;
		char* pPos = psz;
		char nPLen = 0;
		while (pEnd - (ptr)pData >= 3) { // Encode full Blocks
			*pPos++ = pcTable[(((byte*)pData)[0] >> 2) & 0x3f];
			*pPos++ = pcTable[(((((byte*)pData)[0] & 0x03) << 4) | (((byte*)pData)[1] >> 4)) & 0x3f];
			*pPos++ = pcTable[(((((byte*)pData)[1] & 0x0f) << 2) | (((byte*)pData)[2] >> 6)) & 0x3f];
			*pPos++ = pcTable[((byte*)pData)[2] & 0x3f];

			(*(byte**)&pData) += 3, nPLen += 4;
			if (bPad && nPLen >= 72) // Add Newline after 72-Chars
				*pPos++ = '\n', nPLen = 0;
		} if (pEnd - (ptr)pData) { // Encode last Block (with Padding) if neccessary
			*pPos++ = pcTable[(((byte*)pData)[0] >> 2) & 0x3f];
			if (pEnd - (ptr)pData == 1) {
				*pPos++ = pcTable[((((byte*)pData)[0] & 0x03) << 4) & 0x3f];
				if (bPad)
					*pPos++ = '=';
			} else {
				*pPos++ = pcTable[(((((byte*)pData)[0] & 0x03) << 4) | (((byte*)pData)[1] >> 4)) & 0x3f];
				*pPos++ = pcTable[((((byte*)pData)[1] & 0x0f) << 2) & 0x3f];
			} if (bPad)
				*pPos++ = '=';
			nPLen += 4;
		} if (bPad && !nPLen) // Remove last Newline if on 72-Char Boundary
			pPos--;

		*pPos = '\0';
		return (status)(pPos - (ptr)psz); // Return actuall Size (not including Nullterminator)
	}
	status Base64::EBase64DecodeA( // Decodes a Base64 String / returns Size of Data
		_In_      PCSTR  psz,      // Base64 String to decode
		_In_      size_t nsz,      // Length of String
		_Out_opt_ void*  pData     // Output Buffer to fill with raw Data / if nul calculates the neccessary size
	) {
		// Setup Internal Table & get unpadded Length
		char* const cTable = (char*)malloc(256);
		memset(cTable, 0x80, 256);
		for (char i = 0; i < 64; i++)
			cTable[pcTable[i]] = (char)i;
		cTable['='] = '\0';
		size_t nC = 0;
		for (uint i = 0; i < nsz; i++)
			if (cTable[((uchar*)psz)[i]] != 0x80)
				nC++;
		if (!nC)
			return -1; // Invalid Size

		// Calculate Padding (optional: return size of space needed)
		const uint nEPad = (4 - nC % 4) % 4;
		if (!pData)
			return (nC + nEPad) / 4 * 3; // return required space
		nC = 0;

		uint  nPad = 0;
		byte  bBlock[4];
		byte* pPos = (byte*)pData;
		for (uint i = 0; i < nsz + nEPad; i++) {
			// Ignore Padding
			CHAR bVal;
			if (i >= nsz)
				bVal = '=';
			else
				bVal = psz[i];
			byte bT = cTable[bVal];
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

		free(cTable);
		return (ptr)pPos - (ptr)pData;
	}

#pragma region Base64Sub
	void IBase64ObfuscatedTableCbA(
		_In_ void* pTable
	) {
		const char ofs[] = { '#', '(', ']', 'a' }; // offsets to startingpoints in ascii128 table
		const char ofl[] = { 4, 25 + 1, 3, 30 };   // run length of offsets
		for (char i = 0, n = 1; i < sizeof(ofs); n += ofl[i], i++)
			for (char j = 0; j < ofl[i]; j++)
				((char*)pTable)[n + j] = ofs[i] + j;

		const word ext[] = { '!' << 8 | 0, '[' << 8 | 29 }; // single extra chars with offsets (format: char-offset)
		for (char i = 0; i < sizeof(ext) / sizeof(*ext); i++)
			((char*)pTable)[ext[i] & 0xff] = ext[i] >> 8;
	}
#pragma endregion
#pragma endregion

#pragma region Uuid
	/* UUID Converters */
	// TODO: maybe rewrite this, its nightmarefuel
	DEPRECATED VOID EUuidEncodeA(      // UUID to sString
		_In_  UUID* pId,    // UUID to Encode
		_Out_ PSTR  pString // String to fill
	) {
		for (char i = 0; i < 2; i++)
			for (char j = 0; j < 2 + (4 * i); j++)
				sprintf((pString + j * 2) + (19 + 5 * i), "%02x", pId->Data4[j + (2 * i)]);
		pString[19 + 4] = '-';
		sprintf(pString, "%08x-%04x-%04x-%s", pId->Data1, pId->Data2, pId->Data3, pString + 19);
	}

	VOID EUuidDecodeA(       // String to UUID
		_In_  PCSTR pString, // String to Decode
		_Out_ UUID* pId      // UUID to fill
	) {
		auto IHexToBinLA = []( // Char to Hexvalue
			_In_ char c		   // Char to convert
		) -> byte {
			if (c >= '0' && c <= '9')
				return c - '0';
			if (c >= 'a' && c <= 'f')
				return c - 'a' + 10;
		};

		const char nPart[] = { 4, 2, 2 };
		for (char i = 0; i < sizeof(nPart); i++) {
			uint nC = nPart[i];
			while (nC--)
				((byte*)pId)[nC] = (IHexToBinLA(*pString++) << 4) + IHexToBinLA(*pString++);
			*(ptr*)&pId += nPart[i];
			pString++;
		} while (pString[0] && pString[1]) {
			if (pString[0] == '-')
				pString++;
			*(*(byte**)&pId)++ = (IHexToBinLA(*pString++) << 4) + IHexToBinLA(*pString++);
		}
	}
#pragma endregion
}

namespace utl {
#pragma region SigScan
	SigScan::SigScan(
		_In_ const void*  pData,
		_In_       size_t nData,
		_In_ const void*  pSig,
		_In_ const char*  szMask
	) : m_pData(pData), m_nData(nData), m_pSig(pSig),
		m_nSig(strlen(szMask))
	{
		// Allocate and calculate Mask
		size_t nMask = ((m_nSig + (8 - 1)) & -8) / 8;
		m_pMask = (byte*)malloc(nMask);
		memset(m_pMask, 0, nMask);
		for (size_t i = 0; i < m_nSig; i++)
			if (szMask[i] != '?')
				m_pMask[i / 8] |= true << (i % 8);
	}
	SigScan::~SigScan() {
		free(m_pMask);
	}

	void* SigScan::FindSig() {
		while (m_nData - m_nSig) {
			size_t i;
			for (i = 0; i < m_nSig; i++)
				if (((m_pMask[m_nSig / 8] >> (i % 8)) & 1) && ((byte*)m_pData)[i] != ((byte*)m_pSig)[i])
					break;

			if (i >= m_nSig)
				return (void*)((*(ptr*)&m_pData) - 1);
			(*(ptr*)&m_pData)++, m_nData--;
		}

		return nullptr;
	}
#pragma endregion
}
