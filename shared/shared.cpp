#ifdef _riftldr
#include "..\_riftldr\_riftldr.h"
#elif _riftTool
#include "..\_riftTool\_riftTool.h"
#endif

namespace utl {
	/* Base64 Encoder/Decoder taken from FreeBSD Project.
	   Ported over to C++ into a singleton class */
	class Base64 {
	public:
		static Base64* Instance() {
			if (!b64Instance)
				b64Instance = new Base64;
			return b64Instance;
		}

		status EBase64EncodeA(      // returns length of string(not including Null) or space needed for string
			_In_      void*  pData, // Data to be encoded
			_In_      size_t nData, // Size of Data
			_Out_opt_ PSTR   psz,   // Output Buffer to fill / if nul Calculates the neccessary size
			_In_      bool   bPad   // Enables Padding
		) {
			if (nData >= (((uint)-1) / 2) / 4)
				return -1; // Too much Data
			if (!psz) { // Calculate Neccessary Space if Output is NULL
				// Raw Space Needed
				size_t nOLen = nData / 3 * 4;
				if (nData % 3)
					nOLen += 4;
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
				*pPos++ = bTable[(((byte*)pData)[0] >> 2) & 0x3f];
				*pPos++ = bTable[(((((byte*)pData)[0] & 0x03) << 4) | (((byte*)pData)[1] >> 4)) & 0x3f];
				*pPos++ = bTable[(((((byte*)pData)[1] & 0x0f) << 2) | (((byte*)pData)[2] >> 6)) & 0x3f];
				*pPos++ = bTable[((byte*)pData)[2] & 0x3f];

				(*(byte**)&pData) += 3, nPLen += 4;
				if (bPad && nPLen >= 72) // Add Newline after 72-Chars
					*pPos++ = '\n', nPLen = 0;
			} if (pEnd - (ptr)pData) { // Encode last Block (with Padding) if neccessary
				*pPos++ = bTable[(((byte*)pData)[0] >> 2) & 0x3f];
				if (pEnd - (ptr)pData == 1) {
					*pPos++ = bTable[((((byte*)pData)[0] & 0x03) << 4) & 0x3f];
					if (bPad)
						*pPos++ = '=';
				}
				else {
					*pPos++ = bTable[(((((byte*)pData)[0] & 0x03) << 4) | (((byte*)pData)[1] >> 4)) & 0x3f];
					*pPos++ = bTable[((((byte*)pData)[1] & 0x0f) << 2) & 0x3f];
				} if (bPad)
					*pPos++ = '=';
				nPLen += 4;
			} if (bPad && !nPLen) // Remove last Newline if on 72-Char Boundary
				pPos--;

			*pPos = '\0';
			return (status)(pPos - (ptr)psz); // Return actuall Size (not including Nullterminator)
		}
		status EBase64DecodeA(     // Decodes a Base64 String / returns Size of Data
			_In_      PCSTR  psz,  // Base64 String to decode
			_In_      size_t nsz,  // Length of String
			_Out_opt_ void*  pData // Output Buffer to fill with raw Data / if nul calculates the neccessary size
		) {
			// Setup Internal Table & get unpadded Length
			char* cTable = (char*)malloc(256);
			memset(cTable, 0x80, 256);
			for (char i = 0; i < 64; i++)
				cTable[bTable[i]] = (char)i;
			cTable['='] = '\0';
			size_t nC = 0;
			for (uint i = 0; i < nsz; i++)
				if (cTable[((uchar*)psz)[i]] != 0x80)
					nC++;
			if (!nC)
				return -1; // Invalid Size

			// Calculate Padding (optional: return size of space needed)
			uint nEPad = (4 - nC % 4) % 4;
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
	private:
		static Base64* b64Instance;
		char* bTable;

		Base64() {
			const char ofs[] = { '#', '(',  ']', 'a' }; // offsets to startingpoints in ascii128 table
			const char ofl[] = { 4,   25 + 1, 3,   30 }; // run length of offsets
			const word ext[] = { '!' << 8 | 0, '[' << 8 | 29 }; // single extra chars with offsets (format: char-offset)

			bTable = (char*)malloc(64);
			for (char i = 0, n = 1; i < sizeof(ofs); n += ofl[i], i++)
				for (char j = 0; j < ofl[i]; j++)
					bTable[n + j] = ofs[i] + j;
			for (char i = 0; i < sizeof(ext) / sizeof(*ext); i++)
				bTable[ext[i] & 0xff] = ext[i] >> 8;
		}
		~Base64() {
			free(bTable);
			bTable = nullptr;
		}
	};


	/* UUID Converters */
	// TODO: maybe rewrite this, its nightmareful
	DEPRECATED VOID EUuidEncodeA(      // UUID to String
		_In_  UUID* pId,    // UUID to Encode
		_Out_ PSTR  pString // String to fill
	) {
		for (char i = 0; i < 2; i++)
			for (char j = 0; j < 2 + (4 * i); j++)
				StringCchPrintfA((pString + j * 2) + (19 + 5 * i), 2 + 1, "%02x", pId->Data4[j + (2 * i)]);
		pString[19 + 4] = '-';
		StringCchPrintfA(pString, UUID_STRLEN, "%08x-%04x-%04x-%s", pId->Data1, pId->Data2, pId->Data3, pString + 19);
	}

	FORCEINLINE uchar ICharToHex( // Char to Hexvalue
		_In_ char c               // Char to convert
	) {
		if (c >= '0' && c <= '9')
			return c - '0';
		if (c >= 'a' && c <= 'f')
			return c - 'a' + 10;
	}
	VOID EUuidDecodeA(       // String to UUID
		_In_  PCSTR pString, // String to Decode
		_Out_ UUID* pId      // UUID to fill
	) {
		const char nPart[] = { 4, 2, 2 };
		for (char i = 0; i < sizeof(nPart); i++) {
			uint nC = nPart[i];
			while (nC--)
				((byte*)pId)[nC] = (ICharToHex(*pString++) << 4) + ICharToHex(*pString++);
			*(ptr*)&pId += nPart[i];
			pString++;
		} while (pString[0] && pString[1]) {
			if (pString[0] == '-')
				pString++;
			*(*(byte**)&pId)++ = (ICharToHex(*pString++) << 4) + ICharToHex(*pString++);
		}
	}

#if 0
	// Wrappers for rpcApi UUID's (unneccessary)
	status EUidToStringW(     // UUID to String
		_In_  UUID* pId,     // UUID to Encode
		_Out_ PWSTR  pString, // String to fill
		_In_  size_t nString  // Size of String
	) {
		RPC_WSTR rpcString;
		status s = UuidToStringW(pId, &rpcString);
		s |= StringCchCopyW(pString, nString, rpcString);
		s |= RpcStringFreeW(&rpcString);
		return s;
	}
	status EUidFromStringW(   // String to UUID
		_In_  PCWSTR pString, // String to Decode
		_Out_ UUID* pId      // UUID to fill
	) {
		return UuidFromStringW(pString, pId);
	}
#endif

	void* ESigScan(        // Signatrure Scanner/Finder
		_In_ void* pData, // Address of Data
		_In_ size_t nData, // Size of Data
		_In_ SIG* sig    // Signature Info
	) {
		do {
			size_t nSig = sig->nLength;
			while (nSig--)
				if ((sig->szMask[nSig] == 'x') && (((byte*)pData)[nSig] != ((byte*)sig->pSig)[nSig]))
					break;
			if (nSig == -1)
				return pData;
			(*(ptr*)&pData)++;
		} while (nData-- - sig->nLength);
		return NULL;
	}
}