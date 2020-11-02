#include "shared.h"
#include <malloc.h>
#include <cstdio>

namespace ALG {
#pragma region Base64
	/* Base64A Encoder/Decoder taken from FreeBSD Project.
	   Migrated to C++ into a class */
	Base64A::Base64A(
		_In_opt_ void(*TableConstructorCbA)(_In_ void* pTable)
	) {
		pcTable = (char*)malloc(64);
		if (!TableConstructorCbA) {
			// This constructs the standard Base64A Table
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
	Base64A::~Base64A() {
		free(pcTable);
		pcTable = nullptr;
	}
	status Base64A::EBase64Encode( // returns length of string(not including Null) or space needed for string
		_In_      void*  pData,    // Data to be encoded
		_In_      size_t nData,    // Size of Data
		_Out_opt_ PSTR   psz,      // Output Buffer to fill / if nul Calculates the neccessary size
		_In_      bool   bPad      // Enables Padding
	) {
		if (nData >= (((uint32)-1) / 2) / 4)
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
			}
			else {
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
	status Base64A::EBase64Decode( // Decodes a Base64A String / returns Size of Data
		_In_      PCSTR  psz,      // Base64A String to decode
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
		for (uint32 i = 0; i < nsz; i++)
			if (cTable[((uchar*)psz)[i]] != 0x80)
				nC++;
		if (!nC)
			return -1; // Invalid Size

		// Calculate Padding (optional: return size of space needed)
		const uint32 nEPad = (4 - nC % 4) % 4;
		if (!pData)
			return (nC + nEPad) / 4 * 3; // return required space
		nC = 0;

		uint32  nPad = 0;
		byte  bBlock[4];
		byte* pPos = (byte*)pData;
		for (uint32 i = 0; i < nsz + nEPad; i++) {
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
#pragma endregion Out of Service

#pragma region Hex
	char HexConvA::s_HexTable[('a' - '0') - 1];

	HexConvA::HexConvA() {
		// Setup HexTable
		for (uint8 i = 0; i < 10; i++)
			s_HexTable[i] = i + '0';

		for (uint8 j = 0; j < 6; j++) {
			s_HexTable[j + 10] = j + 'a';
			s_HexTable[j + ('a' - '0')] = j + ('0' + 10);
		}
	}
	void HexConvA::BinToHex( //
		_In_  void*  pData,  // Data to be converted
		_In_  size_t nData,  // Size of Data
		_Out_ char*  sz      // Target String to Fill
	) {
		for (int i = 0; i < nData; i++) {
			sz[i * 2] = s_HexTable[((byte*)pData)[i] >> 4];
			sz[(i * 2) + 1] = s_HexTable[((byte*)pData)[i] & 0xf];
		}
		sz[nData * 2] = '\0';
	}

	void HexConvA::HexToBin( //
		_In_  char* sz,      // String to be converted
		_Out_ void* pOut     // Target array to fill
	) {
		while (*sz != '\0')
			 *(*(byte**)&pOut)++ = ((s_HexTable[*sz++ - '0'] - '0') << 4) + (s_HexTable[*sz++ - '0'] - '0');
	}
#pragma endregion

#pragma region Uuid
	/* UUID Converters */
	// TODO: maybe rewrite this, its nightmarefuel
	DEPRECATED void EUuidEncodeA(      // UUID to sString
		_In_  uuid* pId,    // UUID to Encode
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
		_Out_ uuid* pId      // UUID to fill
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
			uint32 nC = nPart[i];
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

namespace rng {
#pragma region CRNG (Crypto Random Number Generator)
	           BCRYPT_ALG_HANDLE CRNG::s_ah;
	alignas(2) uint16            CRNG::s_nRefCount = 0;

	CRNG::CRNG() {
		if (!(_InterlockedIncrement16((short*)&s_nRefCount) - 1))
			BCryptOpenAlgorithmProvider(&s_ah, BCRYPT_RNG_ALGORITHM, nullptr, NULL);
	}
	CRNG::~CRNG() {
		if (!_InterlockedDecrement16((short*)&s_nRefCount))
			BCryptCloseAlgorithmProvider(s_ah, NULL);
	}

	status CRNG::FillRandom(
		_In_ void*  pBuf,
		_In_ size_t nBuf
	) {
		return -!!BCryptGenRandom(s_ah, (byte*)pBuf, nBuf, NULL);
	}
#pragma endregion

#pragma region Xoshiro
	CRITICAL_SECTION Xoshiro::cs;

	// Constructor/Destructor and Signleton Initialization
	Xoshiro::Xoshiro(
		_In_opt_ void(Xoshiro::* const tl)(), //
		_In_opt_ void* dwState                // default: nullptr
	)
		: m_Trampoline(tl)
	{
		if (!dwState) {
			CRNG::FillRandom(m_dwState, nState);
		} else
			memcpy(m_dwState, dwState, nState);

		if (tl == &Xoshiro::GNext)
			InitializeCriticalSection(&cs);
	}
	Xoshiro::Xoshiro(
		_In_opt_ void* dwState // default: nullptr
	) : Xoshiro(&Xoshiro::Next, dwState) {}
	Xoshiro::~Xoshiro() {
		if (this == &Instance())
			DeleteCriticalSection(&cs);
	}
	Xoshiro& Xoshiro::Instance() {
		static Xoshiro xsr(&GNext);
		return xsr;
	}

	status Xoshiro::Reseed() {
		return CRNG::FillRandom(m_dwState, nState);
	}

	// Internal State manipulation Functions
	dword __forceinline Xoshiro::rol32l(
		_In_ dword dw,
		_In_ uint8 sh
	) const {
		return (dw << sh) | (dw >> ((sizeof(dword) * 8) - sh));
	}
	inline void Xoshiro::Next() {
		const dword dw = m_dwState[1] << 9;
		m_dwState[2] ^= m_dwState[0];
		m_dwState[3] ^= m_dwState[1];
		m_dwState[1] ^= m_dwState[2];
		m_dwState[0] ^= m_dwState[3];
		m_dwState[2] ^= dw;
		m_dwState[3] = rol32l(m_dwState[3], 11);
	}
	inline void Xoshiro::GNext() { // Thread safe call to NextState function
		EnterCriticalSection(&cs);
		Next();
		LeaveCriticalSection(&cs);
	}

	// Xoshiro Functions
	dword Xoshiro::XoshiroSS() {
		const dword dw = rol32l(m_dwState[1] * 5, 7) * 9;
		(this->*m_Trampoline)();
		return dw;
	}
	dword Xoshiro::XoshiroP() {
		const dword dw = m_dwState[0] + m_dwState[3];
		(this->*m_Trampoline)();
		return dw;
	}

	// Uniform int/float Distribution Functions
	uint32 Xoshiro::RandomIntDistribution(
		_In_ uint32 nMin,
		_In_ uint32 nMax
	) {
		const uint32 nRange = (nMax - nMin) + 1;
		const uint32 nScale = (uint32)-1 / nRange;
		const uint32 nLimit = nRange * nScale;

		uint32 nRet;
		do {
			nRet = XoshiroSS();
		} while (nRet >= nLimit);
		nRet /= nScale;
		return nRet + nMin;
	}
	float Xoshiro::RandomRealDistribution() {
		// 24 bits resolution: (r >> 8) * 2^(-24)
		return (XoshiroP() >> 8) * (1.F / 0x1000000p0F);
	}
#pragma endregion

	// TODO: Rewrite all this bullshit, as it is needed

	// Random Tools / TODO: fix this mess
	VOID EGenRandomB64W(
		_In_opt_ PDWORD dwState,
		_Out_    void* sz,
		_In_     size_t n
	) {
		rng::Xoshiro* xsr;
		if (dwState)
			xsr = new rng::Xoshiro(dwState);
		else
			xsr = &rng::Xoshiro::Instance();
		for (size_t i = 0; i < n; i++)
			;//	((PWCHAR)sz)[i] = (WCHAR)e_Base64Table[xsr->ERandomIntDistribution(0, 63)];
	}
	VOID EGenRandomPathW(
		_In_opt_ PDWORD dwState,
		_Out_    void* sz,
		_In_     size_t n
	) {
		EGenRandomB64W(dwState, sz, n);
		for (size_t i = 0; i < n; i++)
			if (((PWCHAR)sz)[i] == L'/')
				((PWCHAR)sz)[i] = L'_';
	}

	inline void* IAllocRandom(
		_In_     size_t  nMin,
		_In_opt_ size_t  nMax,
		_Out_    size_t* n
	) {
		if (!nMin)
			return 0;

		if (nMax && (nMax <= nMin))
			*n = rng::Xoshiro::Instance().RandomIntDistribution(nMin, nMax);
		else
			*n = nMin;

		return malloc((*n + 1) * sizeof(WCHAR));
	}
	DEPRECATED PCWSTR EAllocRandomBase64StringW(
		_In_opt_ PDWORD dwState,
		_In_     size_t nMin,
		_In_opt_ size_t nMax
	) {
		size_t n;
		void* pBuffer = IAllocRandom(nMin, nMax, &n);
		EGenRandomB64W(dwState, pBuffer, n);
		((PWCHAR)pBuffer)[n] = L'\0';
		return (PCWSTR)pBuffer;
	}
	DEPRECATED PCWSTR EAllocRandomPathW(
		_In_opt_ PDWORD dwState,
		_In_     size_t  nMin,
		_In_opt_ size_t  nMax
	) {
		size_t n;
		void* pBuffer = IAllocRandom(nMin, nMax, &n);
		EGenRandomPathW(dwState, pBuffer, n);
		((PWCHAR)pBuffer)[n + 1] = L'\0';
		return (PCWSTR)pBuffer;
	}

	VOID EGenRandom(
		_In_opt_ PDWORD dwState,
		_Out_    void* pBuffer,
		_In_     size_t nBuffer
	) {
		rng::Xoshiro* xsr = &rng::Xoshiro::Instance();
		for (uint32 i = 0; i < (nBuffer / 4); i++) {
			((PDWORD)pBuffer)[i] = xsr->XoshiroSS();
		} for (uint32 i = (nBuffer / 4) * 4; i < nBuffer; i++) {
			((byte*)pBuffer)[i] = xsr->XoshiroP() >> (3 * 8);
		}
	}
}

namespace utl {
#pragma region Signature Scaner
	SigScan::SigScan(
		_In_ const void*  pData,
		_In_       size_t nData,
		_In_ const void*  pSig,
		_In_ const char*  szMask
	)
		: m_pData(pData),
		m_nData(nData),
		m_pSig(pSig),
		m_nSig(strlen(szMask))
	{
		// Allocate and calculate Mask
		size_t nMask = RoundUpToMulOfPow2(m_nSig, 8) / 8;
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

	void* ELoadResourceW(
		_In_  word         wResID,
		_In_  const wchar* pResType,
		_Out_ size_t*      nBufferSize
	) {
		HRSRC hResInfo = FindResourceW(NULL, MAKEINTRESOURCEW(wResID), pResType);
		if (hResInfo) {
			HGLOBAL hgData = LoadResource(NULL, hResInfo);
			if (hgData) {
				void* lpBuffer = LockResource(hgData);
				if (!lpBuffer)
					return nullptr;

				if (!(*nBufferSize = SizeofResource(NULL, hResInfo)))
					return nullptr;

				return lpBuffer;
			}
		}

		return nullptr;
	}
}
