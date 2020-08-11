#include "_riftldr.h"

namespace rng {
	CRITICAL_SECTION Xoshiro::cs;
	rng::Xoshiro* Xoshiro::xsrInstance;

	// Constructor/Destructor and Signleton Initialization
	Xoshiro::Xoshiro(
		_In_opt_ dword* dwState // = nullptr
	) {
		BCRYPT_ALG_HANDLE cah;
		if (!BCryptOpenAlgorithmProvider(&cah, BCRYPT_RNG_ALGORITHM, nullptr, NULL)) {
			if (!xsrInstance)
				InitializeCriticalSection(&cs);

			if (!dwState)
				BCryptGenRandom(cah, (UCHAR*)&m_dwState, sizeof(dword) * 4, NULL);
			else
				memcpy(m_dwState, dwState, 16);
			BCryptCloseAlgorithmProvider(cah, NULL);
		}
	}
	Xoshiro::~Xoshiro() {
		if (this == xsrInstance) {
			DeleteCriticalSection(&cs);
			xsrInstance = nullptr;
		}
	}
	Xoshiro* Xoshiro::Instance(
		_In_opt_ bool bDelete // = false
	) {
		if (!bDelete) {
			if (!xsrInstance)
				xsrInstance = new Xoshiro();
		} else
			if (xsrInstance) {
				delete xsrInstance;
				xsrInstance = nullptr;
			}
		return xsrInstance;
	}

	// Xoshiro Functions
	dword Xoshiro::EXoshiroSS() {
		const dword dwT = IRotlDw(m_dwState[1] * 5, 7) * 9;
		IXoshiroNext();
		return dwT;
	}
	dword Xoshiro::EXoshiroP() {
		const dword dwT = m_dwState[0] + m_dwState[3];
		IXoshiroNext();
		return dwT;
	}
	// Uniform int/FLOAT Distribution Functions
	uint Xoshiro::ERandomIntDistribution(
		_In_ uint nMin,
		_In_ uint nMax
	) {
		const uint nRange = (nMax - nMin) + 1;
		const uint nScale = (uint)-1 / nRange;
		const uint nLimit = nRange * nScale;

		uint nRet;
		do {
			nRet = EXoshiroSS();
		} while (nRet >= nLimit);
		nRet /= nScale;
		return nRet + nMin;
	}
	FLOAT Xoshiro::ERandomRealDistribution() {
		// 24 bits resolution: (r >> 8) * 2^(-24)
		return (EXoshiroP() >> 8) * (1.F / 0x1000000p0F);
	}

	// Internal State manipulation Functions
	inline dword Xoshiro::IRotlDw(
		_In_ dword dwT,
		_In_ uchar ui8T
	) const {
		return (dwT << ui8T) | (dwT >> ((sizeof(dword) * 8) - ui8T));
	}
	inline VOID Xoshiro::IXoshiroNext() {
		bool bFlag = this == xsrInstance ? 1 : 0;
		if (bFlag)
			EnterCriticalSection(&cs);

		const dword dwT = m_dwState[1] << 9;
		m_dwState[2] ^= m_dwState[0];
		m_dwState[3] ^= m_dwState[1];
		m_dwState[1] ^= m_dwState[2];
		m_dwState[0] ^= m_dwState[3];
		m_dwState[2] ^= dwT;
		m_dwState[3] = IRotlDw(m_dwState[3], 11);

		if (bFlag)
			LeaveCriticalSection(&cs);
	}

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
			xsr = rng::Xoshiro::Instance();
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
			*n = rng::Xoshiro::Instance()->ERandomIntDistribution(nMin, nMax);
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
		rng::Xoshiro* xsr = rng::Xoshiro::Instance();
		for (uint i = 0; i < (nBuffer / 4); i++) {
			((PDWORD)pBuffer)[i] = xsr->EXoshiroSS();
		} for (uint i = (nBuffer / 4) * 4; i < nBuffer; i++) {
			((byte*)pBuffer)[i] = xsr->EXoshiroP() >> (3 * 8);
		}
	}
}