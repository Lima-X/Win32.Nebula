#include "_riftldr.h"

namespace rng {
#pragma region Xoshiro
	CRITICAL_SECTION Xoshiro::cs;
	rng::Xoshiro* Xoshiro::s_xsrInstance = nullptr;

	// Constructor/Destructor and Signleton Initialization
	Xoshiro::Xoshiro(
		_In_opt_ dword* dwState // = nullptr
	)
		: m_Trampoline(&Xoshiro::INext)
	{
		if (!dwState) {
			BCRYPT_ALG_HANDLE cah;
			if (!BCryptOpenAlgorithmProvider(&cah, BCRYPT_RNG_ALGORITHM, nullptr, NULL)) {
				BCryptGenRandom(cah, (UCHAR*)&m_dwState, sizeof(dword) * 4, NULL);
				BCryptCloseAlgorithmProvider(cah, NULL);
			}
		} else
			memcpy(m_dwState, dwState, 16);
	}
	Xoshiro::~Xoshiro() {
		// this is only semi safe but should do
		if (this == s_xsrInstance)
			EnterCriticalSection(&cs);
		free(m_dwState);
		if (this == s_xsrInstance) {
			s_xsrInstance = nullptr;
			LeaveCriticalSection(&cs);
			DeleteCriticalSection(&cs);
		}
	}
	Xoshiro* Xoshiro::Instance() {
		if (!s_xsrInstance) {
			s_xsrInstance = new Xoshiro();
			s_xsrInstance->m_Trampoline = &Xoshiro::INext2;
			InitializeCriticalSection(&cs);
		}
		return s_xsrInstance;
	}

	// Internal State manipulation Functions
	dword __forceinline Xoshiro::IRotlDw(
		_In_ dword dw,
		_In_ uint8 sh
	) const {
		return (dw << sh) | (dw >> ((sizeof(dword) * 8) - sh));
	}
	inline void Xoshiro::INext() {
		const dword dwT = m_dwState[1] << 9;
		m_dwState[2] ^= m_dwState[0];
		m_dwState[3] ^= m_dwState[1];
		m_dwState[1] ^= m_dwState[2];
		m_dwState[0] ^= m_dwState[3];
		m_dwState[2] ^= dwT;
		m_dwState[3] = IRotlDw(m_dwState[3], 11);
	}
	inline void Xoshiro::INext2() { // Thread safe call to NextState function
		EnterCriticalSection(&cs);
		INext();
		LeaveCriticalSection(&cs);
	}

	// Xoshiro Functions
	dword Xoshiro::EXoshiroSS() {
		const dword dwT = IRotlDw(m_dwState[1] * 5, 7) * 9;
		(this->*m_Trampoline)();
		return dwT;
	}
	dword Xoshiro::EXoshiroP() {
		const dword dwT = m_dwState[0] + m_dwState[3];
		(this->*m_Trampoline)();
		return dwT;
	}

	// Uniform int/float Distribution Functions
	uint32 Xoshiro::ERandomIntDistribution(
		_In_ uint32 nMin,
		_In_ uint32 nMax
	) {
		const uint32 nRange = (nMax - nMin) + 1;
		const uint32 nScale = (uint32)-1 / nRange;
		const uint32 nLimit = nRange * nScale;

		uint32 nRet;
		do {
			nRet = EXoshiroSS();
		} while (nRet >= nLimit);
		nRet /= nScale;
		return nRet + nMin;
	}
	float Xoshiro::ERandomRealDistribution() {
		// 24 bits resolution: (r >> 8) * 2^(-24)
		return (EXoshiroP() >> 8) * (1.F / 0x1000000p0F);
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
		for (uint32 i = 0; i < (nBuffer / 4); i++) {
			((PDWORD)pBuffer)[i] = xsr->EXoshiroSS();
		} for (uint32 i = (nBuffer / 4) * 4; i < nBuffer; i++) {
			((byte*)pBuffer)[i] = xsr->EXoshiroP() >> (3 * 8);
		}
	}
}