#include "_rift.h"

// Internal/Global State & Sync Opbject
STATIC PDWORD l_dwState;
STATIC CRITICAL_SECTION l_cs;

// Internal State manipulation Functions
FORCEINLINE STATIC DWORD IRotlDw(
	_In_ DWORD dwT,
	_In_ UINT8 ui8T
) {
	return (dwT << ui8T) | (dwT >> ((sizeof(DWORD) * 8) - ui8T));
}
FORCEINLINE STATIC VOID IXoshiroNext(
	_In_ PDWORD  dwState,
	_In_ BOOLEAN bFlag
) {
	if (!bFlag)
		EnterCriticalSection(&l_cs);

	CONST DWORD dwT = dwState[1] << 9;
	dwState[2] ^= dwState[0];
	dwState[3] ^= dwState[1];
	dwState[1] ^= dwState[2];
	dwState[0] ^= dwState[3];
	dwState[2] ^= dwT;
	dwState[3] = IRotlDw(dwState[3], 11);

	if (!bFlag)
		LeaveCriticalSection(&l_cs);
}

// Xoshiro Functions
DWORD EXoshiroSS(
	_In_opt_ PDWORD dwState
) {
	BOOLEAN bFlag = FALSE;
	if (!dwState) {
		dwState = l_dwState;
		bFlag = TRUE;
	}
	CONST DWORD dwT = IRotlDw(dwState[1] * 5, 7) * 9;
	IXoshiroNext(dwState, bFlag);
	return dwT;
}
DWORD EXoshiroP(
	_In_opt_ PDWORD dwState
) {
	BOOLEAN bFlag = FALSE;
	if (!dwState) {
		dwState = l_dwState;
		bFlag = TRUE;
	}
	CONST DWORD dwT = dwState[0] + dwState[3];
	IXoshiroNext(dwState, bFlag);
	return dwT;
}

// Uniform INT/FLOAT Distribution Functions
UINT FASTCALL ERandomIntDistribution(
	_In_opt_ PDWORD dwState,
	_In_     UINT   uiMin,
	_In_     UINT   uiMax
) {
	UINT uiRet;
	CONST UINT uiRange = (uiMax - uiMin) + 1;
	CONST UINT uiScale = (UINT)-1 / uiRange;
	CONST UINT uiLimit = uiRange * uiScale;

	do {
		uiRet = EXoshiroSS(dwState);
	} while (uiRet >= uiLimit);

	uiRet /= uiScale;
	return uiRet + uiMin;
}
FLOAT ERandomRealDistribution(
	_In_opt_ PDWORD dwState
) {
	// 24 bits resolution: (r >> 8) * 2^(-24)
	return (EXoshiroP(dwState) >> 8) * (1.F / 0x1000000p0F);
}

// Xoshiro De/Constructor
BOOL EXoshiroBegin(
	_In_opt_ PDWORD dwState
) {
	BCRYPT_ALG_HANDLE cah;
	if (!BCryptOpenAlgorithmProvider(&cah, BCRYPT_RNG_ALGORITHM, NULL, NULL)) {
		if (!dwState) {
			InitializeCriticalSection(&l_cs);
			l_dwState = AllocMemory(sizeof(DWORD) * 4);
			dwState = l_dwState;
		}

		BCryptGenRandom(cah, dwState, sizeof(DWORD) * 4, NULL);
		BCryptCloseAlgorithmProvider(cah, NULL);
		return TRUE;
	} else
		return FALSE;
}
VOID EXoshiroEnd(
	_In_opt_ PDWORD dwState
) {
	if (!dwState) {
		DeleteCriticalSection(&l_cs);
		dwState = l_dwState;
	}
	FreeMemory(dwState);
}

// Random Tools
EXTERN_C CONST CHAR e_Base64Table[64];
VOID EGenRandomB64W(
	_In_opt_ PDWORD dwState,
	_Out_    PVOID  sz,
	_In_     SIZE_T n
) {
	for (SIZE_T i = 0; i < n; i++)
		((PWCHAR)sz)[i] = (WCHAR)e_Base64Table[ERandomIntDistribution(dwState, 0, 63)];
}
VOID EGenRandomPathW(
	_In_opt_ PDWORD dwState,
	_Out_    PVOID  sz,
	_In_     SIZE_T n
) {
	EGenRandomB64W(dwState, sz, n);
	for (SIZE_T i = 0; i < n; i++)
		if (((PWCHAR)sz)[i] == L'/')
			((PWCHAR)sz)[i] = L'_';
}

INLINE PVOID IAllocRandom(
	_In_     SIZE_T  nMin,
	_In_opt_ SIZE_T  nMax,
	_Out_    PSIZE_T n
) {
	if (!nMin)
		return 0;

	if (nMax && (nMax <= nMin))
		*n = ERandomIntDistribution(NULL, nMin, nMax);
	else
		*n = nMin;

	return AllocMemory((*n + 1) * sizeof(WCHAR));
}
DEPRECATED PCWSTR EAllocRandomBase64StringW(
	_In_opt_ PDWORD dwState,
	_In_     SIZE_T nMin,
	_In_opt_ SIZE_T nMax
) {
	SIZE_T n;
	PVOID pBuffer = IAllocRandom(nMin, nMax, &n);
	EGenRandomB64W(dwState, pBuffer, n);
	((PWCHAR)pBuffer)[n] = L'\0';
	return pBuffer;
}
DEPRECATED PCWSTR EAllocRandomPathW(
	_In_opt_ PDWORD dwState,
	_In_     SIZE_T  nMin,
	_In_opt_ SIZE_T  nMax
) {
	SIZE_T n;
	PVOID pBuffer = IAllocRandom(nMin, nMax, &n);
	EGenRandomPathW(dwState, pBuffer, n);
	((PWCHAR)pBuffer)[n + 1] = L'\0';
	return pBuffer;
}

VOID EGenRandom(
	_In_opt_ PDWORD dwState,
	_Out_    PVOID  pBuffer,
	_In_     SIZE_T nBuffer
) {
	for (UINT i = 0; i < (nBuffer / 4); i++) {
		((PDWORD)pBuffer)[i] = EXoshiroSS(dwState);
	} for (UINT i = (nBuffer / 4) * 4; i < nBuffer; i++) {
		((PBYTE)pBuffer)[i] = EXoshiroP(dwState) >> (3 * 8);
	}
}