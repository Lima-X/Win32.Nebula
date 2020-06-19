#include "pch.h"
#include "_rift.h"

// Internal State / Sync Opbject
STATIC PDWORD l_dwa4;
STATIC CRITICAL_SECTION l_cs;

FORCEINLINE DWORD IRotlDw(
	_In_ DWORD dwT,
	_In_ UINT8 ui8T
) {
	return (dwT << ui8T) | (dwT >> ((sizeof(DWORD) * 8) - ui8T));
}
FORCEINLINE VOID IXoshiroNext() {
	EnterCriticalSection(&l_cs);

	CONST DWORD dwT = l_dwa4[1] << 9;
	l_dwa4[2] ^= l_dwa4[0];
	l_dwa4[3] ^= l_dwa4[1];
	l_dwa4[1] ^= l_dwa4[2];
	l_dwa4[0] ^= l_dwa4[3];
	l_dwa4[2] ^= dwT;
	l_dwa4[3] = IRotlDw(l_dwa4[3], 11);

	LeaveCriticalSection(&l_cs);
}

DWORD EXoshiroSS() {
	CONST DWORD dwT = IRotlDw(l_dwa4[1] * 5, 7) * 9;
	IXoshiroNext();
	return dwT;
}
DWORD EXoshiroP() {
	CONST DWORD dwT = l_dwa4[0] + l_dwa4[3];
	IXoshiroNext();
	return dwT;
}

UINT ERandomIntDistribution(
	_In_ UINT uiMin,
	_In_ UINT uiMax
) {
	UINT uiRet;
	CONST UINT uiRange = (uiMax - uiMin) + 1;
	CONST UINT uiScale = (UINT)-1 / uiRange;
	CONST UINT uiLimit = uiRange * uiScale;

	do {
		uiRet = EXoshiroSS();
	} while (uiRet >= uiLimit);

	uiRet /= uiScale;
	return uiRet + uiMin;
}
FLOAT ERandomRealDistribution() {
	// 24 bits resolution: (r >> 8) * 2^(-24)
	return (EXoshiroP() >> 8) * (1.F / 0x1000000p0F);
}

BOOL EXoshiroBegin() {
	BCRYPT_ALG_HANDLE cah;
	if (!BCryptOpenAlgorithmProvider(&cah, BCRYPT_RNG_ALGORITHM, 0, 0)) {
		InitializeCriticalSection(&l_cs);
		l_dwa4 = AllocMemory(sizeof(DWORD) * 4);
		BCryptGenRandom(cah, l_dwa4, sizeof(DWORD) * 4, 0);
		BCryptCloseAlgorithmProvider(cah, 0);

		return TRUE;
	} else
		return FALSE;
}
VOID EXoshiroEnd() {
	FreeMemory(l_dwa4);
	DeleteCriticalSection(&l_cs);
}


/* Random Tools */
extern CONST CHAR e_Base64Table[64];
VOID fnGenRandomB64W(
	_Out_ PVOID  sz,
	_In_  SIZE_T n
) {
	for (SIZE_T i = 0; i < n; i++)
		((PWCHAR)sz)[i] = (WCHAR)e_Base64Table[ERandomIntDistribution(0, 63)];
}
VOID fnGenRandomPathW(
	_Out_ PVOID  sz,
	_In_  SIZE_T n
) {
	fnGenRandomB64W(sz, n);
	for (SIZE_T i = 0; i < n; i++)
		if (((PWCHAR)sz)[i] == L'/')
			((PWCHAR)sz)[i] = L'_';
}

__inline PVOID fnAllocRandom(
	_In_     SIZE_T  nMin,
	_In_opt_ SIZE_T  nMax,
	_Out_    PSIZE_T n
) {
	if (!nMin)
		return 0;

	if (nMax && (nMax != nMin))
		*n = ERandomIntDistribution(nMin, nMax);
	else
		*n = nMin;

	return AllocMemory((*n + 1) * sizeof(WCHAR));
}
PCWSTR EAllocRandomBase64StringW(
	_In_     SIZE_T nMin,
	_In_opt_ SIZE_T nMax
) {
	SIZE_T n;
	PVOID pBuffer = fnAllocRandom(nMin, nMax, &n);
	fnGenRandomB64W(pBuffer, n);
	((PWCHAR)pBuffer)[n] = L'\0';
	return pBuffer;
}
PCWSTR EAllocRandomPathW(
	_In_     SIZE_T  nMin,
	_In_opt_ SIZE_T  nMax
) {
	SIZE_T n;
	PVOID pBuffer = fnAllocRandom(nMin, nMax, &n);
	fnGenRandomPathW(pBuffer, n);
	((PWCHAR)pBuffer)[n + 1] = L'\0';
	return pBuffer;
}

VOID fnGenRandom(
	_In_ PVOID  pBuffer,
	_In_ SIZE_T nBuffer
) {
	for (UINT i = 0; i < (nBuffer / 4); i++) {
		((PDWORD)pBuffer)[i] = EXoshiroSS();
	} for (UINT i = (nBuffer / 4) * 4; i < nBuffer; i++) {
		((PBYTE)pBuffer)[i] = EXoshiroP() >> (3 * 8);
	}
}