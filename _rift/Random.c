#include "pch.h"
#include "_rift.h"

// Internal State / Sync Opbject
STATIC PDWORD l_dwa4;
STATIC CRITICAL_SECTION l_cs;

FORCEINLINE STATIC DWORD IRotlDw(
	_In_ DWORD dwT,
	_In_ UINT8 ui8T
) {
	return (dwT << ui8T) | (dwT >> ((sizeof(DWORD) * 8) - ui8T));
}
FORCEINLINE STATIC VOID IXoshiroNext(
	_In_ PDWORD  dwa4,
	_In_ BOOLEAN bFlag
) {
	if (!bFlag)
		EnterCriticalSection(&l_cs);

	CONST DWORD dwT = dwa4[1] << 9;
	dwa4[2] ^= dwa4[0];
	dwa4[3] ^= dwa4[1];
	dwa4[1] ^= dwa4[2];
	dwa4[0] ^= dwa4[3];
	dwa4[2] ^= dwT;
	dwa4[3] = IRotlDw(dwa4[3], 11);

	if (!bFlag)
		LeaveCriticalSection(&l_cs);
}

DWORD EXoshiroSS(
	_In_opt_ PDWORD dwa4
) {
	BOOLEAN bFlag = FALSE;
	if (!dwa4) {
		dwa4 = l_dwa4;
		bFlag = TRUE;
	}
	CONST DWORD dwT = IRotlDw(dwa4[1] * 5, 7) * 9;
	IXoshiroNext(dwa4, bFlag);
	return dwT;
}
DWORD EXoshiroP(
	_In_opt_ PDWORD dwa4
) {
	BOOLEAN bFlag = FALSE;
	if (!dwa4) {
		dwa4 = l_dwa4;
		bFlag = TRUE;
	}
	CONST DWORD dwT = dwa4[0] + dwa4[3];
	IXoshiroNext(dwa4, bFlag);
	return dwT;
}

UINT FASTCALL ERandomIntDistribution(
	_In_opt_ PDWORD dwa4,
	_In_     UINT   uiMin,
	_In_     UINT   uiMax
) {
	UINT uiRet;
	CONST UINT uiRange = (uiMax - uiMin) + 1;
	CONST UINT uiScale = (UINT)-1 / uiRange;
	CONST UINT uiLimit = uiRange * uiScale;

	do {
		uiRet = EXoshiroSS(dwa4);
	} while (uiRet >= uiLimit);

	uiRet /= uiScale;
	return uiRet + uiMin;
}
FLOAT ERandomRealDistribution(
	_In_opt_ PDWORD dwa4
) {
	// 24 bits resolution: (r >> 8) * 2^(-24)
	return (EXoshiroP(dwa4) >> 8) * (1.F / 0x1000000p0F);
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
VOID EGenRandomB64W(
	_Out_ PVOID  sz,
	_In_  SIZE_T n
) {
	for (SIZE_T i = 0; i < n; i++)
		((PWCHAR)sz)[i] = (WCHAR)e_Base64Table[ERandomIntDistribution(0, 0, 63)];
}
VOID EGenRandomPathW(
	_Out_ PVOID  sz,
	_In_  SIZE_T n
) {
	EGenRandomB64W(sz, n);
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

	if (nMax && (nMax != nMin))
		*n = ERandomIntDistribution(0, nMin, nMax);
	else
		*n = nMin;

	return AllocMemory((*n + 1) * sizeof(WCHAR));
}
PCWSTR EAllocRandomBase64StringW(
	_In_     SIZE_T nMin,
	_In_opt_ SIZE_T nMax
) {
	SIZE_T n;
	PVOID pBuffer = IAllocRandom(nMin, nMax, &n);
	EGenRandomB64W(pBuffer, n);
	((PWCHAR)pBuffer)[n] = L'\0';
	return pBuffer;
}
PCWSTR EAllocRandomPathW(
	_In_     SIZE_T  nMin,
	_In_opt_ SIZE_T  nMax
) {
	SIZE_T n;
	PVOID pBuffer = IAllocRandom(nMin, nMax, &n);
	EGenRandomPathW(pBuffer, n);
	((PWCHAR)pBuffer)[n + 1] = L'\0';
	return pBuffer;
}

VOID EGenRandom(
	_In_opt_ PDWORD dwa4,
	_In_     PVOID  pBuffer,
	_In_     SIZE_T nBuffer
) {
	for (UINT i = 0; i < (nBuffer / 4); i++) {
		((PDWORD)pBuffer)[i] = EXoshiroSS(dwa4);
	} for (UINT i = (nBuffer / 4) * 4; i < nBuffer; i++) {
		((PBYTE)pBuffer)[i] = EXoshiroP(dwa4) >> (3 * 8);
	}
}
VOID EGenReproducable(
	_In_ PVOID  pBuffer,
	_In_ SIZE_T nBuffer
) {
	// Create Hash from Computername
	PWSTR szComName = AllocMemory((MAX_COMPUTERNAME_LENGTH + 1) * sizeof(WCHAR));
	GetComputerNameW(szComName, MAX_COMPUTERNAME_LENGTH + 1);
	SIZE_T nComName;
	StringCchLengthW(szComName, (MAX_COMPUTERNAME_LENGTH + 1) * sizeof(WCHAR), &nComName);
	PVOID pMd5 = EMd5HashData(szComName, nComName * sizeof(WCHAR));
	FreeMemory(szComName);

	EGenRandom(pMd5, pBuffer, nBuffer);
}