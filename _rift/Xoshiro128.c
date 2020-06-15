#include "pch.h"
#include "_rift.h"

// Internal State / Sync Opbject
static PDWORD l_dwa4;
static CRITICAL_SECTION l_cs;

__inline DWORD IRotlDw(
	_In_ DWORD dwT,
	_In_ UINT8 ui8T
) {
	return (dwT << ui8T) | (dwT >> ((sizeof(DWORD) * 8) - ui8T));
}
__inline VOID IXoshiroNext() {
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