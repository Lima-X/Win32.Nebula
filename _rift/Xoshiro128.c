#include "pch.h"
#include "_rift.h"

// Internal State / Sync Opbject
static DWORD l_dwa4S[4];
static CRITICAL_SECTION l_cs;

// Internal
static __inline DWORD fnRotlDW(
	_In_ DWORD dwT,
	_In_ UINT8 ui8T
) {
	return (dwT << ui8T) | (dwT >> ((sizeof(DWORD) * 8) - ui8T));
}
static __inline VOID fnNext128() {
	EnterCriticalSection(&l_cs);

	const DWORD dwT = l_dwa4S[1] << 9;
	l_dwa4S[2] ^= l_dwa4S[0];
	l_dwa4S[3] ^= l_dwa4S[1];
	l_dwa4S[1] ^= l_dwa4S[2];
	l_dwa4S[0] ^= l_dwa4S[3];
	l_dwa4S[2] ^= dwT;
	l_dwa4S[3] = fnRotlDW(l_dwa4S[3], 11);

	LeaveCriticalSection(&l_cs);
}

// Can be used externaly
DWORD fnNext128ss() {
	const DWORD dwT = fnRotlDW(l_dwa4S[1] * 5, 7) * 9;
	fnNext128();
	return dwT;
}
DWORD fnNext128p() {
	const DWORD dwT = l_dwa4S[0] + l_dwa4S[3];
	fnNext128();
	return dwT;
}

// External
UINT fnURID(
	_In_ UINT uiMin,
	_In_ UINT uiMax
) {
	UINT uiRet;
	const UINT uiRange = (uiMax - uiMin) + 1;
	const UINT uiScale = (UINT)-1 / uiRange;
	const UINT uiLimit = uiRange * uiScale;

	do {
		uiRet = fnNext128ss(TRUE);
	} while (uiRet >= uiLimit);

	uiRet /= uiScale;
	return uiRet + uiMin;
}
FLOAT fnURRD() {
	// 24 bits resolution: (r >> 8) * 2^(-24)
	return (fnNext128p() >> 8) * (1.F / 0x1000000p0F);
	// 23 bits resolution: (r >> 9) * 2^(-23)
	// return (fnNext128p() >> 9) * (1.F / 0x800000p0F);
}

// XSR-API Interface
BOOL fnInitializeXSR() {
	BCRYPT_ALG_HANDLE cah;
	if (!BCryptOpenAlgorithmProvider(&cah, BCRYPT_RNG_ALGORITHM, 0, 0)) {
		InitializeCriticalSection(&l_cs);
		BCryptGenRandom(cah, l_dwa4S, sizeof(DWORD) * 4, 0);
		BCryptCloseAlgorithmProvider(cah, 0);

		return TRUE;
	} else
		return FALSE;
}
VOID fnDeleteXSR() {
	for (UINT8 i = 0; i < 4; i++)
		l_dwa4S[i] = 0;
	DeleteCriticalSection(&l_cs);
}