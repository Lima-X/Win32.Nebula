#include "pch.h"
#include "_rift.h"

// has to be rewritten to use the "full" ascii table (only the ones allowed in paths)
VOID fnGenRandomB64W(
	_Out_ PVOID  sz,
	_In_  SIZE_T n
) {
	for (SIZE_T i = 0; i < n; i++)
		((PWCHAR)sz)[i] = g_Base64Table[fnURID(0, 64)];
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

static PVOID fnAllocRandom(
	_In_     SIZE_T  nMin,
	_In_opt_ SIZE_T  nMax,
	_Out_    PSIZE_T n
) {
	if (!nMin)
		return 0;

	if (nMax && (nMax != nMin))
		*n = fnURID(nMin, nMax);
	else
		*n = nMin;

	return HAlloc((*n + 1) * sizeof(WCHAR), 0);
}
PCWSTR fnAllocRandomB64W(
	_In_     SIZE_T  nMin,
	_In_opt_ SIZE_T  nMax
) {
	SIZE_T n;
	PVOID pBuffer = fnAllocRandom(nMin, nMax, &n);
	fnGenRandomB64W(pBuffer, n);
	((PWCHAR)pBuffer)[n + 1] = L'\0';
	return pBuffer;
}
PCWSTR fnAllocRandomPathW(
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
		((PDWORD)pBuffer)[i] = fnNext128ss();
	} for (UINT i = (nBuffer / 4) * 4; i < nBuffer; i++) {
		((PBYTE)pBuffer)[i] = fnNext128p() >> (3 * 8);
	}
}