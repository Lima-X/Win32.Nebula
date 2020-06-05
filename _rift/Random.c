#include "pch.h"
#include "_rift.h"

// has to be rewritten to use the "full" ascii table (only the ones allowed in paths)
CONST WCHAR l_szCharSet[] = {
	L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	L"abcdefghijklmnopqrstuvwxyz"
	L"^1234567890´°!§$&()=`{[]},"
	L"-;_"
};
VOID fnGenRandomPathW(
	_Out_ PVOID  pBuffer,
	_In_  SIZE_T nBuffer
) {
	if (pBuffer) {
		for (SIZE_T i = 0; i < nBuffer; i++) {
			((PWCHAR)pBuffer)[i] = l_szCharSet[fnURID(0, sizeof(l_szCharSet) / sizeof(*l_szCharSet))];
		}
	}
}

PCWSTR fnAllocRandomPathW(
	_In_     SIZE_T  nMin,
	_In_opt_ SIZE_T  nMax,
	_Out_    PSIZE_T nLen
) {
	if (!nMin)
		return 0;

	if (nMax && (nMax != nMin))
		*nLen = fnURID(nMin, nMax);
	else
		*nLen = nMin;

	PWSTR pBuffer = (PWSTR)fnMalloc((*nLen + 1) * sizeof(WCHAR), 0);

	fnGenRandomPathW(pBuffer, *nLen);
	pBuffer[*nLen + 1] = L'\0';

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