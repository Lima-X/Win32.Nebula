#include "pch.h"
#include "_rift.h"

const WCHAR szCharSet[] = {
	L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	L"abcdefghijklmnopqrstuvwxyz"
	L"^1234567890´°!§$&()=`{[]},"
	L"-;_"
};

VOID fnGenRandomStringW(
	_Out_ PVOID  pBuffer,
	_In_  SIZE_T nBuffer
) {
	if (pBuffer) {
		for (SIZE_T i = 0; i < nBuffer; i++) {
			((PWCHAR)pBuffer)[i] = szCharSet[fnURID(0, sizeof(szCharSet) / sizeof(*szCharSet))];
		}
	}
}

PCWSTR fnAllocRandomStringW(
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

	PWSTR pBuffer = (PWSTR)HeapAlloc(g_hPH, 0, (*nLen + 1) * sizeof(WCHAR));

	fnGenRandomStringW(pBuffer, *nLen);
	pBuffer[*nLen + 1] = L'\0';

	return pBuffer;
}